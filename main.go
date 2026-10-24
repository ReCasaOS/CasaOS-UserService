//go:generate bash -c "mkdir -p codegen/user_service && go run github.com/deepmap/oapi-codegen/cmd/oapi-codegen@v1.12.4 -generate types,server,spec -package codegen api/user-service/openapi.yaml > codegen/user_service/user_service_api.go"
//go:generate bash -c "mkdir -p codegen/message_bus && go run github.com/deepmap/oapi-codegen/cmd/oapi-codegen@v1.12.4 -package message_bus https://raw.githubusercontent.com/ReCasaOS/CasaOS-MessageBus/v0.4.19/api/message_bus/openapi.yaml > codegen/message_bus/api.go"
package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/CasaOS-Common/model"
	util_http "github.com/ReCasaOS/CasaOS-Common/utils/http"
	"github.com/ReCasaOS/CasaOS-Common/utils/jwt"
	"github.com/ReCasaOS/CasaOS-Common/utils/logger"
	"github.com/ReCasaOS/CasaOS-UserService/codegen/message_bus"
	"github.com/ReCasaOS/CasaOS-UserService/common"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/config"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/sqlite"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/utils/encryption"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/utils/random"
	"github.com/ReCasaOS/CasaOS-UserService/route"
	v1 "github.com/ReCasaOS/CasaOS-UserService/route/v1"
	"github.com/ReCasaOS/CasaOS-UserService/service"
	"github.com/coreos/go-systemd/daemon"
	"go.uber.org/zap"
)

const localhost = "127.0.0.1"

var (
	commit = "private build"
	date   = "private build"

	//go:embed api/index.html
	_docHTML string

	//go:embed api/user-service/openapi.yaml
	_docYAML string

	//go:embed build/sysroot/etc/casaos/user-service.conf.sample
	_confSample string
)

func init() {
	configFlag := flag.String("c", "", "config address")
	dbFlag := flag.String("db", "", "db path")
	resetUserFlag := flag.Bool("ru", false, "reset user")
	userFlag := flag.String("user", "", "user name")
	versionFlag := flag.Bool("v", false, "version")
	bootstrapAdminFlag := flag.Bool("bootstrap-admin", false, "create the first administrator: username and password from $CREDENTIALS_DIRECTORY or two lines on stdin; once")

	flag.Parse()

	if *versionFlag {
		fmt.Printf("v%s\n", common.Version)
		os.Exit(0)
	}

	println("git commit:", commit)
	println("build date:", date)

	config.InitSetup(*configFlag, _confSample)

	logger.LogInit(config.AppInfo.LogPath, config.AppInfo.LogSaveName, config.AppInfo.LogFileExt)

	if len(*dbFlag) == 0 {
		*dbFlag = config.AppInfo.DBPath
	}

	sqliteDB := sqlite.GetDb(*dbFlag)

	// the commands below need the account store only, not the gateway: they
	// run (and end) on a box whose services are down; errors on stderr, exit 1
	failed := func(what string, err error) {
		fmt.Fprintln(os.Stderr, what+":", err)
		os.Exit(1)
	}

	if *bootstrapAdminFlag {
		users := service.NewUserService(sqliteDB, filepath.Join(config.AppInfo.DBPath, service.KeyFilename))
		username, err := v1.BootstrapFirstAdmin(users, os.Stdin)
		if err != nil {
			failed("first administrator not created", err)
		}
		fmt.Println("first administrator created:", username)
		os.Exit(0)
	}

	// -ru is a command: it ends the process, never goes on to start a second service
	if *resetUserFlag {
		users := service.NewUserService(sqliteDB, filepath.Join(config.AppInfo.DBPath, service.KeyFilename))
		if userFlag == nil || len(*userFlag) == 0 {
			failed("user not reset", errors.New("user is empty"))
		}

		userData := users.GetUserAllInfoByName(*userFlag)

		if userData.Id == 0 {
			failed("user not reset", errors.New("user not exist"))
		}

		password := random.RandomString(6, false)
		userData.Password = encryption.HashPassword(password)
		if err := users.UpdateUserPassword(userData); err != nil {
			failed("user not reset", err)
		}
		// The shell is the way back in when the authenticator and the recovery codes are both lost.
		userData.TotpSecret, userData.TotpEnabled, userData.TotpLastStep, userData.RecoveryCodes = "", false, 0, nil
		if err := users.UpdateUserTOTP(userData); err != nil {
			failed("password reset, two-factor authentication not disabled", err)
		}
		fmt.Println("User reset successful, two-factor authentication disabled")
		fmt.Println("UserName:" + userData.Username)
		fmt.Println("Password:" + password)
		os.Exit(0)
	}

	service.MyService = service.NewService(sqliteDB, config.CommonInfo.RuntimePath)
}

func main() {
	v1Router := route.InitRouter()
	v2Router := route.InitV2Router()
	v2DocRouter := route.InitV2DocRouter(_docHTML, _docYAML)

	_, publicKey := service.MyService.User().GetKeyPair()

	jswkJSON, err := jwt.GenerateJwksJSON(publicKey)
	if err != nil {
		panic(err)
	}

	mux := &util_http.HandlerMultiplexer{
		HandlerMap: map[string]http.Handler{
			"v1":                                    v1Router,
			"v2":                                    v2Router,
			"doc":                                   v2DocRouter,
			strings.SplitN(jwt.JWKSPath, "/", 2)[0]: jwt.JWKSHandler(jswkJSON),
		},
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(localhost, "0"))
	if err != nil {
		panic(err)
	}

	apiPaths := []string{
		"/v1/users",
		route.V2APIPath,
		route.V2DocPath,
		"/" + jwt.JWKSPath,
	}
	for _, v := range apiPaths {
		err = service.MyService.Gateway().CreateRoute(&model.Route{
			Path:   v,
			Target: "http://" + listener.Addr().String(),
		})

		if err != nil {
			panic(err)
		}
	}

	// write address file
	addressFilePath, err := writeAddressFile(config.CommonInfo.RuntimePath, external.UserServiceAddressFilename, "http://"+listener.Addr().String())
	if err != nil {
		panic(err)
	}

	if supported, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		logger.Error("Failed to notify systemd that user service is ready", zap.Any("error", err))
	} else if supported {
		logger.Info("Notified systemd that user service is ready")
	} else {
		logger.Info("This process is not running as a systemd service.")
	}
	go route.EventListen()
	logger.Info("User service is listening...", zap.Any("address", listener.Addr().String()), zap.String("filepath", addressFilePath))

	var events []message_bus.EventType
	events = append(events, message_bus.EventType{Name: "zimaos:user:save_config", SourceID: common.SERVICENAME, PropertyTypeList: []message_bus.PropertyType{}})
	// register at message bus
	for i := 0; i < 10; i++ {
		response, err := service.MyService.MessageBus().RegisterEventTypesWithResponse(context.Background(), events)
		if err != nil {
			logger.Error("error when trying to register one or more event types - some event type will not be discoverable", zap.Error(err))
		}
		if response != nil && response.StatusCode() != http.StatusOK {
			logger.Error("error when trying to register one or more event types - some event type will not be discoverable", zap.String("status", response.Status()), zap.String("body", string(response.Body)))
		}
		// nil when the bus could not be reached at all -- which is what a service
		// starting a second before the bus sees, and what used to be a nil pointer
		// panic on the first start of every fresh install
		if response != nil && response.StatusCode() == http.StatusOK {
			break
		}
		time.Sleep(time.Second)
	}

	s := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second, // fix G112: Potential slowloris attack (see https://github.com/securego/gosec)
	}

	err = s.Serve(listener) // not using http.serve() to fix G114: Use of net/http serve function that has no support for setting timeouts (see https://github.com/securego/gosec)
	if err != nil {
		panic(err)
	}
}

func writeAddressFile(runtimePath string, filename string, address string) (string, error) {
	err := os.MkdirAll(runtimePath, 0o755)
	if err != nil {
		return "", err
	}

	filepath := filepath.Join(runtimePath, filename)
	return filepath, os.WriteFile(filepath, []byte(address), 0o600)
}
