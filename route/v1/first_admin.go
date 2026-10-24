package v1

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ReCasaOS/CasaOS-UserService/pkg/config"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/utils/encryption"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/utils/file"
	"github.com/ReCasaOS/CasaOS-UserService/service"
	model2 "github.com/ReCasaOS/CasaOS-UserService/service/model"
	"github.com/mattn/go-isatty"
)

// FirstAdminLocal: [app] FirstAdmin = local → the first account is created on the
// machine (casaos-user-service -bootstrap-admin), never over the network:
// GET /v1/users/status hands out no register key, POST /v1/users/register is
// refused. Default (web): the first visitor of the dashboard creates it.
func FirstAdminLocal() bool {
	return strings.EqualFold(strings.TrimSpace(config.AppInfo.FirstAdmin), "local")
}

// FirstAdminValueKnown: [app] FirstAdmin is empty, web or local; anything else (a typo) is taken as web, and said at start.
func FirstAdminValueKnown() bool {
	switch strings.ToLower(strings.TrimSpace(config.AppInfo.FirstAdmin)) {
	case "", "web", "local":
		return true
	}
	return false
}

var (
	ErrAlreadyInitialised = errors.New("an account exists already: the first administrator is created only once")
	ErrEmptyCredentials   = errors.New("username and password must not be empty")
	ErrPasswordTooShort   = errors.New("the password needs at least 6 characters")
	ErrUserCreateFailed   = errors.New("the account could not be stored")
	ErrTerminalInput      = errors.New("the password would be echoed on this terminal: pipe the two lines in, or use systemd credentials ($CREDENTIALS_DIRECTORY)")
)

// CreateFirstAdmin creates the first administrator, with the rules of the
// web registration; refused once any account exists.
func CreateFirstAdmin(users service.UserService, username, password string) error {
	if users.GetUserCount() > 0 {
		return ErrAlreadyInitialised
	}
	if username == "" || password == "" {
		return ErrEmptyCredentials
	}
	if len(password) < 6 {
		return ErrPasswordTooShort
	}
	user := users.CreateUser(model2.UserDBModel{
		Username: username,
		Password: encryption.HashPassword(password),
		Role:     "admin",
	})
	if user.Id == 0 {
		return ErrUserCreateFailed
	}
	file.MkDir(config.AppInfo.UserDataPath + "/" + strconv.Itoa(user.Id))
	return nil
}

// ReadFirstAdminCredentials: from systemd credentials ($CREDENTIALS_DIRECTORY/
// username, password: LoadCredential=) when set, else two lines on input. Never
// arguments or environment: those reach ps, logs and shell history.
func ReadFirstAdminCredentials(input io.Reader) (string, string, error) {
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		username, err := os.ReadFile(filepath.Join(dir, "username"))
		if err != nil {
			return "", "", err
		}
		password, err := os.ReadFile(filepath.Join(dir, "password"))
		if err != nil {
			return "", "", err
		}
		return strings.TrimRight(string(username), "\r\n"), strings.TrimRight(string(password), "\r\n"), nil
	}
	lines := bufio.NewScanner(input)
	read := func() string {
		if !lines.Scan() {
			return ""
		}
		return strings.TrimRight(lines.Text(), "\r")
	}
	username, password := read(), read()
	return username, password, lines.Err()
}

// BootstrapFirstAdmin is -bootstrap-admin: refused (ErrAlreadyInitialised)
// before any credential is read when an account exists, else the credentials
// read and the first administrator created. The username it created.
func BootstrapFirstAdmin(users service.UserService, input io.Reader) (string, error) {
	if users.GetUserCount() > 0 {
		return "", ErrAlreadyInitialised
	}
	if os.Getenv("CREDENTIALS_DIRECTORY") == "" && isTerminal(input) {
		return "", ErrTerminalInput
	}
	username, password, err := ReadFirstAdminCredentials(input)
	if err != nil {
		return "", err
	}
	return username, CreateFirstAdmin(users, username, password)
}

// isTerminal: input is a terminal, where what is typed is echoed.
func isTerminal(input io.Reader) bool {
	f, ok := input.(*os.File)
	return ok && (isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd()))
}
