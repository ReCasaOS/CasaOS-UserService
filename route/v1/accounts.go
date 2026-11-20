package v1

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/CasaOS-Common/utils/common_err"
	"github.com/ReCasaOS/CasaOS-Common/utils/jwt"
	"github.com/ReCasaOS/CasaOS-UserService/model"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/config"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/utils/encryption"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/utils/file"
	"github.com/ReCasaOS/CasaOS-UserService/service"
	model2 "github.com/ReCasaOS/CasaOS-UserService/service/model"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

func forbidden(ctx echo.Context) error {
	return ctx.JSON(http.StatusForbidden, model.Result{Success: common_err.INSUFFICIENT_PERMISSIONS, Message: common_err.GetMsg(common_err.INSUFFICIENT_PERMISSIONS)})
}

// RequireAdmin lets the administrator through. The role is read from the row, not from the
// token: an account that is gone, or never had one, is not one.
func RequireAdmin(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		if service.MyService.User().GetUserInfoById(ctx.Request().Header.Get("user_id")).Role != "admin" {
			return forbidden(ctx)
		}
		return next(ctx)
	}
}

// RequireInternal lets this box's own services through: loopback with the secret of this boot.
func RequireInternal(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		if !external.IsInternalRequest(ctx.RealIP(), ctx.Request().Header.Get(echo.HeaderAuthorization), config.CommonInfo.RuntimePath) {
			return forbidden(ctx)
		}
		return next(ctx)
	}
}

// TokenIsOfTheAccount is false for a token whose account is gone, or is older than the account
// (a number is never given twice now, but a database of before the counter may have done so).
// The token is dated to the second, so the creation is cut to the second too; a rename keeps it.
func TokenIsOfTheAccount(claims *jwt.Claims) bool {
	user := service.MyService.User().GetUserAllInfoById(strconv.Itoa(claims.ID))
	if user.Id == 0 {
		return false
	}
	return claims.IssuedAt == nil || !claims.IssuedAt.Time.Before(user.CreatedAt.Truncate(time.Second))
}

// removeUserDir clears the folder of an account: what an account left must not be the next one's.
func removeUserDir(id int) {
	if config.AppInfo.UserDataPath != "" {
		_ = os.RemoveAll(ownDir(id))
	}
}

func invalidParams(ctx echo.Context) error {
	return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
}

// PostUser creates an account of role user. The role is not a field of the request: a body
// that names one is refused rather than ignored.
func PostUser(ctx echo.Context) error {
	body := map[string]interface{}{}
	if err := ctx.Bind(&body); err != nil {
		return invalidParams(ctx)
	}
	if _, named := body["role"]; named {
		return invalidParams(ctx)
	}
	username, _ := body["username"].(string)
	password, _ := body["password"].(string)
	if len(username) == 0 || len(password) == 0 {
		return invalidParams(ctx)
	}
	if len(password) < 6 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.PWD_IS_TOO_SIMPLE, Message: common_err.GetMsg(common_err.PWD_IS_TOO_SIMPLE)})
	}

	// held to the end: two requests for one name make one account
	service.UserRegisterMu.Lock()
	defer service.UserRegisterMu.Unlock()

	if service.MyService.User().GetUserInfoByUserName(username).Id > 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.USER_EXIST, Message: common_err.GetMsg(common_err.USER_EXIST)})
	}
	user := service.MyService.User().CreateUser(model2.UserDBModel{Username: username, Password: encryption.HashPassword(password), Role: "user"})
	if user.Id == 0 {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	removeUserDir(user.Id)
	file.MkDir(ownDir(user.Id))

	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
}

// GetUsers lists the accounts: who they are, their role, whether 2FA is on.
func GetUsers(ctx echo.Context) error {
	type row struct {
		Id          int      `json:"id"`
		Username    string   `json:"username"`
		Role        string   `json:"role"`
		TotpEnabled bool     `json:"totp_enabled"`
		Rights      []string         `json:"rights"`
		Folders     []service.Folder `json:"folders"`
	}
	rows := []row{}
	for _, u := range service.MyService.User().ListUsers() {
		rows = append(rows, row{u.Id, u.Username, u.Role, u.TotpEnabled, service.ParseRights(u.Rights), service.ParseFolders(u.Folders)})
	}

	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: rows})
}

// GetUserRole is how the other services learn a role: "admin" or "user", 404 for no such account.
func GetUserRole(ctx echo.Context) error {
	// "no such account" only when the read says so: a failed read is an error, not a deleted account
	if _, err := strconv.Atoi(ctx.Param("id")); err != nil {
		return ctx.JSON(http.StatusNotFound, model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	user, err := service.MyService.User().FindUserRole(ctx.Param("id"))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ctx.JSON(http.StatusNotFound, model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	role := "user" // never admin by default: an empty role is a user's
	if user.Role == "admin" {
		role = "admin"
	}

	// data stays the role string, as the services already built read it; rights is its sibling,
	// empty for the administrator, who passes everything by role
	rights, folders := []string{}, []service.Folder{}
	if role == "user" {
		rights, folders = service.ParseRights(user.Rights), service.ParseFolders(user.Folders)
	}
	return ctx.JSON(common_err.SUCCESS, struct {
		model.Result
		Rights  []string         `json:"rights"`
		Folders []service.Folder `json:"folders"`
	}{model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: role}, rights, folders})
}

// PutUserFolders sets the folders of Files a user account may reach. A list that does not
// pass CheckFolders refuses the whole request; the administrator's are not settable (it
// reaches everything).
func PutUserFolders(ctx echo.Context) error {
	id := ctx.Param("id")
	if _, err := strconv.Atoi(id); err != nil {
		return ctx.JSON(http.StatusNotFound, model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	var body struct {
		Folders *[]service.Folder `json:"folders"`
	}
	// no "folders" key (or null) is not a request to clear them: {"folders":[]} is
	if err := ctx.Bind(&body); err != nil || body.Folders == nil {
		return invalidParams(ctx)
	}
	folders, err := service.CheckFolders(*body.Folders)
	if err != nil {
		return invalidParams(ctx)
	}
	service.UserRegisterMu.Lock()
	defer service.UserRegisterMu.Unlock()
	target := service.MyService.User().GetUserAllInfoById(id)
	if target.Id == 0 {
		return ctx.JSON(http.StatusNotFound, model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	if target.Role == "admin" {
		return invalidParams(ctx)
	}
	if err := service.MyService.User().SetUserFolders(id, folders); err != nil {
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}

	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: folders})
}

// PutUserRights sets the rights of a user account: the names asked for, each once. An unknown
// name refuses the whole request; the administrator's rights are not settable.
func PutUserRights(ctx echo.Context) error {
	id := ctx.Param("id")
	if _, err := strconv.Atoi(id); err != nil {
		return ctx.JSON(http.StatusNotFound, model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	var body struct {
		Rights *[]string `json:"rights"`
	}
	// no "rights" key (or null) is not a request to clear them: {"rights":[]} is
	if err := ctx.Bind(&body); err != nil || body.Rights == nil {
		return invalidParams(ctx)
	}
	for _, name := range *body.Rights {
		if !slices.Contains(service.ValidRights, name) {
			return invalidParams(ctx)
		}
	}
	// under the lock of creation and deletion: the account read is the one written
	service.UserRegisterMu.Lock()
	defer service.UserRegisterMu.Unlock()
	target := service.MyService.User().GetUserAllInfoById(id)
	if target.Id == 0 {
		return ctx.JSON(http.StatusNotFound, model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	if target.Role == "admin" {
		return invalidParams(ctx)
	}
	if err := service.MyService.User().SetUserRights(id, *body.Rights); err != nil {
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}

	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: service.NormaliseRights(*body.Rights)})
}

// DeleteUser removes an account. Not the administrator and not the one asking. The row goes
// first, and its folder; then AppManagement is told to forget the account (its entries would
// otherwise stay as leftovers the owner removes by hand). If AppManagement does not
// answer the account is gone all the same and the answer says what was not cleaned. The sessions
// end with the row (refresh reads it again).
func DeleteUser(ctx echo.Context) error {
	id := ctx.Param("id")
	if _, err := strconv.Atoi(id); err != nil {
		return ctx.JSON(http.StatusNotFound, model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	asked := service.MyService.User().GetUserAllInfoById(id)
	service.UserRegisterMu.Lock()
	defer service.UserRegisterMu.Unlock()
	// read again under the lock: the account asked for may be gone, and its number may be another's now
	target := service.MyService.User().GetUserAllInfoById(id)
	if target.Id == 0 || target.SessionVersion != asked.SessionVersion {
		return ctx.JSON(http.StatusNotFound, model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	if target.Role == "admin" || strconv.Itoa(target.Id) == ctx.Request().Header.Get("user_id") {
		return ctx.JSON(http.StatusConflict, model.Result{Success: http.StatusConflict, Message: "the administrator and your own account cannot be deleted"})
	}
	id = strconv.Itoa(target.Id)
	if err := service.MyService.User().DeleteUserById(id); err != nil {
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: "the account was not deleted"})
	}
	removeUserDir(target.Id)
	if err := forgetAccountInAppManagement(id); err != nil {
		return ctx.JSON(http.StatusBadGateway, model.Result{Success: http.StatusBadGateway, Message: "the account is deleted but its visibility entries could not be cleaned: AppManagement did not answer"})
	}

	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: id})
}

var appManagementClient = &http.Client{Timeout: 5 * time.Second}

// forgetAccountInAppManagement has AppManagement drop the account from its visibility lists.
func forgetAccountInAppManagement(id string) error {
	runtimePath := config.CommonInfo.RuntimePath
	raw, err := os.ReadFile(filepath.Join(runtimePath, external.AppManageURLFilename))
	if err != nil {
		return err
	}
	address := strings.TrimSpace(string(raw))
	parsed, err := url.Parse(address)
	if err != nil {
		return err
	}
	// the secret goes to this box's own services only
	if host := parsed.Hostname(); host != "localhost" && !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("app-management.url is not a loopback address")
	}
	req, err := http.NewRequest(http.MethodDelete, strings.TrimRight(address, "/")+"/v2/app_management/visibility/accounts/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	req.Header.Set(echo.HeaderAuthorization, external.InternalAuthorization(runtimePath))
	resp, err := appManagementClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("app management answered %d", resp.StatusCode)
	}

	return nil
}
