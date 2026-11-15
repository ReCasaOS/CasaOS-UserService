package v1

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	json2 "encoding/json"
	"image"
	"image/png"
	"io"
	"net/http"
	url2 "net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/CasaOS-Common/utils/common_err"
	"github.com/ReCasaOS/CasaOS-Common/utils/jwt"
	"github.com/ReCasaOS/CasaOS-Common/utils/logger"
	"github.com/ReCasaOS/CasaOS-UserService/common"
	"github.com/ReCasaOS/CasaOS-UserService/model"
	"github.com/ReCasaOS/CasaOS-UserService/model/system_model"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/config"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/utils/encryption"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/utils/file"
	model2 "github.com/ReCasaOS/CasaOS-UserService/service/model"
	"github.com/labstack/echo/v4"
	uuid "github.com/satori/go.uuid"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/ReCasaOS/CasaOS-UserService/service"
)

// ownDir is the folder of an account: what an account route reads, copies or deletes is in it.
func ownDir(id int) string { return config.AppInfo.UserDataPath + "/" + strconv.Itoa(id) }

// within is true for a path under dir (not dir itself): cleaned, then checked with filepath.Rel,
// with the links of what exists resolved so a link in the folder does not lead out.
func within(dir, p string) bool {
	if dir == "" || p == "" {
		return false
	}
	dir, p = filepath.Clean(dir), filepath.Clean(p)
	if !under(dir, p) {
		return false
	}
	resolved := p
	if r, err := filepath.EvalSymlinks(p); err == nil {
		resolved = r
	} else if r, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
		resolved = filepath.Join(r, filepath.Base(p))
	}
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	return under(dir, resolved)
}

func under(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// @Summary register user
// @Router /user/register/ [post]
func PostUserRegister(ctx echo.Context) error {
	if FirstAdminLocal() {
		return ctx.JSON(http.StatusForbidden,
			model.Result{Success: common_err.KEY_NOT_EXIST, Message: "the first account is created on the machine: casaos-user-service -bootstrap-admin"})
	}

	json := make(map[string]string)
	ctx.Bind(&json)

	username := json["username"]
	pwd := json["password"]
	key := json["key"]

	// Held to the end: two keys used at the same moment make one account, not two.
	service.UserRegisterMu.Lock()
	defer service.UserRegisterMu.Unlock()

	// A key creates the first account and no other. Every visit before the box is
	// set up was handed one, and only the one used was ever forgotten.
	if _, ok := service.UserRegisterHash[key]; !ok || service.MyService.User().GetUserCount() > 0 {
		return ctx.JSON(common_err.CLIENT_ERROR,
			model.Result{Success: common_err.KEY_NOT_EXIST, Message: common_err.GetMsg(common_err.KEY_NOT_EXIST)})
	}

	if len(username) == 0 || len(pwd) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR,
			model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	if len(pwd) < 6 {
		return ctx.JSON(common_err.CLIENT_ERROR,
			model.Result{Success: common_err.PWD_IS_TOO_SIMPLE, Message: common_err.GetMsg(common_err.PWD_IS_TOO_SIMPLE)})
	}
	oldUser := service.MyService.User().GetUserInfoByUserName(username)
	if oldUser.Id > 0 {
		return ctx.JSON(common_err.CLIENT_ERROR,
			model.Result{Success: common_err.USER_EXIST, Message: common_err.GetMsg(common_err.USER_EXIST)})
	}

	user := model2.UserDBModel{}
	user.Username = username
	user.Password = encryption.HashPassword(pwd)
	user.Role = "admin"

	user = service.MyService.User().CreateUser(user)
	if user.Id == 0 {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	file.MkDir(config.AppInfo.UserDataPath + "/" + strconv.Itoa(user.Id))
	clear(service.UserRegisterHash)
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
}

// The /login budgets: burst 5, refill 1/min. /login needs no account, so everybody
// who never signed in shares one budget: however many addresses somebody guessing
// passwords has, it is five tries and then one a minute. With that budget alone,
// any machine on the network spent it and the owner could not sign in; so an
// address a sign-in succeeded from has a budget of its own. The address is the
// one the gateway reports; it drops what the client says about itself.
// shortcut: the known addresses are forgotten at a restart and when the owner's
// address changes; the next sign-in is a stranger's again. Keep them on disk if
// that turns out to matter.
var (
	// LoginLimit is the refill rate of each budget; exported so tests can lift it.
	LoginLimit = rate.Every(time.Minute)

	loginMu        sync.Mutex
	strangersLogin = rate.NewLimiter(LoginLimit, 5)
	knownLogin     = map[string]*rate.Limiter{}
)

// maxKnownLogins bounds a table only a correct password adds to.
const maxKnownLogins = 1024

// loginBudget is the budget a sign-in from ip is taken from.
func loginBudget(ip string) *rate.Limiter {
	loginMu.Lock()
	defer loginMu.Unlock()
	if l, known := knownLogin[ip]; known {
		return l
	}
	return strangersLogin
}

// signedInFrom gives ip its own budget from now on: its password was right.
func signedInFrom(ip string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	if _, known := knownLogin[ip]; known {
		return
	}
	if len(knownLogin) >= maxKnownLogins {
		clear(knownLogin)
	}
	knownLogin[ip] = rate.NewLimiter(LoginLimit, 5)
}

// ResetLoginLimiters starts every /login budget again, at LoginLimit. Test hook,
// as ResetUserLimiters.
func ResetLoginLimiters() {
	loginMu.Lock()
	defer loginMu.Unlock()
	strangersLogin = rate.NewLimiter(LoginLimit, 5)
	clear(knownLogin)
}

// passwordMatches is whether candidate is the password stored as stored, an
// argon2id hash or, for an account not signed in to since the upgrade, the
// legacy MD5.
func passwordMatches(stored, candidate string) bool {
	return encryption.VerifyPassword(stored, candidate)
}

// upgradePassword stores password, which the user's hash just matched, as a fresh
// argon2id hash when that hash is the legacy MD5 or was made with other
// parameters: the owner signs in once and the weak value is gone, with nothing
// asked of them. The swap is keyed on the hash as read, so a password changed
// in the meantime is not put back; if it does not land, the next sign-in tries
// again.
func upgradePassword(user model2.UserDBModel, password string) {
	if encryption.NeedsRehash(user.Password) {
		service.MyService.User().ReplacePasswordHash(user.Id, user.Password, encryption.HashPassword(password))
	}
}

// @Summary login
// @Produce  application/json
// @Accept application/json
// @Tags user
// @Param user_name query string true "User name"
// @Param pwd  query string true "password"
// @Success 200 {string} string "ok"
// @Router /user/login [post]
func PostUserLogin(ctx echo.Context) error {
	if !loginBudget(ctx.RealIP()).Allow() {
		return ctx.JSON(common_err.TOO_MANY_REQUEST,
			model.Result{
				Success: common_err.TOO_MANY_LOGIN_REQUESTS,
				Message: common_err.GetMsg(common_err.TOO_MANY_LOGIN_REQUESTS),
			})
	}

	json := make(map[string]string)
	ctx.Bind(&json)

	username := json["username"]

	password := json["password"]
	// check params is empty
	if len(username) == 0 || len(password) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR,
			model.Result{
				Success: common_err.CLIENT_ERROR,
				Message: common_err.GetMsg(common_err.INVALID_PARAMS),
			})
	}
	user := service.MyService.User().GetUserAllInfoByName(username)
	if user.Id == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	if !passwordMatches(user.Password, password) {
		return ctx.JSON(common_err.CLIENT_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST_OR_PWD_INVALID, Message: common_err.GetMsg(common_err.USER_NOT_EXIST_OR_PWD_INVALID)})
	}
	signedInFrom(ctx.RealIP())
	upgradePassword(user, password)
	if !user.TotpEnabled && user.TotpSecret != "" {
		// An abandoned /2fa/setup does not leave its secret in user.db. The
		// clear is conditional on the row as read: if /2fa/enable won the race
		// since, the row is left alone and this login must stop at the factor.
		if !service.MyService.User().ClearPendingTOTP(user.Id, user.TotpSecret) {
			user = service.MyService.User().GetUserAllInfoById(strconv.Itoa(user.Id))
			if user.Id == 0 {
				return ctx.JSON(common_err.CLIENT_ERROR,
					model.Result{Success: common_err.USER_NOT_EXIST_OR_PWD_INVALID, Message: common_err.GetMsg(common_err.USER_NOT_EXIST_OR_PWD_INVALID)})
			}
		}
	}
	if user.TotpEnabled {
		preAuth, err := service.MyService.User().IssuePreAuthToken(user)
		if err != nil {
			return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: err.Error()})
		}
		return ctx.JSON(common_err.SUCCESS,
			model.Result{
				Success: common.TWO_FA_REQUIRED,
				Message: common.GetMsg(common.TWO_FA_REQUIRED),
				Data:    map[string]interface{}{"pre_auth_token": preAuth, "expires_at": time.Now().Add(service.PreAuthTTL).Unix()},
			})
	}

	return issueTokens(ctx, user)
}

// newTokens is the pair of a session of user: an access token, three hours, and the refresh
// token of the session the row is at.
func newTokens(user model2.UserDBModel) (system_model.VerifyInformation, error) {
	privateKey, _ := service.MyService.User().GetKeyPair()
	access, err := jwt.GetAccessToken(user.Username, privateKey, user.Id)
	if err != nil {
		return system_model.VerifyInformation{}, err
	}
	refresh, err := service.MyService.User().RefreshToken(user)
	if err != nil {
		return system_model.VerifyInformation{}, err
	}
	return system_model.VerifyInformation{AccessToken: access, RefreshToken: refresh, ExpiresAt: time.Now().Add(3 * time.Hour).Unix()}, nil
}

// issueTokens mints the access and refresh tokens and builds the login body;
// shared by /login (2FA off) and /2fa/verify (2FA on).
func issueTokens(ctx echo.Context, user model2.UserDBModel) error {
	token, err := newTokens(user)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: err.Error()})
	}
	data := make(map[string]interface{}, 2)
	user.Password = ""
	data["token"] = token

	// TODO:1 Database fields cannot be external
	data["user"] = user

	return ctx.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    data,
		})
}

// @Summary edit user head
// @Produce  application/json
// @Accept multipart/form-data
// @Tags user
// @Param file formData file true "用户头像"
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /users/avatar [put]
const maxAvatarPixels = 16 << 20

func PutUserAvatar(ctx echo.Context) error {
	id := ctx.Request().Header.Get("user_id")
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		return ctx.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	json := make(map[string]string)
	ctx.Bind(&json)

	data := json["file"]
	imgBase64 := strings.Replace(data, "data:image/png;base64,", "", 1)
	decodeData, err := base64.StdEncoding.DecodeString(string(imgBase64))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}

	// the header first: a small file can declare billions of pixels
	if c, _, err := image.DecodeConfig(bytes.NewReader(decodeData)); err != nil || int64(c.Width)*int64(c.Height) > maxAvatarPixels {
		return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.NOT_IMAGE, Message: common_err.GetMsg(common_err.NOT_IMAGE)})
	}
	img, _, err := image.Decode(bytes.NewReader(decodeData))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.NOT_IMAGE, Message: common_err.GetMsg(common_err.NOT_IMAGE)})
	}

	avatarPath := ownDir(user.Id) + "/avatar.png"
	if err := os.MkdirAll(ownDir(user.Id), 0o755); err != nil {
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	os.Remove(avatarPath)
	outFile, err := os.Create(avatarPath)
	if err != nil {
		logger.Error("create file error", zap.Error(err))
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	defer outFile.Close()

	err = png.Encode(outFile, img)
	if err != nil {
		logger.Error("encode error", zap.Error(err))
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	user.Avatar = avatarPath
	service.MyService.User().UpdateUser(user)
	return ctx.JSON(http.StatusOK,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    user,
		})
}

// @Summary get user head
// @Produce  application/json
// @Tags user
// @Param file formData file true "用户头像"
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /users/avatar [get]
func GetUserAvatar(ctx echo.Context) error {
	id := ctx.Request().Header.Get("user_id")
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		return ctx.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}

	if within(ownDir(user.Id), user.Avatar) && file.Exists(user.Avatar) {
		ctx.Response().Header().Set("Content-Disposition", "attachment; filename*=utf-8''"+url2.PathEscape(path.Base(user.Avatar)))
		ctx.Response().Header().Set("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate, value")
		return ctx.File(user.Avatar)

	}
	user.Avatar = "/usr/share/casaos/www/avatar.svg"
	if file.Exists(user.Avatar) {
		ctx.Response().Header().Set("Content-Disposition", "attachment; filename*=utf-8''"+url2.PathEscape(path.Base(user.Avatar)))
		ctx.Response().Header().Set("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate, value")
		return ctx.File(user.Avatar)

	}
	user.Avatar = "/var/lib/casaos/www/avatar.svg"
	ctx.Response().Header().Set("Content-Disposition", "attachment; filename*=utf-8''"+url2.PathEscape(path.Base(user.Avatar)))
	ctx.Response().Header().Set("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate, value")
	return ctx.File(user.Avatar)
}

// @Summary edit user name
// @Produce  application/json
// @Accept application/json
// @Tags user
// @Param old_name  query string true "Old user name"
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /user/name/:id [put]
func PutUserInfo(ctx echo.Context) error {
	id := ctx.Request().Header.Get("user_id")
	// the request names four fields; the rest of the row is not its to say
	var body struct {
		Username    string `json:"username"`
		Nickname    string `json:"nickname"`
		Description string `json:"description"`
		Email       string `json:"email"`
	}
	ctx.Bind(&body)
	// with PostUser: two requests for one name make one account
	service.UserRegisterMu.Lock()
	defer service.UserRegisterMu.Unlock()
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		return ctx.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST_OR_PWD_INVALID, Message: common_err.GetMsg(common_err.USER_NOT_EXIST_OR_PWD_INVALID)})
	}
	if len(body.Username) > 0 && body.Username != user.Username {
		if user.Role != "admin" { // a user's login name is the owner's to choose
			return forbidden(ctx)
		}
		if u := service.MyService.User().GetUserInfoByUserName(body.Username); u.Id > 0 {
			return ctx.JSON(common_err.CLIENT_ERROR,
				model.Result{Success: common_err.USER_EXIST, Message: common_err.GetMsg(common_err.USER_EXIST)})
		}
		user.Username = body.Username
	}
	if len(body.Email) > 0 {
		user.Email = body.Email
	}
	if len(body.Description) > 0 {
		user.Description = body.Description
	}
	if len(body.Nickname) > 0 {
		user.Nickname = body.Nickname
	}
	service.MyService.User().UpdateUser(user)
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: user})
}

// @Summary edit user password
// @Produce  application/json
// @Accept application/json
// @Tags user
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /user/password/:id [put]
func PutUserPassword(ctx echo.Context) error {
	id := ctx.Request().Header.Get("user_id")
	json := make(map[string]string)
	ctx.Bind(&json)
	oldPwd := json["old_password"]
	pwd := json["password"]
	if len(oldPwd) == 0 || len(pwd) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	user := service.MyService.User().GetUserAllInfoById(id)
	if user.Id == 0 {
		return ctx.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	if !passwordMatches(user.Password, oldPwd) {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.PWD_INVALID_OLD, Message: common_err.GetMsg(common_err.PWD_INVALID_OLD)})
	}
	user.Password = encryption.HashPassword(pwd)
	if err := service.MyService.User().UpdateUserPassword(user); err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	// The change ended every session of the account, this one with them: it goes on with the
	// pair made here, of the session the row is at now. The body is the one of a login.
	user = service.MyService.User().GetUserAllInfoById(id)
	if user.Id == 0 { // gone since the change: no pair for an account that is not there
		return ctx.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	return issueTokens(ctx, user)
}

// @Summary edit user nick
// @Produce  application/json
// @Accept application/json
// @Tags user
// @Param nick_name query string false "nick name"
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /user/nick [put]
func PutUserNick(ctx echo.Context) error {
	id := ctx.Request().Header.Get("user_id")
	json := make(map[string]string)
	ctx.Bind(&json)
	Nickname := json["nick_name"]
	if len(Nickname) == 0 {
		return ctx.JSON(http.StatusOK, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		return ctx.JSON(http.StatusOK,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	user.Nickname = Nickname
	service.MyService.User().UpdateUser(user)
	return ctx.JSON(http.StatusOK, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: user})
}

// @Summary edit user description
// @Produce  application/json
// @Accept multipart/form-data
// @Tags user
// @Param description formData string false "Description"
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /user/desc [put]
func PutUserDesc(ctx echo.Context) error {
	id := ctx.Request().Header.Get("user_id")
	json := make(map[string]string)
	ctx.Bind(&json)
	desc := json["description"]
	if len(desc) == 0 {
		return ctx.JSON(http.StatusOK, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		return ctx.JSON(http.StatusOK,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	user.Description = desc

	service.MyService.User().UpdateUser(user)

	return ctx.JSON(http.StatusOK, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: user})
}

// @Summary get user info
// @Produce  application/json
// @Accept  application/json
// @Tags user
// @Success 200 {string} string "ok"
// @Router /user/info/:id [get]
func GetUserInfo(ctx echo.Context) error {
	id := ctx.Request().Header.Get("user_id")
	user := service.MyService.User().GetUserInfoById(id)
	// the caller's own rights only; the administrator passes by role, so none are listed
	rights := []string{}
	if user.Role != "admin" {
		rights = service.ParseRights(user.Rights)
	}

	return ctx.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data: struct {
				model2.UserDBModel
				Rights []string `json:"rights"`
			}{user, rights},
		})
}

/**
 * @description:
 * @param {*gin.Context} c
 * @param {string} Username
 * @return {*}
 * @method:
 * @router:
 */
func GetUserInfoByUsername(ctx echo.Context) error {
	username := ctx.Param("username")
	if len(username) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	user := service.MyService.User().GetUserInfoByUserName(username)
	if user.Id == 0 {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}

	return ctx.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    user,
		})
}

/**
 * @description: get all Usernames
 * @method:GET
 * @router:/user/all/name
 */
func GetUserAllUsername(ctx echo.Context) error {
	users := service.MyService.User().GetAllUserName()
	names := []string{}
	for _, v := range users {
		names = append(names, v.Username)
	}
	return ctx.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    names,
		})
}

/**
 * @description:get custom file by user
 * @param {path} name string "file name"
 * @method: GET
 * @router: /user/custom/:key
 */
func GetUserCustomConf(ctx echo.Context) error {
	name := ctx.Param("key")
	if len(name) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	id := ctx.Request().Header.Get("user_id")

	user := service.MyService.User().GetUserInfoById(id)
	//	user := service.MyService.User().GetUserInfoByUsername(Username)
	if user.Id == 0 {
		return ctx.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	filePath := ownDir(user.Id) + "/" + name + ".json"
	if !within(ownDir(user.Id), filePath) {
		return forbidden(ctx)
	}

	data := file.ReadFullFile(filePath)
	if !gjson.ValidBytes(data) {
		return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: string(data)})
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: json2.RawMessage(string(data))})
}

/**
 * @description:create or update custom conf by user
 * @param {path} name string "file name"
 * @method:POST
 * @router:/user/custom/:key
 */
func PostUserCustomConf(ctx echo.Context) error {
	name := ctx.Param("key")
	if len(name) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	id := ctx.Request().Header.Get("user_id")
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		return ctx.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	if !within(ownDir(user.Id), ownDir(user.Id)+"/"+name+".json") {
		return forbidden(ctx)
	}
	data, err := io.ReadAll(ctx.Request().Body)
	if err != nil { // past the route's limit (BodyLimit) or cut: nothing is written
		return ctx.JSON(http.StatusRequestEntityTooLarge, model.Result{Success: common_err.CLIENT_ERROR, Message: err.Error()})
	}
	filePath := ownDir(user.Id)

	if err := file.IsNotExistMkDir(filePath); err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}

	if err := file.WriteToPath(data, filePath, name+".json"); err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}

	if name == "system" {
		dataMap := make(map[string]string, 1)
		dataMap["system"] = string(data)
		response, err := service.MyService.MessageBus().PublishEventWithResponse(context.Background(), common.SERVICENAME, "zimaos:user:save_config", dataMap)
		if err != nil {
			logger.Error("failed to publish event to message bus", zap.Error(err), zap.Any("event", string(data)))
		}
		if response.StatusCode() != http.StatusOK {
			logger.Error("failed to publish event to message bus", zap.String("status", response.Status()), zap.Any("response", response))
		}

	}

	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: json2.RawMessage(string(data))})
}

/**
 * @description: delete user custom config
 * @param {path} key string
 * @method:delete
 * @router:/user/custom/:key
 */
func DeleteUserCustomConf(ctx echo.Context) error {
	name := ctx.Param("key")
	if len(name) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	id := ctx.Request().Header.Get("user_id")
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		return ctx.JSON(common_err.SERVICE_ERROR,
			model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	filePath := ownDir(user.Id) + "/" + name + ".json"
	if !within(ownDir(user.Id), filePath) {
		return forbidden(ctx)
	}
	err := os.Remove(filePath)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
}

/**
 * @description:update user image
 * @method:POST
 * @router:/user/current/image/:key
 */
func PutUserImage(ctx echo.Context) error {
	id := ctx.Request().Header.Get("user_id")
	json := make(map[string]string)
	if err := ctx.Bind(&json); err != nil { // past the route's limit (BodyLimit) or not JSON
		return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}

	path := json["path"]
	key := ctx.Param("key")
	if len(path) == 0 || len(key) == 0 {
		return ctx.JSON(http.StatusOK, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		return ctx.JSON(http.StatusOK, model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	ext := file.GetExt(path)
	filePath := ownDir(user.Id) + "/" + key + ext
	if !within(ownDir(user.Id), path) || !within(ownDir(user.Id), filePath) {
		return forbidden(ctx)
	}
	if !file.Exists(path) {
		return ctx.JSON(http.StatusOK, model.Result{Success: common_err.FILE_DOES_NOT_EXIST, Message: common_err.GetMsg(common_err.FILE_DOES_NOT_EXIST)})
	}

	_, err := file.GetImageExt(path)
	if err != nil {
		return ctx.JSON(http.StatusOK, model.Result{Success: common_err.NOT_IMAGE, Message: common_err.GetMsg(common_err.NOT_IMAGE)})
	}

	fstat, err := os.Stat(path)
	if err != nil || fstat.Size() > 10<<20 {
		return ctx.JSON(http.StatusOK, model.Result{Success: common_err.IMAGE_TOO_LARGE, Message: common_err.GetMsg(common_err.IMAGE_TOO_LARGE)})
	}
	file.CopySingleFile(path, filePath, "overwrite")

	data := make(map[string]string, 3)
	data["path"] = filePath
	data["file_name"] = key + ext
	data["online_path"] = "/v1/users/image?path=" + filePath
	return ctx.JSON(http.StatusOK, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: data})
}

/**
* @description:
* @param {*gin.Context} c
* @param {file} file
* @param {string} key
* @param {string} type:avatar,background
* @return {*}
* @method:
* @router:
 */
func PostUserUploadImage(ctx echo.Context) error {
	id := ctx.Request().Header.Get("user_id")
	f, err := ctx.FormFile("file")
	key := ctx.Param("key")
	t := ctx.FormValue("type")
	if len(key) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	if err != nil {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.CLIENT_ERROR, Message: common_err.GetMsg(common_err.CLIENT_ERROR), Data: err.Error()})
	}

	_, err = file.GetImageExtByName(f.Filename)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.NOT_IMAGE, Message: common_err.GetMsg(common_err.NOT_IMAGE)})
	}
	ext := filepath.Ext(f.Filename)
	user := service.MyService.User().GetUserInfoById(id)

	if user.Id == 0 {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	if t == "avatar" {
		key = "avatar"
	}
	path := ownDir(user.Id) + "/" + key + ext
	if !within(ownDir(user.Id), path) {
		return forbidden(ctx)
	}

	if err := file.SaveUploadedFile(f, path); err != nil {
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}

	data := make(map[string]string, 3)
	data["path"] = path
	data["file_name"] = key + ext
	data["online_path"] = "/v1/users/image?path=" + path
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: data})
}

// userFolderFile is a path, relative to UserDataPath, of a file in a user's folder.
var userFolderFile = regexp.MustCompile(`^\d+/.`)

/**
 * @description: get current user's image
 * @method:GET
 * @router:/user/image/:id
 */
func GetUserImage(ctx echo.Context) error {
	filePath := ctx.QueryParam("path")
	if len(filePath) == 0 {
		return ctx.JSON(http.StatusNotFound, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	absFilePath, err := filepath.Abs(filepath.Clean(filePath))
	if err != nil {
		return ctx.JSON(http.StatusNotFound, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	// A user's folder is <UserDataPath>/<id>, and what is asked for is in one. Checked
	// before the disk is looked at: the answer does not say what exists elsewhere.
	rel, err := filepath.Rel(config.AppInfo.UserDataPath, absFilePath)
	if err != nil || !userFolderFile.MatchString(filepath.ToSlash(rel)) ||
		!within(filepath.Join(config.AppInfo.UserDataPath, strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]), absFilePath) {
		return ctx.JSON(http.StatusNotFound, model.Result{Success: common_err.INSUFFICIENT_PERMISSIONS, Message: common_err.GetMsg(common_err.INSUFFICIENT_PERMISSIONS)})
	}
	if !file.Exists(absFilePath) {
		return ctx.JSON(http.StatusNotFound, model.Result{Success: common_err.FILE_DOES_NOT_EXIST, Message: common_err.GetMsg(common_err.FILE_DOES_NOT_EXIST)})
	}
	// This route needs no sign-in (the sign-in page shows the avatar and its wallpaper),
	// and the folder holds the dashboard's settings too: pictures only, by the two rules
	// a picture gets in by, its name (an upload) or its content (one taken from Files).
	if _, err := file.GetImageExtByName(strings.ToLower(absFilePath)); err != nil {
		if _, err := file.GetImageExt(absFilePath); err != nil {
			return ctx.JSON(http.StatusNotFound, model.Result{Success: common_err.INSUFFICIENT_PERMISSIONS, Message: common_err.GetMsg(common_err.INSUFFICIENT_PERMISSIONS)})
		}
	}

	fileName := path.Base(absFilePath)

	// @tiger - RESTful 规范下不应该返回文件本身内容，而是返回文件的静态URL，由前端去解析
	ctx.Response().Header().Set("Content-Disposition", "attachment; filename*=utf-8''"+url2.PathEscape(fileName))
	return ctx.File(absFilePath)
}

func DeleteUserImage(ctx echo.Context) error {
	id := ctx.Request().Header.Get("user_id")
	path := ctx.QueryParam("path")
	if len(path) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	user := service.MyService.User().GetUserInfoById(id)
	if user.Id == 0 {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	if !within(ownDir(user.Id), path) {
		return forbidden(ctx)
	}
	if !file.Exists(path) {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.FILE_DOES_NOT_EXIST, Message: common_err.GetMsg(common_err.FILE_DOES_NOT_EXIST)})
	}
	os.Remove(path)
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
}

/**
 * @description:
 * @param {*gin.Context} c
 * @param {string} refresh_token
 * @return {*}
 * @method:
 * @router:
 */
func PostUserRefreshToken(ctx echo.Context) error {
	js := make(map[string]string)
	ctx.Bind(&js)
	refresh := js["refresh_token"]

	claims, err := jwt.ParseToken(
		refresh,
		func() (*ecdsa.PublicKey, error) {
			_, publicKey := service.MyService.User().GetKeyPair()
			return publicKey, nil
		})
	if err != nil {
		return ctx.JSON(http.StatusUnauthorized, model.Result{Success: common_err.VERIFICATION_FAILURE, Message: common_err.GetMsg(common_err.VERIFICATION_FAILURE), Data: err.Error()})
	}
	if !claims.VerifyExpiresAt(time.Now(), true) || !claims.VerifyIssuer("refresh", true) {
		return ctx.JSON(http.StatusUnauthorized, model.Result{Success: common_err.VERIFICATION_FAILURE, Message: common_err.GetMsg(common_err.VERIFICATION_FAILURE)})
	}

	// The token is only a signature: the account is read again. It may be gone, a password
	// change since the token was made ended its session, and an account made since under the
	// same id has sessions of its own.
	user := service.MyService.User().GetUserAllInfoById(strconv.Itoa(claims.ID))
	if user.Id == 0 || service.SessionOf(claims) != user.SessionVersion {
		return ctx.JSON(http.StatusUnauthorized, model.Result{Success: common_err.VERIFICATION_FAILURE, Message: common_err.GetMsg(common_err.VERIFICATION_FAILURE)})
	}

	verifyInfo, err := newTokens(user)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: err.Error()})
	}

	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: verifyInfo})
}

// @Summary 检查是否进入引导状态
// @Produce  application/json
// @Accept application/json
// @Tags sys
// @Security ApiKeyAuth
// @Success 200 {string} string "ok"
// @Router /sys/init/check [get]
func GetUserStatus(ctx echo.Context) error {
	data := make(map[string]interface{}, 5)

	// "web" or "local": where the first account is created
	data["first_admin"] = "web"
	if FirstAdminLocal() {
		data["first_admin"] = "local"
	}
	if service.MyService.User().GetUserCount() > 0 {
		data["initialized"] = true
		data["key"] = ""
	} else if FirstAdminLocal() {
		// no key over the network: the first account is created on the machine
		data["initialized"] = false
		data["key"] = ""
	} else {
		key := uuid.NewV4().String()
		service.UserRegisterMu.Lock()
		service.UserRegisterHash[key] = key
		service.UserRegisterMu.Unlock()
		data["key"] = key
		data["initialized"] = false
	}
	gpus, err := external.NvidiaGPUInfoList()
	if err != nil {
		logger.Error("NvidiaGPUInfoList error", zap.Error(err))
	}
	data["gpus"] = len(gpus)
	// which login page to show: the login page asks before anybody signs in
	data["login_style"] = LoginStyle()
	return ctx.JSON(common_err.SUCCESS,
		model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    data,
		})
}
