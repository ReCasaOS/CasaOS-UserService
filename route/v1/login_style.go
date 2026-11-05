package v1

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ReCasaOS/CasaOS-Common/utils/common_err"
	"github.com/ReCasaOS/CasaOS-UserService/model"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/config"
	"github.com/labstack/echo/v4"
)

// The login page has no session to read a user's settings with, so which of
// the two login pages the box shows is kept for the whole box, in a file of its
// own, and said by GET /v1/users/status to anybody. No file: the classic one.
const (
	LoginStyleClassic = "classic"
	LoginStyleBeta    = "beta"

	loginStyleFile = "login-style"
)

func loginStylePath() string {
	return filepath.Join(config.AppInfo.UserDataPath, loginStyleFile)
}

// LoginStyle is the login page the box shows: "beta" when it was chosen,
// "classic" otherwise, a file that cannot be read or says anything else too.
func LoginStyle() string {
	raw, err := os.ReadFile(loginStylePath())
	if err == nil && strings.TrimSpace(string(raw)) == LoginStyleBeta {
		return LoginStyleBeta
	}
	return LoginStyleClassic
}

// setLoginStyle keeps style; classic removes the file, so the box is as before.
func setLoginStyle(style string) error {
	path := loginStylePath()
	if style == LoginStyleClassic {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}

	// written beside and renamed, so a reader never sees half a file
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(style+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// PutLoginStyle chooses the login page the box shows: {"style": "classic"} or
// {"style": "beta"}. It needs a session, as every other setting does.
func PutLoginStyle(ctx echo.Context) error {
	var req struct {
		Style string `json:"style"`
	}
	if err := ctx.Bind(&req); err != nil || (req.Style != LoginStyleClassic && req.Style != LoginStyleBeta) {
		return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.INVALID_PARAMS, Message: "style is classic or beta"})
	}
	if err := setLoginStyle(req.Style); err != nil {
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: err.Error()})
	}
	return ctx.JSON(http.StatusOK, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: map[string]string{"style": req.Style}})
}
