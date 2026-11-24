package v1

import (
	"net/http"
	"strconv"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/CasaOS-Common/utils/common_err"
	"github.com/ReCasaOS/CasaOS-Common/utils/jwt"
	"github.com/ReCasaOS/CasaOS-UserService/model"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/config"
	"github.com/ReCasaOS/CasaOS-UserService/service"
	"github.com/labstack/echo/v4"
)

const internalTokenLife = 5 * time.Minute

// PostInternalAccessToken hands one of the box's own services a short access token for an account.
// The group's middleware also lets a JWT through, so the handler checks for itself that the caller
// is a service of this box (loopback plus the secret of this boot).
func PostInternalAccessToken(ctx echo.Context) error {
	if !external.IsInternalRequest(ctx.RealIP(), ctx.Request().Header.Get(echo.HeaderAuthorization), config.CommonInfo.RuntimePath) {
		return forbidden(ctx)
	}
	var body struct {
		ID int `json:"id"`
	}
	if err := ctx.Bind(&body); err != nil || body.ID <= 0 {
		return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.CLIENT_ERROR, Message: "a positive account id is required"})
	}
	user := service.MyService.User().GetUserAllInfoById(strconv.Itoa(body.ID))
	if user.Id == 0 {
		return ctx.JSON(http.StatusNotFound, model.Result{Success: common_err.USER_NOT_EXIST, Message: common_err.GetMsg(common_err.USER_NOT_EXIST)})
	}
	privateKey, _ := service.MyService.User().GetKeyPair()
	token, err := jwt.GenerateToken(user.Username, privateKey, user.Id, jwt.AccessIssuer, internalTokenLife)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	return ctx.JSON(http.StatusOK, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: map[string]interface{}{
		"access_token": token,
		"expires_at":   time.Now().Add(internalTokenLife).Unix(),
	}})
}
