package v1

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/IceWhaleTech/CasaOS-Common/utils/common_err"
	"github.com/IceWhaleTech/CasaOS-UserService/common"
	"github.com/IceWhaleTech/CasaOS-UserService/model"
	model2 "github.com/IceWhaleTech/CasaOS-UserService/service/model"
	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
	"golang.org/x/time/rate"

	"github.com/IceWhaleTech/CasaOS-UserService/service"
)

// Per-user limiter for second-factor and password checks: burst 5, refill
// 5/min. Every attempt costs a token, correct answers included, and the token
// is taken before anything is checked: N concurrent attempts cannot all see a
// full bucket and all get verified. Five a minute is plenty for a human.
// ponytail: the map grows with the user count (one admin) and is never pruned.
var (
	// UserLimit is the per-user refill rate; exported so tests can lift it.
	UserLimit = rate.Every(time.Minute / 5)

	userLimitersMu sync.Mutex
	userLimiters   = map[int]*rate.Limiter{}
)

func userLimiter(id int) *rate.Limiter {
	userLimitersMu.Lock()
	defer userLimitersMu.Unlock()
	l, ok := userLimiters[id]
	if !ok {
		l = rate.NewLimiter(UserLimit, 5)
		userLimiters[id] = l
	}
	return l
}

// ResetUserLimiters drops every per-user limiter. Test hook: user ids restart
// at 1 in every fresh database while this map is process-wide, so without it
// a test inherits the budget another test spent on the same id.
func ResetUserLimiters() {
	userLimitersMu.Lock()
	defer userLimitersMu.Unlock()
	userLimiters = map[int]*rate.Limiter{}
}

func fail(ctx echo.Context, status, code int) error {
	return ctx.JSON(status, model.Result{Success: code, Message: common.GetMsg(code)})
}

func ok(ctx echo.Context, data interface{}) error {
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: data})
}

// PostUser2FAVerify exchanges the pre-auth token from /login plus a TOTP code
// or a recovery code for the usual access and refresh tokens. Public route,
// deliberately outside LoginLimiter: without a pre-auth token, which only a
// correct password on the limited /login mints, a request costs one signature
// check and nothing else; with one, attempts are bounded by the per-user
// budget and the token's five minutes. A global budget here would only let
// anyone starve /login with garbage.
func PostUser2FAVerify(ctx echo.Context) error {
	json := make(map[string]string)
	ctx.Bind(&json)

	claims, err := service.MyService.User().ParsePreAuthToken(json["pre_auth_token"])
	if err != nil {
		// 400, not 401: the dashboard treats every 401 as an expired session.
		return fail(ctx, common_err.CLIENT_ERROR, common_err.VERIFICATION_FAILURE)
	}
	user := service.MyService.User().GetUserAllInfoById(strconv.Itoa(claims.ID))
	if user.Id == 0 || !user.TotpEnabled {
		return fail(ctx, common_err.CLIENT_ERROR, common.TWO_FA_NOT_ENABLED)
	}
	if !userLimiter(user.Id).Allow() {
		return fail(ctx, common_err.TOO_MANY_REQUEST, common_err.TOO_MANY_LOGIN_REQUESTS)
	}

	code, recovery := json["code"], json["recovery_code"]
	switch {
	case code != "" && recovery == "":
		// VerifyTOTP checks the step against the row as read; ConsumeTOTPStep
		// is the atomic check, so a code replayed concurrently passes once.
		step, valid := service.VerifyTOTP(user.TotpSecret, code, user.TotpLastStep, time.Now())
		if !valid || !service.MyService.User().ConsumeTOTPStep(user.Id, step) {
			return fail(ctx, common_err.CLIENT_ERROR, common.TWO_FA_CODE_INVALID)
		}
	case recovery != "" && code == "":
		if !service.MyService.User().UseRecoveryCode(user.Id, recovery) {
			return fail(ctx, common_err.CLIENT_ERROR, common.TWO_FA_CODE_INVALID)
		}
	default:
		return fail(ctx, common_err.CLIENT_ERROR, common_err.INVALID_PARAMS)
	}
	return issueTokens(ctx, user)
}

// PostUser2FASetup stores a pending secret and returns it for the authenticator.
// The session is not enough: the JWT middleware accepts a refresh token as an
// access token, so a stolen token alone must not be able to enrol an
// authenticator and lock the owner out. The password is required, as on
// /2fa/disable, and the check draws on the same per-user budget.
func PostUser2FASetup(ctx echo.Context) error {
	user := service.MyService.User().GetUserAllInfoById(ctx.Request().Header.Get("user_id"))
	if user.Id == 0 {
		return fail(ctx, common_err.SERVICE_ERROR, common_err.USER_NOT_EXIST)
	}
	if user.TotpEnabled {
		return fail(ctx, common_err.CLIENT_ERROR, common.TWO_FA_ALREADY_ENABLED)
	}
	json := make(map[string]string)
	ctx.Bind(&json)
	if json["password"] == "" {
		return fail(ctx, common_err.CLIENT_ERROR, common_err.INVALID_PARAMS)
	}
	if !userLimiter(user.Id).Allow() {
		return fail(ctx, common_err.TOO_MANY_REQUEST, common_err.TOO_MANY_LOGIN_REQUESTS)
	}
	if !passwordMatches(user.Password, json["password"]) {
		return fail(ctx, common_err.CLIENT_ERROR, common.TWO_FA_CODE_INVALID)
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "CasaOS", AccountName: user.Username})
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: err.Error()})
	}
	service.MyService.User().UpdateUserTOTP(model2.UserDBModel{Id: user.Id, TotpSecret: key.Secret()})
	return ok(ctx, map[string]string{"secret": key.Secret(), "otpauth_url": key.URL()})
}

// PostUser2FAEnable confirms the pending secret with a code and returns the
// recovery codes, once.
func PostUser2FAEnable(ctx echo.Context) error {
	user := service.MyService.User().GetUserAllInfoById(ctx.Request().Header.Get("user_id"))
	if user.Id == 0 {
		return fail(ctx, common_err.SERVICE_ERROR, common_err.USER_NOT_EXIST)
	}
	if user.TotpEnabled {
		return fail(ctx, common_err.CLIENT_ERROR, common.TWO_FA_ALREADY_ENABLED)
	}
	if user.TotpSecret == "" {
		return fail(ctx, common_err.CLIENT_ERROR, common.TWO_FA_NOT_ENABLED)
	}
	if !userLimiter(user.Id).Allow() {
		return fail(ctx, common_err.TOO_MANY_REQUEST, common_err.TOO_MANY_LOGIN_REQUESTS)
	}
	json := make(map[string]string)
	ctx.Bind(&json)

	step, valid := service.VerifyTOTP(user.TotpSecret, json["code"], 0, time.Now())
	if !valid {
		return fail(ctx, common_err.CLIENT_ERROR, common.TWO_FA_CODE_INVALID)
	}
	plain, hashes, err := service.NewRecoveryCodes()
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: err.Error()})
	}
	// The enrolment step is recorded so that code cannot be replayed at first
	// login. EnableUserTOTP is a compare-and-set on the pending secret: of two
	// requests carrying the same code, one enables and gets its codes stored,
	// the other is told 2FA is already enabled (also what a login that cleared
	// the pending secret in between looks like: the setup is over either way).
	if !service.MyService.User().EnableUserTOTP(user.Id, user.TotpSecret, step, hashes) {
		return fail(ctx, common_err.CLIENT_ERROR, common.TWO_FA_ALREADY_ENABLED)
	}
	return ok(ctx, map[string][]string{"recovery_codes": plain})
}

// PostUser2FADisable turns 2FA off after a current code or the password.
func PostUser2FADisable(ctx echo.Context) error {
	user := service.MyService.User().GetUserAllInfoById(ctx.Request().Header.Get("user_id"))
	if user.Id == 0 {
		return fail(ctx, common_err.SERVICE_ERROR, common_err.USER_NOT_EXIST)
	}
	if !user.TotpEnabled {
		return fail(ctx, common_err.CLIENT_ERROR, common.TWO_FA_NOT_ENABLED)
	}
	json := make(map[string]string)
	ctx.Bind(&json)
	code, password := json["code"], json["password"]
	if (code == "") == (password == "") { // exactly one of the two
		return fail(ctx, common_err.CLIENT_ERROR, common_err.INVALID_PARAMS)
	}
	if !userLimiter(user.Id).Allow() {
		return fail(ctx, common_err.TOO_MANY_REQUEST, common_err.TOO_MANY_LOGIN_REQUESTS)
	}

	var valid bool
	if code != "" {
		_, valid = service.VerifyTOTP(user.TotpSecret, code, user.TotpLastStep, time.Now())
	} else {
		valid = passwordMatches(user.Password, password)
	}
	if !valid {
		return fail(ctx, common_err.CLIENT_ERROR, common.TWO_FA_CODE_INVALID)
	}
	service.MyService.User().UpdateUserTOTP(model2.UserDBModel{Id: user.Id})
	return ok(ctx, nil)
}
