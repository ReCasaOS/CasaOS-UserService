package route

import (
	"crypto/ecdsa"
	"net/http"
	"strconv"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/CasaOS-Common/utils/jwt"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/config"
	v1 "github.com/ReCasaOS/CasaOS-UserService/route/v1"
	"github.com/ReCasaOS/CasaOS-UserService/service"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	echo_middleware "github.com/labstack/echo/v4/middleware"
)

func InitRouter() http.Handler {
	e := echo.New()

	e.Use((echo_middleware.CORSWithConfig(echo_middleware.CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{echo.POST, echo.GET, echo.OPTIONS, echo.PUT, echo.DELETE},
		AllowHeaders:     []string{echo.HeaderAuthorization, echo.HeaderContentLength, echo.HeaderXCSRFToken, echo.HeaderContentType, echo.HeaderAccessControlAllowOrigin, echo.HeaderAccessControlAllowHeaders, echo.HeaderAccessControlAllowMethods, echo.HeaderConnection, echo.HeaderOrigin, echo.HeaderXRequestedWith},
		ExposeHeaders:    []string{echo.HeaderContentLength, echo.HeaderAccessControlAllowOrigin, echo.HeaderAccessControlAllowHeaders},
		MaxAge:           172800,
		AllowCredentials: true,
	})))

	e.Use(echo_middleware.Gzip())

	e.Use(echo_middleware.Logger())

	e.POST("/v1/users/register", v1.PostUserRegister)
	e.POST("/v1/users/login", v1.PostUserLogin)
	e.POST("/v1/users/2fa/verify", v1.PostUser2FAVerify)
	e.GET("/v1/users/name", v1.GetUserAllUsername) // all/name
	e.POST("/v1/users/refresh", v1.PostUserRefreshToken)
	// No short-term modifications
	e.GET("/v1/users/image", v1.GetUserImage)

	e.GET("/v1/users/status", v1.GetUserStatus) // init/check

	v1Group := e.Group("/v1")

	v1UsersGroup := v1Group.Group("/users")
	v1UsersGroup.Use(echojwt.WithConfig(echojwt.Config{
		Skipper: func(c echo.Context) bool {
			return external.IsInternalRequest(c.RealIP(), c.Request().Header.Get(echo.HeaderAuthorization), config.CommonInfo.RuntimePath)
		},
		ParseTokenFunc: func(c echo.Context, token string) (interface{}, error) {
			valid, claims, err := jwt.Validate(
				token,
				func() (*ecdsa.PublicKey, error) {
					_, publicKey := service.MyService.User().GetKeyPair()
					return publicKey, nil
				})
			if err != nil || !valid {
				return nil, echo.ErrUnauthorized
			}

			c.Request().Header.Set("user_id", strconv.Itoa(claims.ID))

			return claims, nil
		},
		TokenLookupFuncs: []echo_middleware.ValuesExtractor{
			func(c echo.Context) ([]string, error) {
				if len(c.Request().Header.Get(echo.HeaderAuthorization)) > 0 {
					return []string{c.Request().Header.Get(echo.HeaderAuthorization)}, nil
				}
				return []string{c.QueryParam("token")}, nil
			},
		},
	}))
	{
		v1UsersGroup.Use()
		v1UsersGroup.GET("/current", v1.GetUserInfo)
		v1UsersGroup.PUT("/current", v1.PutUserInfo)
		v1UsersGroup.PUT("/current/password", v1.PutUserPassword)

		v1UsersGroup.POST("/2fa/setup", v1.PostUser2FASetup)
		v1UsersGroup.POST("/2fa/enable", v1.PostUser2FAEnable)
		v1UsersGroup.POST("/2fa/disable", v1.PostUser2FADisable)

		v1UsersGroup.GET("/current/custom/:key", v1.GetUserCustomConf)
		v1UsersGroup.POST("/current/custom/:key", v1.PostUserCustomConf)
		v1UsersGroup.DELETE("/current/custom/:key", v1.DeleteUserCustomConf)

		v1UsersGroup.POST("/current/image/:key", v1.PostUserUploadImage)
		v1UsersGroup.PUT("/current/image/:key", v1.PutUserImage)
		// v1UserGroup.POST("/file/image/:key", v1.PostUserFileImage)
		v1UsersGroup.DELETE("/current/image", v1.DeleteUserImage)

		v1UsersGroup.PUT("/avatar", v1.PutUserAvatar)
		v1UsersGroup.GET("/avatar", v1.GetUserAvatar)

		v1UsersGroup.DELETE("/:id", v1.DeleteUser)
		v1UsersGroup.GET("/:username", v1.GetUserInfoByUsername)
		v1UsersGroup.DELETE("", v1.DeleteUserAll)
	}

	return e
}
