package route_test

import (
	"testing"

	"github.com/ReCasaOS/CasaOS-UserService/pkg/utils/encryption"
	model2 "github.com/ReCasaOS/CasaOS-UserService/service/model"
)

// The access token works bare (as the dashboard sends it) and as `Bearer <token>`.
func TestTheAccessTokenIsTakenBareOrAsBearer(t *testing.T) {
	users, c := newRig(t)
	users.CreateUser(model2.UserDBModel{Username: "owner", Password: encryption.HashPassword("a long enough one"), Role: "admin"})
	access, _ := tokens(t, c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "owner", "password": "a long enough one"}))

	c.expect(200, 200, "GET", "/v1/users/current", access, nil)
	c.expect(200, 200, "GET", "/v1/users/current", "Bearer "+access, nil)
	c.expect(200, 200, "GET", "/v1/users/current", "bearer "+access, nil)
	c.expect(401, 0, "GET", "/v1/users/current", "Basic "+access, nil)
}
