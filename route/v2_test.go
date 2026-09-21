package route_test

import (
	"testing"

	"github.com/ReCasaOS/CasaOS-UserService/pkg/utils/encryption"
	"github.com/ReCasaOS/CasaOS-UserService/route"
	model2 "github.com/ReCasaOS/CasaOS-UserService/service/model"
)

// TestV2AuthThenValidation pins the v2 middleware chain: the JWT check runs
// before the OpenAPI validator, and the validator still resolves routes and
// checks parameters against the spec. None of these requests reaches a
// handler.
func TestV2AuthThenValidation(t *testing.T) {
	users, c := newRig(t)
	users.CreateUser(model2.UserDBModel{Username: "admin", Password: encryption.GetMD5ByStr("pw"), Role: "admin"})
	access, _ := tokens(t, c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "admin", "password": "pw"}))
	v2 := client{t: t, h: route.InitV2Router()}

	for _, tc := range []struct {
		path, token string
		want        int
	}{
		{"/v2/users/nope", "", 401},                      // the validator would say 400: auth runs first
		{"/v2/users/events?form=yesterday", "", 401},     // same with a known route
		{"/v2/users/nope", access, 400},                  // unknown route
		{"/v2/users/events?form=yesterday", access, 400}, // form is not a date-time
	} {
		if got, _ := v2.do("GET", tc.path, tc.token, nil); got != tc.want {
			t.Errorf("GET %s (token %v): got %d, want %d", tc.path, tc.token != "", got, tc.want)
		}
	}
}
