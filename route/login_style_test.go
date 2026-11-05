package route_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ReCasaOS/CasaOS-UserService/pkg/config"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/utils/encryption"
	model2 "github.com/ReCasaOS/CasaOS-UserService/service/model"
)

// The login page asks which page to be before anybody signs in; only a session
// changes it, and classic leaves nothing behind.
func TestTheLoginStyleIsSaidToAnybodyAndChangedWithASession(t *testing.T) {
	users, c := newRig(t)
	config.AppInfo.UserDataPath = t.TempDir()
	users.CreateUser(model2.UserDBModel{Username: "owner", Password: encryption.GetMD5ByStr("a long enough one"), Role: "admin"})

	style := func() interface{} {
		t.Helper()
		return c.expect(200, 200, "GET", "/v1/users/status", "", nil)["login_style"]
	}
	if got := style(); got != "classic" {
		t.Fatalf("a new box: %v, want classic", got)
	}

	c.expect(401, 0, "PUT", "/v1/users/login-style", "", map[string]string{"style": "beta"})
	if got := style(); got != "classic" {
		t.Fatalf("after a PUT without a session: %v", got)
	}

	access, _ := tokens(t, c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "owner", "password": "a long enough one"}))
	for _, bad := range []map[string]string{{"style": "Beta"}, {"style": ""}, {"style": "../x"}, {}} {
		c.expect(400, 4000, "PUT", "/v1/users/login-style", access, bad)
	}

	c.expect(200, 200, "PUT", "/v1/users/login-style", access, map[string]string{"style": "beta"})
	if got := style(); got != "beta" {
		t.Fatalf("after beta: %v", got)
	}
	file := filepath.Join(config.AppInfo.UserDataPath, "login-style")
	if raw, err := os.ReadFile(file); err != nil || string(raw) != "beta\n" {
		t.Fatalf("the file: %q %v", raw, err)
	}

	c.expect(200, 200, "PUT", "/v1/users/login-style", access, map[string]string{"style": "classic"})
	if got := style(); got != "classic" {
		t.Fatalf("after classic: %v", got)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("classic left the file: %v", err)
	}
	// twice is fine
	c.expect(200, 200, "PUT", "/v1/users/login-style", access, map[string]string{"style": "classic"})

	// a file with anything else in it is the classic page
	os.WriteFile(file, []byte("zima\n"), 0o644)
	if got := style(); got != "classic" {
		t.Fatalf("a file that says zima: %v", got)
	}
}
