package route_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/ReCasaOS/CasaOS-UserService/pkg/config"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/utils/encryption"
	v1 "github.com/ReCasaOS/CasaOS-UserService/route/v1"
	"github.com/ReCasaOS/CasaOS-UserService/service"
	model2 "github.com/ReCasaOS/CasaOS-UserService/service/model"
)

func userDataIn(t *testing.T) string {
	t.Helper()
	previous := config.AppInfo.UserDataPath
	config.AppInfo.UserDataPath = t.TempDir()
	t.Cleanup(func() { config.AppInfo.UserDataPath = previous })
	return config.AppInfo.UserDataPath
}

// The key GET /v1/users/status hands out creates the first account and no other.
// Every visit before the box is set up gets one; those not used are worth nothing
// once an account exists, or anybody who looked at the box that day makes
// themselves an administrator later.
func TestARegisterKeyCreatesTheFirstAccountAndNoOther(t *testing.T) {
	users, c := newRig(t)
	userDataIn(t)

	kept, _ := c.expect(200, 200, "GET", "/v1/users/status", "", nil)["key"].(string)
	used, _ := c.expect(200, 200, "GET", "/v1/users/status", "", nil)["key"].(string)
	if kept == "" || used == "" || kept == used {
		t.Fatalf("two visits, two keys: %q %q", kept, used)
	}

	c.expect(200, 200, "POST", "/v1/users/register", "", map[string]string{"username": "owner", "password": "a long enough one", "key": used})
	c.expect(400, 10008, "POST", "/v1/users/register", "", map[string]string{"username": "intruder", "password": "a long enough one", "key": kept})
	// a visit that read "no account yet" just before, and whose key lands just after
	service.UserRegisterHash["late"] = "late"
	c.expect(400, 10008, "POST", "/v1/users/register", "", map[string]string{"username": "intruder", "password": "a long enough one", "key": "late"})

	if count := users.GetUserCount(); count != 1 {
		t.Fatalf("%d accounts, want the owner alone", count)
	}
}

// /login needs no account, so everybody who never signed in shares one budget, as
// before: nothing more for somebody guessing passwords from many addresses. An
// address somebody did sign in from has its own, so the owner's machine still gets
// in when another one has spent the strangers'.
func TestAnAddressThatSignedInKeepsItsOwnSignInBudget(t *testing.T) {
	users, c := newRig(t)
	v1.LoginLimit = rate.Every(time.Minute)
	v1.ResetLoginLimiters()
	const password = "correct horse"
	users.CreateUser(model2.UserDBModel{Username: "owner", Password: encryption.HashPassword(password), Role: "admin"})
	right := map[string]string{"username": "owner", "password": password}
	wrong := map[string]string{"username": "owner", "password": "wrong"}

	c.expect(200, 200, "POST", "/v1/users/login", "", right) // one of the strangers' five; known from here on

	noisy := client{t: t, h: c.h, ip: "10.0.0.66"}
	for i := 0; i < 4; i++ {
		noisy.expect(400, 10013, "POST", "/v1/users/login", "", wrong)
	}
	noisy.expect(429, 10012, "POST", "/v1/users/login", "", wrong)
	client{t: t, h: c.h, ip: "10.0.0.77"}.expect(429, 10012, "POST", "/v1/users/login", "", right) // a stranger too, password or not

	c.expect(200, 200, "POST", "/v1/users/login", "", right)
	for i := 0; i < 4; i++ {
		c.expect(400, 10013, "POST", "/v1/users/login", "", wrong)
	}
	c.expect(429, 10012, "POST", "/v1/users/login", "", wrong) // its own budget is a budget
}

// Without signing in, /v1/users/image gives the pictures the sign-in page shows and
// nothing else a user's folder holds: the dashboard's settings are kept there too.
func TestWithoutSigningInOnlyPicturesAreServed(t *testing.T) {
	_, c := newRig(t)
	home := filepath.Join(userDataIn(t), "1")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	// "wallpaper" is a picture stored without an extension: PUT .../image/:key keeps the source's
	for name, content := range map[string]string{
		"avatar.png": "content", "login-wallpaper.jpg": "content", "wallpaper.JPG": "content",
		"wallpaper": "\x89PNG\r\n\x1a\n", "system.json": `{"lang":"en_us"}`, "notes": "content",
	} {
		if err := os.WriteFile(filepath.Join(home, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	get := func(file string) int {
		status, _ := c.do("GET", "/v1/users/image?path="+filepath.ToSlash(file), "", nil)
		return status
	}

	for _, picture := range []string{"avatar.png", "login-wallpaper.jpg", "wallpaper.JPG", "wallpaper"} {
		if status := get(filepath.Join(home, picture)); status != 200 {
			t.Fatalf("%s: %d, want it served", picture, status)
		}
	}
	for _, kept := range []string{
		filepath.Join(home, "system.json"), filepath.Join(home, "..", "1", "system.json"),
		filepath.Join(home, "notes"), filepath.Join(filepath.Dir(home), "avatar.png"),
	} {
		if status := get(kept); status != 404 {
			t.Fatalf("%s: %d, want it refused", kept, status)
		}
	}

	// outside a user's folder, a file that exists and one that does not get the same answer
	outside := filepath.Join(t.TempDir(), "there.png")
	if err := os.WriteFile(outside, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, there := c.do("GET", "/v1/users/image?path="+filepath.ToSlash(outside), "", nil)
	_, absent := c.do("GET", "/v1/users/image?path="+filepath.ToSlash(outside)+".absent", "", nil)
	if there.Success != absent.Success {
		t.Fatalf("the answer says whether a file outside exists: %d and %d", there.Success, absent.Success)
	}
}

// Who has an account here is not said to somebody who has none.
func TestTheNamesOfTheAccountsNeedASignIn(t *testing.T) {
	users, c := newRig(t)
	const password = "correct horse"
	users.CreateUser(model2.UserDBModel{Username: "owner", Password: encryption.HashPassword(password), Role: "admin"})

	if status, _ := c.do("GET", "/v1/users/name", "", nil); status != 401 {
		t.Fatalf("without a token: %d, want 401", status)
	}
	access, _ := tokens(t, c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "owner", "password": password}))
	if status, _ := c.do("GET", "/v1/users/name", access, nil); status != 200 {
		t.Fatalf("with a token: %d, want 200", status)
	}
}
