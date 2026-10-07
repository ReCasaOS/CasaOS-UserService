package route_test

import (
	"strings"
	"testing"

	"github.com/ReCasaOS/CasaOS-UserService/pkg/config"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/utils/encryption"
	"github.com/ReCasaOS/CasaOS-UserService/service"
	model2 "github.com/ReCasaOS/CasaOS-UserService/service/model"
)

const argonPrefix = "$argon2id$"

func storedPassword(t *testing.T, users service.UserService, name string) string {
	t.Helper()
	user := users.GetUserAllInfoByName(name)
	if user.Id == 0 {
		t.Fatalf("no user %q", name)
	}
	return user.Password
}

// An account from an older release, or from IceWhale's, holds an unsalted MD5.
// It signs in, and the sign-in leaves an argon2id hash in its place.
func TestASignInReplacesTheLegacyMD5(t *testing.T) {
	users, c := newRig(t)
	const password = "correct horse"
	legacy := encryption.GetMD5ByStr(password)
	users.CreateUser(model2.UserDBModel{Username: "admin", Password: legacy, Role: "admin"})

	c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "admin", "password": password})

	stored := storedPassword(t, users, "admin")
	if !strings.HasPrefix(stored, argonPrefix) {
		t.Fatalf("after a sign-in the password is still %q", stored)
	}
	// and it is still the same password, for this sign-in and the next
	c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "admin", "password": password})
	c.expect(400, 10013, "POST", "/v1/users/login", "", map[string]string{"username": "admin", "password": "wrong"})
	if again := storedPassword(t, users, "admin"); again != stored {
		t.Fatal("a second sign-in made a new hash: only the legacy one is replaced")
	}
}

func TestAWrongPasswordLeavesTheLegacyHashAlone(t *testing.T) {
	users, c := newRig(t)
	legacy := encryption.GetMD5ByStr("correct horse")
	users.CreateUser(model2.UserDBModel{Username: "admin", Password: legacy, Role: "admin"})

	c.expect(400, 10013, "POST", "/v1/users/login", "", map[string]string{"username": "admin", "password": "wrong"})

	if stored := storedPassword(t, users, "admin"); stored != legacy {
		t.Fatalf("a failed sign-in changed the stored password to %q", stored)
	}
}

func TestANewAccountIsStoredAsArgon2id(t *testing.T) {
	users, c := newRig(t)
	defer func(old string) { config.AppInfo.UserDataPath = old }(config.AppInfo.UserDataPath)
	config.AppInfo.UserDataPath = t.TempDir()
	service.UserRegisterHash["k"] = "k"

	c.expect(200, 200, "POST", "/v1/users/register", "", map[string]string{"username": "owner", "password": "a long enough one", "key": "k"})

	stored := storedPassword(t, users, "owner")
	if !strings.HasPrefix(stored, argonPrefix) {
		t.Fatalf("a new account's password is stored as %q", stored)
	}
	c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "owner", "password": "a long enough one"})
}

func TestChangingThePasswordStoresArgon2idAndRetiresTheOldOne(t *testing.T) {
	users, c := newRig(t)
	users.CreateUser(model2.UserDBModel{Username: "admin", Password: encryption.GetMD5ByStr("old password"), Role: "admin"})
	access, _ := tokens(t, c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "admin", "password": "old password"}))

	c.expect(200, 200, "PUT", "/v1/users/current/password", access, map[string]string{"old_password": "old password", "password": "new password"})

	if stored := storedPassword(t, users, "admin"); !strings.HasPrefix(stored, argonPrefix) || encryption.VerifyPassword(stored, "old password") {
		t.Fatalf("after the change the stored password is %q", stored)
	}
	c.expect(400, 10013, "POST", "/v1/users/login", "", map[string]string{"username": "admin", "password": "old password"})
	c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "admin", "password": "new password"})
}

// A sign-in that read the legacy hash before a password change wrote its own
// must not put the old password back when it comes to replace the hash.
func TestAStaleSignInDoesNotRestoreAChangedPassword(t *testing.T) {
	users, _ := newRig(t)
	legacy := encryption.GetMD5ByStr("old password")
	user := users.CreateUser(model2.UserDBModel{Username: "admin", Password: legacy, Role: "admin"})

	changed := encryption.HashPassword("new password")
	user.Password = changed
	users.UpdateUserPassword(user) // the change lands between the sign-in's read and its write

	if users.ReplacePasswordHash(user.Id, legacy, encryption.HashPassword("old password")) {
		t.Fatal("the swap landed on a row that no longer held the hash it was made from")
	}
	if stored := storedPassword(t, users, "admin"); stored != changed {
		t.Fatalf("the changed password was overwritten by %q", stored)
	}
	if !users.ReplacePasswordHash(user.Id, changed, encryption.HashPassword("new password")) {
		t.Fatal("the swap does not land on a row that still holds the hash it was made from")
	}
}
