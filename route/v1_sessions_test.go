package route_test

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/utils/jwt"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/utils/encryption"
	model2 "github.com/ReCasaOS/CasaOS-UserService/service/model"
	gojwt "github.com/golang-jwt/jwt/v4"
)

func refreshStatus(c client, refresh string) (int, result) {
	return c.do("POST", "/v1/users/refresh", "", map[string]string{"refresh_token": refresh})
}

// A refresh token is good for seven days and for a new pair each time, so a copy of one outlived
// everything its owner could do. Changing the password ends every session opened before it; the
// one that changed it goes on with the pair the change hands back.
func TestARefreshTokenStopsWorkingWhenThePasswordChanges(t *testing.T) {
	users, c := newRig(t)
	const password, changed = "correct horse", "battery staple"
	users.CreateUser(model2.UserDBModel{Username: "admin", Password: encryption.HashPassword(password), Role: "admin"})

	access, copied := tokens(t, c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "admin", "password": password}))
	// the copy is used once: the pair it gives is as old as the session
	status, res := refreshStatus(c, copied)
	if status != http.StatusOK {
		t.Fatalf("a refresh before the change: %d", status)
	}
	renewed, _ := res.Data["refresh_token"].(string)
	if renewed == "" {
		t.Fatalf("no refresh token in %v", res.Data)
	}

	data := c.expect(200, 200, "PUT", "/v1/users/current/password", access, map[string]string{"old_password": password, "password": changed})
	_, mine := tokens(t, data)
	if user, _ := data["user"].(map[string]interface{}); user["username"] != "admin" || user["password"] != nil {
		t.Fatalf("the user of the answer: %v", data["user"])
	}

	for name, token := range map[string]string{"the copied token": copied, "the one it was renewed into": renewed} {
		if status, _ := refreshStatus(c, token); status != http.StatusUnauthorized {
			t.Errorf("%s after the password changed: %d, want 401", name, status)
		}
	}
	status, res = refreshStatus(c, mine)
	if status != http.StatusOK {
		t.Fatalf("the session that changed the password: %d, want 200", status)
	}
	// and what it is renewed into goes on working
	if next, _ := res.Data["refresh_token"].(string); next == "" {
		t.Fatalf("no refresh token in %v", res.Data)
	} else if status, _ := refreshStatus(c, next); status != http.StatusOK {
		t.Fatalf("the renewed token of that session: %d, want 200", status)
	}
	c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "admin", "password": changed})
}

func TestARefreshTokenStopsWorkingWhenTheAccountIsGone(t *testing.T) {
	users, c := newRig(t)
	const password = "correct horse"
	user := users.CreateUser(model2.UserDBModel{Username: "guest", Password: encryption.HashPassword(password), Role: "admin"})
	_, refresh := tokens(t, c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "guest", "password": password}))

	users.DeleteUserById(strconv.Itoa(user.Id))

	if status, _ := refreshStatus(c, refresh); status != http.StatusUnauthorized {
		t.Fatalf("the token of an account that is gone: %d, want 401", status)
	}
}

// A box that updates keeps its sessions: a token made before this change says nothing of the
// session it belongs to, and is one of the sessions opened before any password change.
func TestARefreshTokenMadeBeforeSessionsWereCountedStillWorks(t *testing.T) {
	users, c, db := newRigDB(t)
	const password = "correct horse"
	user := users.CreateUser(model2.UserDBModel{Username: "admin", Password: encryption.HashPassword(password), Role: "admin"})
	// the row as the update finds it: the column is added with 0 in it
	if err := db.Exec("UPDATE o_users SET session_version = 0").Error; err != nil {
		t.Fatal(err)
	}
	private, _ := users.GetKeyPair()
	old, err := jwt.GetRefreshToken("admin", private, user.Id)
	if err != nil {
		t.Fatal(err)
	}

	if status, _ := refreshStatus(c, old); status != http.StatusOK {
		t.Fatalf("a token of before the update: %d, want 200", status)
	}

	access, _ := tokens(t, c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "admin", "password": password}))
	c.expect(200, 200, "PUT", "/v1/users/current/password", access, map[string]string{"old_password": password, "password": "battery staple"})
	if status, _ := refreshStatus(c, old); status != http.StatusUnauthorized {
		t.Fatalf("a token of before the update, after the password changed: %d, want 401", status)
	}
}

// The reset from the command line is what an owner runs when the account is not theirs any more:
// it ends the sessions too.
func TestARefreshTokenStopsWorkingWhenTheCredentialsAreReset(t *testing.T) {
	users, c := newRig(t)
	const password = "correct horse"
	user := users.CreateUser(model2.UserDBModel{Username: "admin", Password: encryption.HashPassword(password), Role: "admin"})
	_, refresh := tokens(t, c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "admin", "password": password}))

	user.Password = encryption.HashPassword("battery staple")
	if err := users.ResetUserCredentials(user); err != nil {
		t.Fatal(err)
	}

	if status, _ := refreshStatus(c, refresh); status != http.StatusUnauthorized {
		t.Fatalf("a token of before the reset: %d, want 401", status)
	}
	c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "admin", "password": "battery staple"})
}

// The database gives the number of an account that is gone to the next one that is made. A
// token of the first, an hour old, must not open the second: a token is never older than its
// account.
func TestARefreshTokenOfAnAccountThatIsGoneDoesNotOpenTheNextOne(t *testing.T) {
	users, c := newRig(t)
	gone := users.CreateUser(model2.UserDBModel{Username: "admin", Password: encryption.HashPassword("correct horse"), Role: "admin"})
	private, _ := users.GetKeyPair()
	issued := time.Now().Add(-time.Hour)
	old, err := gojwt.NewWithClaims(gojwt.SigningMethodES256, jwt.Claims{Username: "admin", ID: gone.Id, RegisteredClaims: gojwt.RegisteredClaims{
		ExpiresAt: gojwt.NewNumericDate(issued.Add(7 * 24 * time.Hour)),
		IssuedAt:  gojwt.NewNumericDate(issued),
		NotBefore: gojwt.NewNumericDate(issued),
		Issuer:    "refresh",
		ID:        "0",
	}}).SignedString(private)
	if err != nil {
		t.Fatal(err)
	}

	users.DeleteUserById(strconv.Itoa(gone.Id))
	next := users.CreateUser(model2.UserDBModel{Username: "owner", Password: encryption.HashPassword("battery staple"), Role: "admin"})
	if next.Id != gone.Id {
		t.Skipf("the next account got another number (%d after %d): nothing to tell apart", next.Id, gone.Id)
	}

	if status, _ := refreshStatus(c, old); status != http.StatusUnauthorized {
		t.Fatalf("the token of the account that was there before: %d, want 401", status)
	}
	// and the next account's own session works
	_, refresh := tokens(t, c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "owner", "password": "battery staple"}))
	if status, _ := refreshStatus(c, refresh); status != http.StatusOK {
		t.Fatalf("the session of the next account: %d, want 200", status)
	}
}

// Saving the profile from a row read earlier must not put the sessions back to where they were.
func TestSavingAProfileDoesNotBringEndedSessionsBack(t *testing.T) {
	users, c := newRig(t)
	const password = "correct horse"
	user := users.CreateUser(model2.UserDBModel{Username: "admin", Password: encryption.HashPassword(password), Role: "admin"})
	if err := users.UpdateUserPassword(user); err != nil { // the row is at session 1
		t.Fatal(err)
	}
	_, copied := tokens(t, c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "admin", "password": password}))
	read := users.GetUserAllInfoById(strconv.Itoa(user.Id)) // read while the copied token is good
	if err := users.UpdateUserPassword(read); err != nil {  // session 2: the copied token is ended
		t.Fatal(err)
	}

	read.Nickname = "Ada"
	users.UpdateUser(read)

	if status, _ := refreshStatus(c, copied); status != http.StatusUnauthorized {
		t.Fatalf("an ended session, after the profile was saved from an older read: %d, want 401", status)
	}
}
