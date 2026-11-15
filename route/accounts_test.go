package route_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/CasaOS-Common/utils/common_err"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/config"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/utils/encryption"
	"github.com/ReCasaOS/CasaOS-UserService/service"
	model2 "github.com/ReCasaOS/CasaOS-UserService/service/model"
	"gorm.io/gorm"
)

const ownerPassword = "correct horse"

// accounts is a rig with an owner, signed in, and a runtime path that holds the box's secret.
type accounts struct {
	users   service.UserService
	c       client
	owner   model2.UserDBModel
	access  string
	runtime string
	db      *gorm.DB
}

func newAccounts(t *testing.T) accounts {
	t.Helper()
	users, c, db := newRigDB(t)
	runtime := t.TempDir()
	if err := external.WriteInternalSecret(runtime); err != nil {
		t.Fatal(err)
	}
	previous, dataPath := config.CommonInfo.RuntimePath, config.AppInfo.UserDataPath
	config.CommonInfo.RuntimePath, config.AppInfo.UserDataPath = runtime, t.TempDir()
	t.Cleanup(func() { config.CommonInfo.RuntimePath, config.AppInfo.UserDataPath = previous, dataPath })

	owner := users.CreateUser(model2.UserDBModel{Username: "owner", Password: encryption.HashPassword(ownerPassword), Role: "admin"})
	access, _ := tokens(t, c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "owner", "password": ownerPassword}))
	return accounts{users: users, c: c, owner: owner, access: access, runtime: runtime, db: db}
}

// appManagement answers at the address the runtime path names; it records what it was asked.
func (a accounts) appManagement(t *testing.T, status int, seen func(r *http.Request)) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			seen(r)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	a.writeAddress(t, srv.URL)
}

func (a accounts) writeAddress(t *testing.T, address string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(a.runtime, external.AppManageURLFilename), []byte(address), 0o600); err != nil {
		t.Fatal(err)
	}
}

// internal is a client the services would be: loopback, with the box's secret.
func (a accounts) internal() (client, string) {
	return client{t: a.c.t, h: a.c.h, ip: "127.0.0.1"}, external.InternalAuthorization(a.runtime)
}

// createUser makes an account through the API, as the owner, and signs it in.
func (a accounts) createUser(t *testing.T, name string) (id int, access, refresh string) {
	t.Helper()
	a.c.expect(200, 200, "POST", "/v1/users", a.access, map[string]string{"username": name, "password": "a long enough one"})
	id = a.users.GetUserAllInfoByName(name).Id
	access, refresh = tokens(t, a.c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": name, "password": "a long enough one"}))
	return id, access, refresh
}

func TestUserCannotCreateAccounts(t *testing.T) {
	a := newAccounts(t)
	id, access, _ := a.createUser(t, "marie")
	before := a.users.GetUserCount()

	a.c.expect(403, 10011, "POST", "/v1/users", access, map[string]string{"username": "eve", "password": "a long enough one"})
	a.c.expect(403, 10011, "GET", "/v1/users", access, nil)
	a.c.expect(403, 10011, "DELETE", "/v1/users/"+strconv.Itoa(a.owner.Id), access, nil)
	a.c.expect(403, 10011, "DELETE", "/v1/users/"+strconv.Itoa(id), access, nil)

	if got := a.users.GetUserCount(); got != before {
		t.Fatalf("accounts: %d, want %d", got, before)
	}
}

func TestAdminCreatesUserAccount(t *testing.T) {
	a := newAccounts(t)
	a.c.expect(200, 200, "POST", "/v1/users", a.access, map[string]string{"username": "marie", "password": "a long enough one"})

	marie := a.users.GetUserAllInfoByName("marie")
	if marie.Role != "user" || !strings.HasPrefix(marie.Password, argonPrefix) || marie.SessionVersion == 0 {
		t.Fatalf("stored as %+v", marie)
	}
	a.c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "marie", "password": "a long enough one"})

	a.c.expect(400, 10007, "POST", "/v1/users", a.access, map[string]string{"username": "marie", "password": "another long one"})
	a.c.expect(400, 10005, "POST", "/v1/users", a.access, map[string]string{"username": "paul", "password": "short"})
	a.c.expect(400, 4000, "POST", "/v1/users", a.access, map[string]string{"username": "", "password": "a long enough one"})

	rows := a.list(t)
	if len(rows) != 2 {
		t.Fatalf("list: %v", rows)
	}
	for _, row := range rows {
		if _, leaked := row["password"]; leaked || row["username"] == nil || row["id"] == nil || row["role"] == nil || row["totp_enabled"] == nil {
			t.Fatalf("a row of the list: %v", row)
		}
		if row["username"] == "marie" && row["role"] != "user" {
			t.Fatalf("marie in the list: %v", row)
		}
	}
}

func TestRoleFieldIsRefusedOnCreation(t *testing.T) {
	a := newAccounts(t)
	for _, role := range []string{"admin", "user", ""} {
		a.c.expect(400, 4000, "POST", "/v1/users", a.access, map[string]string{"username": "eve", "password": "a long enough one", "role": role})
	}
	if got := a.users.GetUserAllInfoByName("eve"); got.Id != 0 {
		t.Fatalf("an account was made: %+v", got)
	}
}

func TestPutCurrentIgnoresRole(t *testing.T) {
	a := newAccounts(t)
	id, access, _ := a.createUser(t, "marie")

	a.c.expect(200, 200, "PUT", "/v1/users/current", access, map[string]interface{}{"role": "admin", "nickname": "Marie"})
	got := a.users.GetUserAllInfoById(strconv.Itoa(id))
	if got.Role != "user" || got.Nickname != "Marie" {
		t.Fatalf("after the save: role %q, nickname %q", got.Role, got.Nickname)
	}

	// the body does not choose whose profile is written either
	a.c.expect(200, 200, "PUT", "/v1/users/current", access, map[string]interface{}{"id": a.owner.Id, "role": "user", "nickname": "Taken"})
	if owner := a.users.GetUserAllInfoById(strconv.Itoa(a.owner.Id)); owner.Nickname == "Taken" || owner.Role != "admin" {
		t.Fatalf("the owner after another account saved: %+v", owner)
	}
}

func TestAdminCannotDeleteSelfOrAdmin(t *testing.T) {
	a := newAccounts(t)
	a.appManagement(t, 200, nil)
	other := a.users.CreateUser(model2.UserDBModel{Username: "second", Password: encryption.HashPassword(ownerPassword), Role: "admin"})

	a.c.expect(409, 409, "DELETE", "/v1/users/"+strconv.Itoa(a.owner.Id), a.access, nil)
	a.c.expect(409, 409, "DELETE", "/v1/users/"+strconv.Itoa(other.Id), a.access, nil)
	a.c.expect(404, 10006, "DELETE", "/v1/users/9999", a.access, nil)
	if got := a.users.GetUserCount(); got != 2 {
		t.Fatalf("accounts: %d, want 2", got)
	}
}

func TestDeletedAccountSessionsAreRefused(t *testing.T) {
	a := newAccounts(t)
	a.appManagement(t, 200, nil)
	id, access, refresh := a.createUser(t, "marie")

	a.c.expect(200, 200, "DELETE", "/v1/users/"+strconv.Itoa(id), a.access, nil)

	if status, _ := refreshStatus(a.c, refresh); status != http.StatusUnauthorized {
		t.Fatalf("a refresh token of the deleted account: %d, want 401", status)
	}
	// an access token of the account is refused too
	a.c.expect(401, 0, "POST", "/v1/users", access, map[string]string{"username": "eve", "password": "a long enough one"})
	a.c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "owner", "password": ownerPassword})
	a.c.expect(400, 10006, "POST", "/v1/users/login", "", map[string]string{"username": "marie", "password": "a long enough one"})
}

func TestRecreatedAccountDoesNotInheritSessions(t *testing.T) {
	a := newAccounts(t)
	a.appManagement(t, 200, nil)
	id, _, old := a.createUser(t, "marie")
	a.c.expect(200, 200, "DELETE", "/v1/users/"+strconv.Itoa(id), a.access, nil)

	again, _, fresh := a.createUser(t, "marie")
	if again == id {
		t.Fatalf("a number was given twice (%d, %d)", again, id)
	}
	if status, _ := refreshStatus(a.c, old); status != http.StatusUnauthorized {
		t.Fatalf("the token of the account that was there before: %d, want 401", status)
	}
	if status, _ := refreshStatus(a.c, fresh); status != http.StatusOK {
		t.Fatalf("the session of the new account: %d, want 200", status)
	}
}

func TestRoleRouteIsInternalOnly(t *testing.T) {
	a := newAccounts(t)
	id, access, _ := a.createUser(t, "marie")
	path := "/v1/users/role/"

	a.c.expect(403, 10011, "GET", path+strconv.Itoa(a.owner.Id), a.access, nil) // not even the owner's own token
	a.c.expect(403, 10011, "GET", path+strconv.Itoa(id), access, nil)
	if status, _ := a.c.do("GET", path+strconv.Itoa(id), "", nil); status != http.StatusUnauthorized {
		t.Fatalf("no token: %d, want 401", status)
	}
	// the right secret from an address that is not loopback is a stranger
	if status, _ := a.c.do("GET", path+strconv.Itoa(id), external.InternalAuthorization(a.runtime), nil); status != http.StatusUnauthorized {
		t.Fatalf("the secret off loopback: %d, want 401", status)
	}

	in, secret := a.internal()
	if data, status := in.raw("GET", path+strconv.Itoa(a.owner.Id), secret); status != 200 || data != "admin" {
		t.Fatalf("the owner: %d %q", status, data)
	}
	if data, status := in.raw("GET", path+strconv.Itoa(id), secret); status != 200 || data != "user" {
		t.Fatalf("marie: %d %q", status, data)
	}
	if _, status := in.raw("GET", path+"9999", secret); status != 404 {
		t.Fatalf("a missing account: %d, want 404", status)
	}
	if _, status := in.raw("GET", path+"abc", secret); status != 404 {
		t.Fatalf("a bad id: %d, want 404", status)
	}
}

// The other services tell a missing account from an older user-service by this body: a 404
// whose success is USER_NOT_EXIST.
func TestRoleRouteSaysAMissingAccountInItsOwnWords(t *testing.T) {
	a := newAccounts(t)
	in, secret := a.internal()
	for _, id := range []string{"9999", "abc"} {
		status, res := in.do("GET", "/v1/users/role/"+id, secret, nil)
		if status != http.StatusNotFound || res.Success != common_err.USER_NOT_EXIST {
			t.Fatalf("%s: %d/%d, want 404/%d", id, status, res.Success, common_err.USER_NOT_EXIST)
		}
	}
}

// A database that cannot be read is no answer: the role route says 500, never "no such account",
// which the other services would take for a deleted account.
func TestRoleRouteSaysAFailedReadIsAnError(t *testing.T) {
	_, c, db := newRigDB(t)
	runtime := t.TempDir()
	if err := external.WriteInternalSecret(runtime); err != nil {
		t.Fatal(err)
	}
	previous := config.CommonInfo.RuntimePath
	config.CommonInfo.RuntimePath = runtime
	t.Cleanup(func() { config.CommonInfo.RuntimePath = previous })
	sqlDB, _ := db.DB()
	sqlDB.Close()

	in := client{t: c.t, h: c.h, ip: "127.0.0.1"}
	status, res := in.do("GET", "/v1/users/role/1", external.InternalAuthorization(runtime), nil)
	if status != http.StatusInternalServerError || res.Success == common_err.USER_NOT_EXIST {
		t.Fatalf("a closed database: %d/%d, want 500", status, res.Success)
	}
}

// The login page is the box's, not an account's: only the admin changes it.
func TestOnlyTheAdminChangesTheLoginStyle(t *testing.T) {
	a := newAccounts(t)
	_, access, _ := a.createUser(t, "marie")

	a.c.expect(403, 10011, "PUT", "/v1/users/login-style", access, map[string]string{"style": "beta"})
	if got := a.c.expect(200, 200, "GET", "/v1/users/status", "", nil)["login_style"]; got != "classic" {
		t.Fatalf("after a user's PUT: %v", got)
	}
	a.c.expect(200, 200, "PUT", "/v1/users/login-style", a.access, map[string]string{"style": "beta"})
}

// raw is do for a route whose data is a plain string.
func (c client) raw(method, path, token string) (string, int) {
	c.t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("X-Real-IP", c.ip)
	req.Header.Set("Authorization", token)
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	var res struct {
		Data string `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	return res.Data, rec.Code
}

func TestEmptyRoleBecomesAdminAtStart(t *testing.T) {
	users, _ := newRig(t)
	legacy := users.CreateUser(model2.UserDBModel{Username: "old", Password: "x"})
	user := users.CreateUser(model2.UserDBModel{Username: "marie", Password: "x", Role: "user"})

	users.NormaliseRoles()

	if got := users.GetUserAllInfoById(strconv.Itoa(legacy.Id)).Role; got != "admin" {
		t.Fatalf("an account of before roles: %q, want admin", got)
	}
	if got := users.GetUserAllInfoById(strconv.Itoa(user.Id)).Role; got != "user" {
		t.Fatalf("a user: %q, want user", got)
	}
}

func TestDeleteAccountThenTellsAppManagement(t *testing.T) {
	a := newAccounts(t)
	id, _, _ := a.createUser(t, "marie")
	path := "/v1/users/" + strconv.Itoa(id)
	dir := ownFolder(t, id)

	// nobody there: the account is gone all the same, and the answer says what was not cleaned
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	a.writeAddress(t, dead.URL)
	a.c.expect(502, 502, "DELETE", path, a.access, nil)
	if a.users.GetUserAllInfoById(strconv.Itoa(id)).Id != 0 {
		t.Fatal("the account is still there")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the folder: %v", err)
	}

	// a yes: asked with the box's secret, once the account is gone
	id, _, _ = a.createUser(t, "paul")
	path = "/v1/users/" + strconv.Itoa(id)
	var mu sync.Mutex
	var method, route, auth string
	var gone bool
	a.appManagement(t, http.StatusNoContent, func(r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		method, route, auth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		gone = a.users.GetUserAllInfoById(strconv.Itoa(id)).Id == 0
	})
	a.c.expect(200, 200, "DELETE", path, a.access, nil)
	mu.Lock()
	defer mu.Unlock()
	if method != "DELETE" || route != "/v2/app_management/visibility/accounts/"+strconv.Itoa(id) || auth != external.InternalAuthorization(a.runtime) || auth == "" {
		t.Fatalf("AppManagement was asked %s %s with %q", method, route, auth)
	}
	if !gone {
		t.Fatal("AppManagement was told before the account was deleted")
	}
}

// The other services know an account by its number only: a number is never given twice, even
// once the highest account is gone and the service has started again.
func TestAnAccountNumberIsNeverGivenTwice(t *testing.T) {
	a := newAccounts(t)
	a.appManagement(t, 200, nil)
	id, old, _ := a.createUser(t, "marie")
	a.c.expect(200, 200, "DELETE", "/v1/users/"+strconv.Itoa(id), a.access, nil)

	again, _, _ := a.createUser(t, "paul")
	if again == id {
		t.Fatalf("the next account got the number of the deleted one (%d)", id)
	}
	if status, _ := a.c.do("GET", "/v1/users/current", old, nil); status != http.StatusUnauthorized {
		t.Fatalf("the token of the deleted account: %d, want 401", status)
	}

	// the service starts again on the same database, after the highest account is gone
	a.c.expect(200, 200, "DELETE", "/v1/users/"+strconv.Itoa(again), a.access, nil)
	restarted := service.NewUserService(a.db, filepath.Join(t.TempDir(), "user-service.key"))
	next := restarted.CreateUser(model2.UserDBModel{Username: "lea", Password: "x", Role: "user"})
	if next.Id == 0 || next.Id == id || next.Id == again {
		t.Fatalf("after a restart: number %d (gone: %d, %d)", next.Id, id, again)
	}
}

// A database of before the counter: the next number is past the highest one there.
func TestTheCounterStartsPastTheAccountsAlreadyThere(t *testing.T) {
	users, _, db := newRigDB(t)
	if err := db.Create(&model2.UserDBModel{Id: 7, Username: "old", Role: "admin"}).Error; err != nil {
		t.Fatal(err)
	}
	if got := users.CreateUser(model2.UserDBModel{Username: "new", Role: "user"}).Id; got != 8 {
		t.Fatalf("number %d, want 8", got)
	}
}

// list reads GET /v1/users as the owner.
func (a accounts) list(t *testing.T) []map[string]interface{} {
	t.Helper()
	req := httptest.NewRequest("GET", "/v1/users", nil)
	req.Header.Set("X-Real-IP", "10.0.0.1")
	req.Header.Set("Authorization", a.access)
	rec := httptest.NewRecorder()
	a.c.h.ServeHTTP(rec, req)
	var res struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	return res.Data
}

// a database of before the counter may hold a number given twice: an access token of the
// account that is gone must not act as the one there now (it lives for hours)
func TestDeletedAccountAccessTokenDoesNotActAsTheNextAccountWithTheSameId(t *testing.T) {
	a := newAccounts(t)
	a.appManagement(t, 200, nil)
	id, old, _ := a.createUser(t, "marie")
	a.c.expect(200, 200, "GET", "/v1/users/current", old, nil)
	a.c.expect(200, 200, "DELETE", "/v1/users/"+strconv.Itoa(id), a.access, nil)
	if status, _ := a.c.do("GET", "/v1/users/current", old, nil); status != http.StatusUnauthorized {
		t.Fatalf("the token of an account that is gone: %d, want 401", status)
	}

	time.Sleep(1100 * time.Millisecond) // tokens are dated to the second
	if err := a.db.Create(&model2.UserDBModel{Id: id, Username: "paul", Password: encryption.HashPassword("a long enough one"), Role: "user", SessionVersion: 1}).Error; err != nil {
		t.Fatal(err)
	}
	fresh, _ := tokens(t, a.c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "paul", "password": "a long enough one"}))
	if status, _ := a.c.do("GET", "/v1/users/current", old, nil); status != http.StatusUnauthorized {
		t.Fatalf("the old token, now that its number is paul's: %d, want 401", status)
	}
	a.c.expect(200, 200, "GET", "/v1/users/current", fresh, nil)
}

// The login name of a user is the owner's to choose: a user saves the other fields only.
func TestAUserCannotRenameItself(t *testing.T) {
	a := newAccounts(t)
	id, access, _ := a.createUser(t, "marie")
	a.c.expect(403, 10011, "PUT", "/v1/users/current", access, map[string]string{"username": "queen", "nickname": "Q"})
	a.c.expect(200, 200, "PUT", "/v1/users/current", access, map[string]string{"username": "marie", "nickname": "Marie"})
	if got := a.users.GetUserAllInfoById(strconv.Itoa(id)); got.Username != "marie" || got.Nickname != "Marie" {
		t.Fatalf("after the saves: %q %q", got.Username, got.Nickname)
	}
}

func TestEditingTheProfileKeepsTheSession(t *testing.T) {
	a := newAccounts(t)
	a.c.expect(200, 200, "PUT", "/v1/users/current", a.access, map[string]string{"username": "renamed", "nickname": "Boss"})
	a.c.expect(200, 200, "GET", "/v1/users/current", a.access, nil)
	a.c.expect(200, 200, "POST", "/v1/users", a.access, map[string]string{"username": "marie", "password": "a long enough one"})
}

func TestAccountFolderIsRemovedWithTheAccountAndNotInherited(t *testing.T) {
	a := newAccounts(t)
	a.appManagement(t, 200, nil)
	id, _, _ := a.createUser(t, "marie")
	dir := filepath.Join(config.AppInfo.UserDataPath, strconv.Itoa(id))
	if err := os.WriteFile(filepath.Join(dir, "avatar"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	a.c.expect(200, 200, "DELETE", "/v1/users/"+strconv.Itoa(id), a.access, nil)
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the folder of the deleted account: %v", err)
	}

	// a leftover under the number the next account gets
	dir = filepath.Join(config.AppInfo.UserDataPath, strconv.Itoa(id+1))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "old"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if again, _, _ := a.createUser(t, "paul"); again != id+1 {
		t.Fatalf("the next account is %d, want %d", again, id+1)
	}
	if _, err := os.Stat(filepath.Join(dir, "old")); !os.IsNotExist(err) {
		t.Fatalf("the new account inherited a file: %v", err)
	}
}
