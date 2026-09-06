package route_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IceWhaleTech/CasaOS-Common/external"
	"github.com/IceWhaleTech/CasaOS-UserService/codegen/message_bus"
	"github.com/IceWhaleTech/CasaOS-UserService/pkg/utils/encryption"
	"github.com/IceWhaleTech/CasaOS-UserService/route"
	v1 "github.com/IceWhaleTech/CasaOS-UserService/route/v1"
	"github.com/IceWhaleTech/CasaOS-UserService/service"
	model2 "github.com/IceWhaleTech/CasaOS-UserService/service/model"
	"github.com/glebarez/sqlite"
	"github.com/pquerna/otp/totp"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
)

// fakeRepo wires the real user service on an in-memory database; the other
// services are never touched by the routes under test.
type fakeRepo struct{ user service.UserService }

func (f fakeRepo) User() service.UserService                  { return f.user }
func (fakeRepo) Gateway() external.ManagementService          { return nil }
func (fakeRepo) MessageBus() *message_bus.ClientWithResponses { return nil }
func (fakeRepo) Event() service.EventService                  { return nil }

type result struct {
	Success int                    `json:"success"`
	Data    map[string]interface{} `json:"data"`
}

type client struct {
	t *testing.T
	h http.Handler
}

// do sends a JSON request from a non-loopback address (the JWT middleware
// skips auth for 127.0.0.1) with the raw token in Authorization, as the
// dashboard does.
func (c client) do(method, path, token string, body interface{}) (int, result) {
	c.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			c.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "10.0.0.1")
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	var res result
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	return rec.Code, res
}

// expect asserts the HTTP status and the envelope code, and returns data.
func (c client) expect(status, success int, method, path, token string, body interface{}) map[string]interface{} {
	c.t.Helper()
	gotStatus, res := c.do(method, path, token, body)
	if gotStatus != status || res.Success != success {
		c.t.Fatalf("%s %s: got %d/%d, want %d/%d", method, path, gotStatus, res.Success, status, success)
	}
	return res.Data
}

func tokens(t *testing.T, data map[string]interface{}) (access, refresh string) {
	t.Helper()
	tok, _ := data["token"].(map[string]interface{})
	access, _ = tok["access_token"].(string)
	refresh, _ = tok["refresh_token"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("no tokens in %v", data)
	}
	return access, refresh
}

func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func wrongCode(t *testing.T, secret string) string {
	t.Helper()
	for _, c := range []string{"000000", "000001"} {
		if _, ok := service.VerifyTOTP(secret, c, 0, time.Now()); !ok {
			return c
		}
	}
	t.Fatal("no wrong code found")
	return ""
}

// newRig wires the real router and user service on a fresh in-memory
// database, with both login budgets lifted: the service-wide one (5/min)
// would stop a flow at its sixth login-class request, the per-user one
// (5/min, right or wrong) at the sixth factor check. Tests that exercise a
// budget restore it themselves. User ids restart at 1 in every rig while
// the per-user limiters are process-wide, so a limiter created under a
// real rate in one test is inherited by the same id in the next.
func newRig(t *testing.T) (service.UserService, client) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model2.UserDBModel{}); err != nil {
		t.Fatal(err)
	}
	users := service.NewUserService(db)
	service.MyService = fakeRepo{user: users}
	v1.LoginLimiter.SetLimit(rate.Inf)
	v1.UserLimit = rate.Inf
	return users, client{t: t, h: route.InitRouter()}
}

func TestTwoFactorFlow(t *testing.T) {
	users, c := newRig(t)

	const password = "correct horse"
	users.CreateUser(model2.UserDBModel{Username: "admin", Password: encryption.GetMD5ByStr(password), Role: "admin"})
	login := func() map[string]interface{} {
		t.Helper()
		return c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "admin", "password": password})
	}
	loginPreAuth := func() string {
		t.Helper()
		data := c.expect(200, 10014, "POST", "/v1/users/login", "", map[string]string{"username": "admin", "password": password})
		if _, leaked := data["token"]; leaked {
			t.Fatal("login with 2FA on must not issue tokens")
		}
		pre, _ := data["pre_auth_token"].(string)
		if pre == "" || data["expires_at"] == nil {
			t.Fatalf("no pre-auth token in %v", data)
		}
		return pre
	}

	// 2FA off: login is unchanged.
	data := login()
	access, refresh := tokens(t, data)
	if data["user"].(map[string]interface{})["totp_enabled"] != false {
		t.Fatalf("totp_enabled should be false: %v", data["user"])
	}

	// Enrol: setup needs the password on top of the session and returns the
	// secret; enable needs a code from an authenticator.
	c.expect(400, 10017, "POST", "/v1/users/2fa/enable", access, map[string]string{"code": "000000"}) // nothing pending yet; no limiter cost
	c.expect(400, 4000, "POST", "/v1/users/2fa/setup", access, nil)
	c.expect(400, 10015, "POST", "/v1/users/2fa/setup", access, map[string]string{"password": "wrong"})
	setup := c.expect(200, 200, "POST", "/v1/users/2fa/setup", access, map[string]string{"password": password})
	secret, _ := setup["secret"].(string)
	// A password login clears a pending secret: an abandoned setup leaves nothing behind.
	login()
	c.expect(400, 10017, "POST", "/v1/users/2fa/enable", access, map[string]string{"code": codeAt(t, secret, time.Now())})
	setup = c.expect(200, 200, "POST", "/v1/users/2fa/setup", access, map[string]string{"password": password})
	secret, _ = setup["secret"].(string)
	if secret == "" || !strings.HasPrefix(setup["otpauth_url"].(string), "otpauth://totp/CasaOS:admin?") {
		t.Fatalf("bad setup response: %v", setup)
	}
	enabled := c.expect(200, 200, "POST", "/v1/users/2fa/enable", access, map[string]string{"code": codeAt(t, secret, time.Now())})
	rawCodes, _ := enabled["recovery_codes"].([]interface{})
	if len(rawCodes) != 8 {
		t.Fatalf("want 8 recovery codes, got %v", enabled)
	}
	shape := regexp.MustCompile(`^[a-z2-7]{5}-[a-z2-7]{5}$`)
	recovery := make([]string, 0, 8)
	for _, r := range rawCodes {
		s, _ := r.(string)
		if !shape.MatchString(s) {
			t.Fatalf("bad recovery code %q", s)
		}
		recovery = append(recovery, s)
	}
	c.expect(400, 10016, "POST", "/v1/users/2fa/setup", access, nil) // an enabled secret is never rotated
	c.expect(400, 10016, "POST", "/v1/users/2fa/enable", access, map[string]string{"code": "000000"})

	// Login now stops at the second factor.
	pre := loginPreAuth()

	// The pre-auth token is nothing else: not an access token, not a refresh token.
	if status, _ := c.do("GET", "/v1/users/current", pre, nil); status != http.StatusUnauthorized {
		t.Fatalf("pre-auth token accepted as access token: %d", status)
	}
	if status, _ := c.do("POST", "/v1/users/refresh", "", map[string]string{"refresh_token": pre}); status != http.StatusUnauthorized {
		t.Fatalf("pre-auth token accepted as refresh token: %d", status)
	}
	// And an access or refresh token is not a pre-auth token.
	valid := codeAt(t, secret, time.Now().Add(30*time.Second)) // next step: the enrolment step is spent
	c.expect(400, 20006, "POST", "/v1/users/2fa/verify", "", map[string]string{"pre_auth_token": access, "code": valid})
	c.expect(400, 20006, "POST", "/v1/users/2fa/verify", "", map[string]string{"pre_auth_token": refresh, "code": valid})
	c.expect(400, 20006, "POST", "/v1/users/2fa/verify", "", map[string]string{"pre_auth_token": "", "code": valid})
	c.expect(400, 4000, "POST", "/v1/users/2fa/verify", "", map[string]string{"pre_auth_token": pre})
	c.expect(400, 4000, "POST", "/v1/users/2fa/verify", "", map[string]string{"pre_auth_token": pre, "code": valid, "recovery_code": recovery[0]})

	// A valid code mints the same body as a login.
	data = c.expect(200, 200, "POST", "/v1/users/2fa/verify", "", map[string]string{"pre_auth_token": pre, "code": valid})
	access2, _ := tokens(t, data)
	user := data["user"].(map[string]interface{})
	if user["totp_enabled"] != true {
		t.Fatalf("totp_enabled should be true: %v", user)
	}
	for _, k := range []string{"password", "totp_secret", "recovery_codes", "totp_last_step"} {
		if _, leaked := user[k]; leaked {
			t.Fatalf("%s leaked in the login body", k)
		}
	}
	me := c.expect(200, 200, "GET", "/v1/users/current", access2, nil)
	if me["totp_enabled"] != true {
		t.Fatalf("GET /current should report totp_enabled: %v", me)
	}

	// The same code is refused a second time.
	pre = loginPreAuth()
	c.expect(400, 10015, "POST", "/v1/users/2fa/verify", "", map[string]string{"pre_auth_token": pre, "code": valid})

	// A recovery code works once, whatever the case, and never twice.
	c.expect(200, 200, "POST", "/v1/users/2fa/verify", "", map[string]string{"pre_auth_token": pre, "recovery_code": strings.ToUpper(recovery[0])})
	c.expect(400, 10015, "POST", "/v1/users/2fa/verify", "", map[string]string{"pre_auth_token": pre, "recovery_code": recovery[0]})

	// Disable needs exactly one factor; the password path is constant-time MD5.
	c.expect(400, 4000, "POST", "/v1/users/2fa/disable", access2, map[string]string{})
	c.expect(400, 4000, "POST", "/v1/users/2fa/disable", access2, map[string]string{"code": valid, "password": password})
	c.expect(400, 10015, "POST", "/v1/users/2fa/disable", access2, map[string]string{"password": "wrong"})
	c.expect(200, 200, "POST", "/v1/users/2fa/disable", access2, map[string]string{"password": password})
	c.expect(400, 10017, "POST", "/v1/users/2fa/disable", access2, map[string]string{"password": password})

	// Off again: login hands out tokens directly and the pending state is gone.
	data = login()
	tokens(t, data)
	if data["user"].(map[string]interface{})["totp_enabled"] != false {
		t.Fatalf("totp_enabled should be false after disable: %v", data["user"])
	}
	c.expect(400, 10017, "POST", "/v1/users/2fa/enable", access2, map[string]string{"code": "000000"})

	// Factor checks are rate-limited per user: the sixth within a minute is 429
	// whether the code is right or wrong, and the budget is shared with the
	// other factor checks of that user. Bob's limiter is created at his first
	// check, so the real rate is restored before it: setup, enable and three
	// wrong codes spend the five tokens.
	v1.UserLimit = rate.Every(time.Minute / 5)
	users.CreateUser(model2.UserDBModel{Username: "bob", Password: encryption.GetMD5ByStr(password), Role: "admin"})
	bobAccess, _ := tokens(t, c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "bob", "password": password}))
	bobSecret, _ := c.expect(200, 200, "POST", "/v1/users/2fa/setup", bobAccess, map[string]string{"password": password})["secret"].(string)
	c.expect(200, 200, "POST", "/v1/users/2fa/enable", bobAccess, map[string]string{"code": codeAt(t, bobSecret, time.Now())}) // second token: setup spent the first
	bobPre, _ := c.expect(200, 10014, "POST", "/v1/users/login", "", map[string]string{"username": "bob", "password": password})["pre_auth_token"].(string)
	wrong := wrongCode(t, bobSecret)
	for i := 0; i < 3; i++ {
		c.expect(400, 10015, "POST", "/v1/users/2fa/verify", "", map[string]string{"pre_auth_token": bobPre, "code": wrong})
	}
	c.expect(429, 10012, "POST", "/v1/users/2fa/verify", "", map[string]string{"pre_auth_token": bobPre, "code": wrong})
	c.expect(429, 10012, "POST", "/v1/users/2fa/verify", "", map[string]string{"pre_auth_token": bobPre, "code": codeAt(t, bobSecret, time.Now().Add(30*time.Second))})
	c.expect(429, 10012, "POST", "/v1/users/2fa/disable", bobAccess, map[string]string{"password": password})
	// The admin is not affected by the limiter of another user.
	login()
}

// TestReplayRace fires the same code twice at once and checks that the
// persistence layer lets exactly one request through: the replay guard is
// a conditional UPDATE, not a read-check-write in the handler.
func TestReplayRace(t *testing.T) {
	users, c := newRig(t)
	const password = "correct horse"
	user := users.CreateUser(model2.UserDBModel{Username: "alice", Password: encryption.GetMD5ByStr(password), Role: "admin"})
	access, _ := tokens(t, c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "alice", "password": password}))
	secret, _ := c.expect(200, 200, "POST", "/v1/users/2fa/setup", access, map[string]string{"password": password})["secret"].(string)
	enabled := c.expect(200, 200, "POST", "/v1/users/2fa/enable", access, map[string]string{"code": codeAt(t, secret, time.Now())})
	recovery, _ := enabled["recovery_codes"].([]interface{})[0].(string)
	pre, _ := c.expect(200, 10014, "POST", "/v1/users/login", "", map[string]string{"username": "alice", "password": password})["pre_auth_token"].(string)

	// race sends body from n goroutines released together and counts the 200s.
	race := func(n int, body map[string]string) (okCount, invalidCount int) {
		t.Helper()
		var mu sync.Mutex
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				status, res := c.do("POST", "/v1/users/2fa/verify", "", body)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case status == 200 && res.Success == 200:
					okCount++
				case status == 400 && res.Success == 10015:
					invalidCount++
				default:
					t.Errorf("unexpected %d/%d", status, res.Success)
				}
			}()
		}
		close(start)
		wg.Wait()
		return
	}

	code := codeAt(t, secret, time.Now().Add(30*time.Second)) // the enrolment step is spent
	if ok, bad := race(4, map[string]string{"pre_auth_token": pre, "code": code}); ok != 1 || bad != 3 {
		t.Fatalf("TOTP code accepted %d times (%d refused), want exactly once", ok, bad)
	}
	if ok, bad := race(4, map[string]string{"pre_auth_token": pre, "recovery_code": recovery}); ok != 1 || bad != 3 {
		t.Fatalf("recovery code accepted %d times (%d refused), want exactly once", ok, bad)
	}

	// The same guarantee, sequentially, at the service layer the handler relies on.
	step := time.Now().Unix()/30 + 2
	if !users.ConsumeTOTPStep(user.Id, step) || users.ConsumeTOTPStep(user.Id, step) || users.ConsumeTOTPStep(user.Id, step-1) {
		t.Fatal("ConsumeTOTPStep must accept a step once and never an older one")
	}
	other, _ := enabled["recovery_codes"].([]interface{})[1].(string)
	if !users.UseRecoveryCode(user.Id, other) || users.UseRecoveryCode(user.Id, other) || users.UseRecoveryCode(user.Id, recovery) {
		t.Fatal("UseRecoveryCode must consume a code once")
	}
	if got := len(users.GetUserAllInfoById(strconv.Itoa(user.Id)).RecoveryCodes); got != 6 {
		t.Fatalf("want 6 recovery codes left, got %d", got)
	}
}
