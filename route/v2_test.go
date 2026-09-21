package route_test

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/CasaOS-UserService/model"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/config"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/utils/encryption"
	"github.com/ReCasaOS/CasaOS-UserService/route"
	"github.com/ReCasaOS/CasaOS-UserService/service"
	model2 "github.com/ReCasaOS/CasaOS-UserService/service/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// eventsRepo is the rig's repository with a real event store, so a request
// that clears both middlewares reaches its handler.
type eventsRepo struct {
	fakeRepo
	events service.EventService
}

func (r eventsRepo) Event() service.EventService { return r.events }

// TestV2AuthThenValidation pins the v2 middleware chain: the JWT check runs
// before the OpenAPI validator, the validator still resolves routes and
// checks parameters against the spec, and a valid request, from the user or
// from one of this box's services (loopback plus the internal secret), gets
// through both to its handler. Only the handler answers 200.
func TestV2AuthThenValidation(t *testing.T) {
	users, c := newRig(t)
	users.CreateUser(model2.UserDBModel{Username: "admin", Password: encryption.GetMD5ByStr("pw"), Role: "admin"})
	access, _ := tokens(t, c.expect(200, 200, "POST", "/v1/users/login", "", map[string]string{"username": "admin", "password": "pw"}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.EventModel{}); err != nil {
		t.Fatal(err)
	}
	service.MyService = eventsRepo{fakeRepo{user: users}, service.NewEventService(db)}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, external.InternalSecretFilename), []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer func(old string) { config.CommonInfo.RuntimePath = old }(config.CommonInfo.RuntimePath)
	config.CommonInfo.RuntimePath = dir

	const lan, loopback, secret = "10.0.0.1:1234", "127.0.0.1:1234", "Internal s3cret"
	h := route.InitV2Router()
	for i, tc := range []struct {
		from, path, auth string
		want             int
	}{
		{lan, "/v2/users/nope", "", 401},                                      // the validator would say 400: auth runs first
		{lan, "/v2/users/events?form=yesterday", "", 401},                     // same with a known route
		{lan, "/v2/users/nope", access, 400},                                  // unknown route
		{lan, "/v2/users/events?form=yesterday", access, 400},                 // form is not a date-time
		{lan, "/v2/users/events?form=2021-01-01T00:00:00Z", access, 200},      // the user: valid, reaches the handler
		{lan, "/v2/users/events", secret, 401},                                // the secret counts from loopback only
		{loopback, "/v2/users/events", "", 401},                               // loopback alone is not trusted
		{loopback, "/v2/users/events?form=2021-01-01T00:00:00Z", secret, 200}, // a service: valid, reaches the handler
	} {
		req := httptest.NewRequest("GET", tc.path, nil)
		req.RemoteAddr = tc.from
		if tc.auth != "" {
			req.Header.Set("Authorization", tc.auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("case %d, GET %s from %s: got %d, want %d", i, tc.path, tc.from, rec.Code, tc.want)
		}
	}
}
