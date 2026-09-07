package service

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/inkly/CasaOS-Common/utils/logger"
	"github.com/inkly/CasaOS-UserService/service/model"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

func TestVerifyTOTP(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "CasaOS", AccountName: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	secret := key.Secret()
	now := time.Unix(1700000000, 0)
	cur := now.Unix() / totpPeriod
	code := func(offset int) string {
		c, err := totp.GenerateCode(secret, now.Add(time.Duration(offset)*totpPeriod*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	wrong := "000000"
	if wrong == code(-1) || wrong == code(0) || wrong == code(1) {
		wrong = "000001"
	}

	for _, tc := range []struct {
		name     string
		code     string
		lastStep int64
		wantStep int64
		wantOK   bool
	}{
		{"current step", code(0), 0, cur, true},
		{"one step behind", code(-1), 0, cur - 1, true},
		{"one step ahead", code(1), 0, cur + 1, true},
		{"two steps behind", code(-2), 0, 0, false},
		{"two steps ahead", code(2), 0, 0, false},
		{"replay of the last accepted step", code(0), cur, 0, false},
		{"older than the last accepted step", code(-1), cur, 0, false},
		{"next step after the last accepted one", code(1), cur, cur + 1, true},
		{"wrong code", wrong, 0, 0, false},
		{"wrong length", "12345", 0, 0, false},
		{"empty", "", 0, 0, false},
	} {
		step, ok := VerifyTOTP(secret, tc.code, tc.lastStep, now)
		if ok != tc.wantOK || step != tc.wantStep {
			t.Errorf("%s: got (%d, %v), want (%d, %v)", tc.name, step, ok, tc.wantStep, tc.wantOK)
		}
	}
}

func TestRecoveryCodes(t *testing.T) {
	plain, hashes, err := NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 8 || len(hashes) != 8 {
		t.Fatalf("got %d codes and %d hashes, want 8 and 8", len(plain), len(hashes))
	}
	shape := regexp.MustCompile(`^[a-z2-7]{5}-[a-z2-7]{5}$`)
	seen := map[string]bool{}
	for _, c := range plain {
		if !shape.MatchString(c) || seen[c] {
			t.Fatalf("bad or duplicate code %q", c)
		}
		seen[c] = true
	}

	remaining, ok := ConsumeRecoveryCode(hashes, " "+strings.ToUpper(plain[3])+" ")
	if !ok || len(remaining) != 7 {
		t.Fatalf("upper-cased code with spaces: ok=%v remaining=%d", ok, len(remaining))
	}
	if _, ok := ConsumeRecoveryCode(remaining, plain[3]); ok {
		t.Fatal("a consumed code was accepted again")
	}
	remaining, ok = ConsumeRecoveryCode(remaining, strings.ReplaceAll(plain[0], "-", ""))
	if !ok || len(remaining) != 6 {
		t.Fatalf("code without hyphen: ok=%v remaining=%d", ok, len(remaining))
	}
	if _, ok := ConsumeRecoveryCode(remaining, "zzzzz-zzzzz"); ok {
		t.Fatal("an unknown code was accepted")
	}
	if len(hashes) != 8 {
		t.Fatal("the original list was modified")
	}
}

// TestCompareAndSetFailsClosed: on a database that cannot execute the write,
// every compare-and-set refuses (and logs) rather than reading as accepted.
func TestCompareAndSetFailsClosed(t *testing.T) {
	logger.LogInitConsoleOnly()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.UserDBModel{}); err != nil {
		t.Fatal(err)
	}
	plain, hashes, err := NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	u := NewUserService(db)
	user := u.CreateUser(model.UserDBModel{Username: "erin", TotpSecret: "S", TotpEnabled: true, RecoveryCodes: hashes})
	sqlDB, _ := db.DB()
	sqlDB.Close()
	if u.ConsumeTOTPStep(user.Id, 1) || u.UseRecoveryCode(user.Id, plain[0]) || u.EnableUserTOTP(user.Id, "S", 1, hashes) || u.ClearPendingTOTP(user.Id, "S") {
		t.Fatal("a failing database must refuse, not accept")
	}
}
