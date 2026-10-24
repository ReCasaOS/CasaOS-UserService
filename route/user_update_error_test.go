package route_test

import (
	"path/filepath"
	"testing"

	"github.com/ReCasaOS/CasaOS-UserService/service"
	model2 "github.com/ReCasaOS/CasaOS-UserService/service/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// -ru prints a new password only when it was stored: the writes say when they were not
func TestPasswordAndTOTPWritesReportTheirErrors(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model2.UserDBModel{}); err != nil {
		t.Fatal(err)
	}
	users := service.NewUserService(db, filepath.Join(t.TempDir(), "user-service.key"))
	user := users.CreateUser(model2.UserDBModel{Username: "owner", Password: "x", Role: "admin"})
	if err := users.UpdateUserPassword(user); err != nil {
		t.Fatalf("a write that goes through: %v", err)
	}
	sqlDB, _ := db.DB()
	_ = sqlDB.Close() // as a database the running service holds locked, for the writes
	if err := users.UpdateUserPassword(user); err == nil {
		t.Error("UpdateUserPassword: nil on a write that failed")
	}
	if err := users.UpdateUserTOTP(user); err == nil {
		t.Error("UpdateUserTOTP: nil on a write that failed")
	}
	if err := users.ResetUserCredentials(user); err == nil {
		t.Error("ResetUserCredentials: nil on a write that failed")
	}
}

// -ru: the new password and 2FA off in one UPDATE: both, or neither
func TestResetUserCredentialsWritesBoth(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model2.UserDBModel{}); err != nil {
		t.Fatal(err)
	}
	users := service.NewUserService(db, filepath.Join(t.TempDir(), "user-service.key"))
	user := users.CreateUser(model2.UserDBModel{Username: "owner", Password: "old", Role: "admin", TotpSecret: "S", TotpEnabled: true, TotpLastStep: 7, RecoveryCodes: []string{"h"}})
	user.Password, user.TotpSecret, user.TotpEnabled, user.TotpLastStep, user.RecoveryCodes = "new", "", false, 0, nil
	if err := users.ResetUserCredentials(user); err != nil {
		t.Fatal(err)
	}
	got := users.GetUserAllInfoByName("owner")
	if got.Password != "new" || got.TotpSecret != "" || got.TotpEnabled || got.TotpLastStep != 0 || len(got.RecoveryCodes) != 0 {
		t.Errorf("after the reset: %+v", got)
	}
}
