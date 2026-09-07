package sqlite

import (
	"reflect"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	model2 "github.com/inkly/CasaOS-UserService/service/model"
	"gorm.io/gorm"
)

// oldUser is o_users as every installation before 2FA created it.
type oldUser struct {
	Id          int `gorm:"column:id;primary_key"`
	Username    string
	Password    string
	Role        string
	Email       string
	Nickname    string
	Avatar      string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (oldUser) TableName() string { return "o_users" }

func TestAutoMigrateKeepsExistingUser(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1) // one connection, or every connection gets its own :memory: database

	if err := db.AutoMigrate(&oldUser{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&oldUser{Username: "admin", Password: "5f4dcc3b5aa765d61d8327deb882cf99", Role: "admin"}).Error; err != nil {
		t.Fatal(err)
	}

	if err := db.AutoMigrate(model2.UserDBModel{}); err != nil {
		t.Fatal(err)
	}

	var u model2.UserDBModel
	if err := db.First(&u).Error; err != nil {
		t.Fatal(err)
	}
	if u.Username != "admin" || u.Password != "5f4dcc3b5aa765d61d8327deb882cf99" {
		t.Fatalf("old columns lost: %+v", u)
	}
	if u.TotpEnabled || u.TotpSecret != "" || u.TotpLastStep != 0 || len(u.RecoveryCodes) != 0 {
		t.Fatalf("new columns not zero for the migrated row: %+v", u)
	}

	// The new columns round-trip, including the JSON-serialised list and the
	// zero values a disable must write.
	want := model2.UserDBModel{Id: u.Id, TotpSecret: "SEED", TotpEnabled: true, TotpLastStep: 42, RecoveryCodes: []string{"h1", "h2"}}
	cols := []string{"totp_secret", "totp_enabled", "totp_last_step", "recovery_codes"}
	if err := db.Model(&want).Select(cols).Updates(&want).Error; err != nil {
		t.Fatal(err)
	}
	var got model2.UserDBModel
	db.First(&got, u.Id)
	if got.TotpSecret != "SEED" || !got.TotpEnabled || got.TotpLastStep != 42 || !reflect.DeepEqual(got.RecoveryCodes, []string{"h1", "h2"}) {
		t.Fatalf("round-trip failed: %+v", got)
	}
	off := model2.UserDBModel{Id: u.Id}
	if err := db.Model(&off).Select(cols).Updates(&off).Error; err != nil {
		t.Fatal(err)
	}
	db.First(&got, u.Id)
	if got.TotpSecret != "" || got.TotpEnabled || got.TotpLastStep != 0 || len(got.RecoveryCodes) != 0 {
		t.Fatalf("zero values were not written: %+v", got)
	}
}
