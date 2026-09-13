/*
 * @Author: LinkLeong link@icewhale.com
 * @Date: 2022-03-18 11:40:55
 * @LastEditors: LinkLeong
 * @LastEditTime: 2022-07-12 10:05:37
 * @Description:
 * @Website: https://www.casaos.io
 * Copyright (c) 2022 by icewhale, All Rights Reserved.
 */
package service

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"os"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/utils/jwt"
	"github.com/ReCasaOS/CasaOS-Common/utils/logger"
	"github.com/ReCasaOS/CasaOS-UserService/service/model"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type UserService interface {
	UpLoadFile(file multipart.File, name string) error
	CreateUser(m model.UserDBModel) model.UserDBModel
	GetUserCount() (userCount int64)
	UpdateUser(m model.UserDBModel)
	UpdateUserPassword(m model.UserDBModel)
	GetUserInfoById(id string) (m model.UserDBModel)
	GetUserAllInfoById(id string) (m model.UserDBModel)
	GetUserAllInfoByName(userName string) (m model.UserDBModel)
	DeleteUserById(id string)
	DeleteAllUser()
	GetUserInfoByUserName(userName string) (m model.UserDBModel)
	GetAllUserName() (list []model.UserDBModel)
	UpdateUserTOTP(m model.UserDBModel)
	EnableUserTOTP(id int, secret string, step int64, hashes []string) bool
	ClearPendingTOTP(id int, secret string) bool
	SetPendingTOTP(id int, secret string) bool
	DisableUserTOTP(id int, secret string) bool
	ConsumeTOTPStep(id int, step int64) bool
	UseRecoveryCode(id int, code string) bool

	GetKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey)
	IssuePreAuthToken(m model.UserDBModel) (string, error)
	ParsePreAuthToken(token string) (*jwt.Claims, error)
}

var UserRegisterHash = make(map[string]string)

type userService struct {
	privateKey *ecdsa.PrivateKey // keep this private - NEVER expose it!!!
	publicKey  *ecdsa.PublicKey

	// preAuthPriv signs the token /login hands out between the password and
	// the second factor. It is never published in the JWKS, so nothing else
	// accepts that token as an access token.
	preAuthPriv *ecdsa.PrivateKey
	preAuthPub  *ecdsa.PublicKey

	db *gorm.DB
}

func (u *userService) DeleteAllUser() {
	u.db.Where("1=1").Delete(&model.UserDBModel{})
}

func (u *userService) DeleteUserById(id string) {
	u.db.Where("id= ?", id).Delete(&model.UserDBModel{})
}

func (u *userService) GetAllUserName() (list []model.UserDBModel) {
	u.db.Select("username").Find(&list)
	return
}

func (u *userService) CreateUser(m model.UserDBModel) model.UserDBModel {
	u.db.Create(&m)
	return m
}

func (u *userService) GetUserCount() (userCount int64) {
	u.db.Find(&model.UserDBModel{}).Count(&userCount)
	return
}

func (u *userService) UpdateUser(m model.UserDBModel) {
	u.db.Model(&m).Omit("password", "totp_secret", "totp_enabled", "totp_last_step", "recovery_codes").Updates(&m)
}

// UpdateUserTOTP writes the four 2FA columns, zero values included: Updates
// alone skips false/0/"" and could never disable.
func (u *userService) UpdateUserTOTP(m model.UserDBModel) {
	u.db.Model(&m).Select("totp_secret", "totp_enabled", "totp_last_step", "recovery_codes").Updates(&m)
}

// EnableUserTOTP turns the pending secret on, recording the enrolment step
// and the recovery-code hashes, and reports whether it did. The write is
// keyed on the row being still disabled with that very secret, so of two
// enable requests released together exactly one wins and the recovery codes
// it returned are the ones in the row; the loser updates nothing.
func (u *userService) EnableUserTOTP(id int, secret string, step int64, hashes []string) bool {
	return changedOne("enable", u.db.Model(&model.UserDBModel{Id: id}).Select("totp_enabled", "totp_last_step", "recovery_codes").Where("totp_enabled = ? AND totp_secret = ?", false, secret).Updates(&model.UserDBModel{TotpEnabled: true, TotpLastStep: step, RecoveryCodes: hashes}))
}

// ClearPendingTOTP removes a never-enabled secret and reports whether it did.
// The write is keyed on the row being still disabled with the secret as read:
// a login that read the row before /2fa/enable wrote it must not zero an
// enabled 2FA on its way to a full session.
func (u *userService) ClearPendingTOTP(id int, secret string) bool {
	return changedOne("clear pending secret", u.db.Model(&model.UserDBModel{Id: id}).Where("totp_enabled = ? AND totp_secret = ?", false, secret).Update("totp_secret", ""))
}

// SetPendingTOTP stores a fresh, not yet enabled secret and reports whether
// it did. Keyed on the row being still disabled: a setup that read the row
// before /2fa/enable wrote it must not replace an enabled secret with a
// pending one, which would leave the caller of enable with recovery codes
// that exist nowhere.
func (u *userService) SetPendingTOTP(id int, secret string) bool {
	return changedOne("set pending secret", u.db.Model(&model.UserDBModel{Id: id}).Where("totp_enabled = ?", false).Update("totp_secret", secret))
}

// DisableUserTOTP zeroes the four 2FA columns and reports whether it did.
// Keyed on the row being enabled with the secret the factor was checked
// against: a disable that verified against one enrolment cannot turn off a
// later one.
func (u *userService) DisableUserTOTP(id int, secret string) bool {
	return changedOne("disable", u.db.Model(&model.UserDBModel{Id: id}).Select("totp_secret", "totp_enabled", "totp_last_step", "recovery_codes").Where("totp_enabled = ? AND totp_secret = ?", true, secret).Updates(&model.UserDBModel{}))
}

// changedOne reports whether the statement updated exactly one row. A failing
// statement (locked or broken database) is logged and counts as no row: the
// factor is refused, never accepted, on a database that could not record it.
func changedOne(what string, res *gorm.DB) bool {
	if res.Error != nil {
		logger.Error("2fa: "+what+" failed", zap.Error(res.Error))
		return false
	}
	return res.RowsAffected == 1
}

// ConsumeTOTPStep records step as the last accepted one and reports whether
// it was still unused. The replay guard lives here, in one conditional
// UPDATE, so no caller can bypass it: SQLite executes a statement under its
// write lock, so of two requests replaying the same code the second one
// finds the step already recorded and updates no row.
func (u *userService) ConsumeTOTPStep(id int, step int64) bool {
	return changedOne("consume step", u.db.Model(&model.UserDBModel{Id: id}).Where("totp_last_step < ?", step).Update("totp_last_step", step))
}

// UseRecoveryCode removes the hash matching code from the user's list and
// reports whether it did. The write is keyed on the list as it was read (its
// JSON, byte for byte what the serializer stored), so it is the same
// compare-and-set as ConsumeTOTPStep: a code presented twice at once is
// removed once, the loser sees no row updated and is told the code is invalid.
// Only this column is written, so it cannot clobber a concurrent TOTP step.
// ponytail: two *different* codes used in the same instant also lose one;
// the losing code is not consumed, its owner just retries.
func (u *userService) UseRecoveryCode(id int, code string) bool {
	var user model.UserDBModel
	if err := u.db.Where("id = ?", id).First(&user).Error; err != nil {
		logger.Error("2fa: read recovery codes failed", zap.Error(err))
		return false
	}
	remaining, ok := ConsumeRecoveryCode(user.RecoveryCodes, code)
	if !ok {
		return false
	}
	prev, _ := json.Marshal(user.RecoveryCodes)
	return changedOne("use recovery code", u.db.Model(&model.UserDBModel{Id: id}).Select("recovery_codes").Where("recovery_codes = ?", string(prev)).Updates(&model.UserDBModel{RecoveryCodes: remaining}))
}

func (u *userService) UpdateUserPassword(m model.UserDBModel) {
	u.db.Model(&m).Update("password", m.Password)
}

func (u *userService) GetUserAllInfoById(id string) (m model.UserDBModel) {
	u.db.Where("id= ?", id).First(&m)
	return
}

func (u *userService) GetUserAllInfoByName(userName string) (m model.UserDBModel) {
	u.db.Where("username= ?", userName).First(&m)
	return
}

func (u *userService) GetUserInfoById(id string) (m model.UserDBModel) {
	u.db.Select("username", "id", "role", "nickname", "description", "avatar", "email", "totp_enabled").Where("id= ?", id).First(&m)
	return
}

func (u *userService) GetUserInfoByUserName(userName string) (m model.UserDBModel) {
	u.db.Select("username", "id", "role", "nickname", "description", "avatar", "email", "totp_enabled").Where("username= ?", userName).First(&m)
	return
}

// 上传文件
func (c *userService) UpLoadFile(file multipart.File, url string) error {
	out, _ := os.OpenFile(url, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0o644)
	defer out.Close()
	io.Copy(out, file)
	return nil
}

func (u *userService) GetKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	return u.privateKey, u.publicKey
}

// PreAuthTTL bounds the window between the password and the second factor.
const PreAuthTTL = 5 * time.Minute

func (u *userService) IssuePreAuthToken(m model.UserDBModel) (string, error) {
	return jwt.GenerateToken(m.Username, u.preAuthPriv, m.Id, "2fa", PreAuthTTL)
}

func (u *userService) ParsePreAuthToken(token string) (*jwt.Claims, error) {
	claims, err := jwt.ParseToken(token, func() (*ecdsa.PublicKey, error) { return u.preAuthPub, nil })
	if err != nil {
		return nil, err
	}
	if !claims.VerifyIssuer("2fa", true) || !claims.VerifyExpiresAt(time.Now(), true) {
		return nil, errors.New("invalid pre-auth token")
	}
	return claims, nil
}

// NewUserService signs with the key kept at keyPath (user_key.go), and with
// a key made here and now for the pre-auth window.
func NewUserService(db *gorm.DB, keyPath string) UserService {
	privateKey, publicKey, err := loadOrCreateKeyPair(keyPath)
	if err != nil {
		logger.Error("failed to load or make the key pair for JWT", zap.Error(err), zap.String("path", keyPath))
		return nil
	}
	preAuthPriv, preAuthPub, err := jwt.GenerateKeyPair()
	if err != nil {
		logger.Error("failed to generate key pair for pre-auth tokens", zap.Error(err))
		return nil
	}

	return &userService{
		privateKey:  privateKey,
		publicKey:   publicKey,
		preAuthPriv: preAuthPriv,
		preAuthPub:  preAuthPub,
		db:          db,
	}
}
