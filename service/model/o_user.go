/*
 * @Author: LinkLeong link@icewhale.com
 * @Date: 2022-05-13 18:15:46
 * @LastEditors: LinkLeong
 * @LastEditTime: 2022-07-11 17:57:00
 * @Description:
 * @Website: https://www.casaos.io
 * Copyright (c) 2022 by icewhale, All Rights Reserved.
 */
package model

import "time"

//Soon to be removed
type UserDBModel struct {
	Id          int       `gorm:"column:id;primary_key" json:"id"`
	Username    string    `json:"username"`
	Password    string    `json:"password,omitempty"`
	Role        string    `json:"role"`
	Email       string    `json:"email"`
	Nickname    string    `json:"nickname"`
	Avatar      string    `json:"avatar"`
	Description string    `json:"description"`
	CreatedAt   time.Time `gorm:"<-:create;autoCreateTime" json:"created_at,omitempty"`
	UpdatedAt   time.Time `gorm:"<-:create;<-:update;autoUpdateTime" json:"updated_at,omitempty"`

	// TotpSecret is the base32 TOTP seed. It cannot be hashed: the server must
	// recompute codes from it at every login, so it lives in clear next to the
	// (MD5) password hash and is protected only by the DB file permissions.
	// json:"-" on the secret fields is load-bearing: login serialises the whole
	// row, and PUT /v1/users/current binds the request body into this struct.
	TotpSecret    string   `gorm:"default:''" json:"-"`
	TotpEnabled   bool     `gorm:"default:false" json:"totp_enabled"`
	TotpLastStep  int64    `gorm:"default:0" json:"-"`      // last accepted 30 s step (replay guard)
	RecoveryCodes []string `gorm:"serializer:json" json:"-"` // bcrypt hashes, removed as consumed
}

func (p *UserDBModel) TableName() string {
	return "o_users"
}
