package common

import "github.com/IceWhaleTech/CasaOS-Common/utils/common_err"

// Result codes for two-factor authentication; the user block in Common ends at 10013.
const (
	TWO_FA_REQUIRED        = 10014
	TWO_FA_CODE_INVALID    = 10015
	TWO_FA_ALREADY_ENABLED = 10016
	TWO_FA_NOT_ENABLED     = 10017
)

var twoFAMsg = map[int]string{
	TWO_FA_REQUIRED:        "Two-factor code required",
	TWO_FA_CODE_INVALID:    "Two-factor code invalid",
	TWO_FA_ALREADY_ENABLED: "Two-factor authentication already enabled",
	TWO_FA_NOT_ENABLED:     "Two-factor authentication not enabled",
}

// GetMsg resolves the codes above and falls back to Common for every other code.
func GetMsg(code int) string {
	if msg, ok := twoFAMsg[code]; ok {
		return msg
	}
	return common_err.GetMsg(code)
}
