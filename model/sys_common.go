package model

type CommonModel struct {
	RuntimePath string
}

type APPModel struct {
	LogPath      string
	LogSaveName  string
	LogFileExt   string
	UserDataPath string
	DBPath       string
	// FirstAdmin: "web" (default) → the first visitor of the dashboard creates
	// the first account; "local" → only on the machine (-bootstrap-admin)
	FirstAdmin string
}

type Result struct {
	Success int         `json:"success" example:"200"`
	Message string      `json:"message" example:"ok"`
	Data    interface{} `json:"data" example:"返回结果"`
}
