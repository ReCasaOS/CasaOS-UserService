package route

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/CasaOS-Common/utils/logger"
	message_bus "github.com/ReCasaOS/CasaOS-UserService/codegen/message_bus"
	"github.com/ReCasaOS/CasaOS-UserService/model"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/config"
	"github.com/ReCasaOS/CasaOS-UserService/service"
	"go.uber.org/zap"
	"golang.org/x/net/websocket"
)

func EventListen() {
	for i := 0; i < 1000; i++ {

		messageBusUrl, err := external.GetMessageBusAddress(config.CommonInfo.RuntimePath)
		if err != nil {
			logger.Error("get message bus url error", zap.Any("err", err))
			return
		}

		wsURL := fmt.Sprintf("ws://%s/event/%s", strings.ReplaceAll(messageBusUrl, "http://", ""), "local-storage")
		ws, err := dialMessageBus(wsURL, config.CommonInfo.RuntimePath)
		if err != nil {
			logger.Error("connect websocket err"+strconv.Itoa(i), zap.Any("error", err))
			time.Sleep(time.Second * 1)
			continue
		}
		logger.Info("subscribed to", zap.Any("url", wsURL))
		// A working subscription starts the retry budget over, as the process
		// restart that used to follow a lost subscription did.
		i = 0
		for {
			var msg []byte
			if err := websocket.Message.Receive(ws, &msg); err != nil {
				// The bus went away: dial again, with the secret of now.
				logger.Error("message bus subscription lost", zap.Error(err))
				break
			}

			var event message_bus.Event
			if err := json.Unmarshal(msg, &event); err != nil || event.Uuid == nil {
				logger.Error("invalid event from message bus", zap.Any("err", err), zap.ByteString("event", msg))
				continue
			}
			propertiesStr, err := json.Marshal(event.Properties)
			if err != nil {
				logger.Error("marshal error", zap.Any("err", err.Error()), zap.Any("event", event))
				continue
			}
			model := model.EventModel{
				SourceID:   event.SourceID,
				Name:       event.Name,
				Properties: string(propertiesStr),
				UUID:       *event.Uuid,
			}
			if event.Name == "local-storage:raid_status" {
				continue
			}
			service.MyService.Event().CreateEvemt(model)
			// logger.Info("info", zap.Any("写入信息1", model))
			// output, err := json.MarshalIndent(event, "", "  ")
			// if err != nil {
			// 	logger.Error("err", zap.Any("err", err.Error()))
			// }
			// logger.Info("info", zap.Any("写入信息", string(output)))
		}
		ws.Close()
		time.Sleep(time.Second * 1)
	}
	logger.Error("error when try to connect to message bus")
}

// dialMessageBus opens the subscription with this boot's internal secret, which
// the bus now requires on its subscription routes. The secret is read at each
// dial because a restarted gateway rewrites it; with no secret file (an older
// gateway) the handshake goes without it, as before.
func dialMessageBus(wsURL, runtimePath string) (*websocket.Conn, error) {
	cfg, err := websocket.NewConfig(wsURL, "http://localhost")
	if err != nil {
		return nil, err
	}

	// the secret goes to this box's own bus only, as Common's clients send it
	if authorization := external.InternalAuthorization(runtimePath); authorization != "" && isLoopbackHost(cfg.Location.Hostname()) {
		cfg.Header.Set("Authorization", authorization)
	}

	return websocket.DialConfig(cfg)
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}
