package service

import (
	"path/filepath"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/CasaOS-UserService/codegen/message_bus"
	"github.com/ReCasaOS/CasaOS-UserService/pkg/config"
	"gorm.io/gorm"
)

var MyService Repository

type Repository interface {
	Gateway() external.ManagementService
	User() UserService
	MessageBus() *message_bus.ClientWithResponses
	Event() EventService
}

func NewService(db *gorm.DB, RuntimePath string) Repository {

	gatewayManagement, err := external.NewManagementService(RuntimePath)
	if err != nil {
		panic(err)
	}

	return &store{
		gateway: gatewayManagement,
		user:    NewUserService(db, filepath.Join(config.AppInfo.DBPath, KeyFilename)),
		event:   NewEventService(db),
	}
}

type store struct {
	gateway external.ManagementService
	user    UserService
	event   EventService
}

func (c *store) Event() EventService {
	return c.event
}
func (c *store) Gateway() external.ManagementService {
	return c.gateway
}

func (c *store) User() UserService {
	return c.user
}
func (c *store) MessageBus() *message_bus.ClientWithResponses {
	client, _ := message_bus.NewClientWithResponses("", func(c *message_bus.Client) error {
		// error will never be returned, as we always want to return a client, even with wrong address,
		// in order to avoid panic.
		//
		// If we don't avoid panic, message bus becomes a hard dependency, which is not what we want.

		messageBusAddress, err := external.GetMessageBusAddress(config.CommonInfo.RuntimePath)
		if err != nil {
			c.Server = "message bus address not found"
			return nil
		}

		c.Server = messageBusAddress
		return nil
	}, message_bus.WithRequestEditorFn(external.InternalRequestEditor(config.CommonInfo.RuntimePath)))

	return client
}
