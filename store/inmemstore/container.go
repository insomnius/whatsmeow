package inmemstore

import (
	"crypto/rand"
	"errors"
	"sync"

	mathRand "math/rand"

	"github.com/insomnius/whatsmeow/store"
	"github.com/insomnius/whatsmeow/types"
	"github.com/insomnius/whatsmeow/util/keys"
	waLog "github.com/insomnius/whatsmeow/util/log"
)

type Container struct {
	devices []*store.Device
	log     waLog.Logger
	locker  *sync.RWMutex
}

// New creates a new in-memory store container.
//
// The logger can be nil and will default to a no-op logger.
//
// container := inmemstore.New(nil)
func New(log waLog.Logger) *Container {
	if log == nil {
		log = waLog.Noop
	}

	return &Container{
		devices: []*store.Device{},
		log:     log,
		locker:  &sync.RWMutex{},
	}
}

// GetAllDevices return all devices from devices array.
func (c *Container) GetAllDevices() []*store.Device {
	return c.devices
}

// GetFirstDevice is a convenience method for getting the first device in device array. If there are
// no devices, then a new device will be created. You should only use this if you don't want to
// have multiple sessions simultaneously.
func (c *Container) GetFirstDevice() (*store.Device, error) {
	if len(c.devices) == 0 {
		return c.NewDevice(), nil
	} else {
		return c.devices[0], nil
	}
}

// NewDevice creates a new device in this database.
//
// No data is actually stored before Save is called. However, the pairing process will automatically
// call Save after a successful pairing, so you most likely don't need to call it yourself.
func (c *Container) NewDevice() *store.Device {
	device := &store.Device{
		Log: c.log,
		// Container: c,

		NoiseKey:       keys.NewKeyPair(),
		IdentityKey:    keys.NewKeyPair(),
		RegistrationID: mathRand.Uint32(),
		AdvSecretKey:   make([]byte, 32),
	}
	_, err := rand.Read(device.AdvSecretKey)
	if err != nil {
		panic(err)
	}
	device.SignedPreKey = device.IdentityKey.CreateSignedPreKey(1)

	return device
}

// GetDevice finds the device with the specified JID in the device array.
//
// If the device is not found, nil is returned instead.
//
// Note that the parameter usually must be an AD-JID.
func (c *Container) GetDevice(jid types.JID) (*store.Device, error) {
	c.locker.RLock()
	defer c.locker.RUnlock()

	for _, device := range c.devices {
		if device.ID != nil && *device.ID == jid {
			return device, nil
		}
	}

	return nil, nil
}

// ErrDeviceIDMustBeSet is the error returned by PutDevice if you try to save a device before knowing its JID.
var ErrDeviceIDMustBeSet = errors.New("device JID must be known before accessing database")

// PutDevice stores the given device in this database. This should be called through Device.Save()
// (which usually doesn't need to be called manually, as the library does that automatically when relevant).
// in this package this would be ignored, instead we let the package users save it in their own way.
func (c *Container) PutDevice(device *store.Device) error {
	return nil
}

// DeleteDevice deletes the given device from this database. This should be called through Device.Delete()
func (c *Container) DeleteDevice(store *store.Device) error {
	if store.ID == nil {
		return ErrDeviceIDMustBeSet
	}
	c.locker.Lock()
	defer c.locker.Unlock()

	for key, device := range c.devices {
		if device.ID != nil && *device.ID == *store.ID {
			c.devices = append(c.devices[:key], c.devices[key+1:]...)
			return nil
		}
	}

	return nil
}
