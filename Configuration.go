package main

import (
	"encoding/json"
	"github.com/labstack/gommon/log"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"time"
)

type WgConf struct {
	configPath string
	PrivateKey string
	PublicKey  string
	Users      map[string]*UserConf
}
type UserConf struct {
	Name    string
	Clients map[string]*ClientConfig
}
type ClientConfig struct {
	Name       string
	PrivateKey string
	PublicKey  string
	IP         net.IP
	Created    string
	Modified   string
	Info       string
}

func newServerConfig(cfgPath string) *WgConf {
	keys, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Error("Fatal", err)
	}
	config := &WgConf{
		configPath: cfgPath,
		PrivateKey: keys.String(),
		PublicKey:  keys.PublicKey().String(),
		Users:      make(map[string]*UserConf),
	}
	file, err := os.Open(filepath.Clean(cfgPath))
	if err == nil {
		if err = json.NewDecoder(file).Decode(config); err != nil {
			log.Fatal("Failing to decode :: ", err)
		}
		log.Info("Read server config from file : ", cfgPath)
		log.Info("------------------------------------------")
	} else if os.IsNotExist(err) {
		log.Info("No configuration file found  ::  Creating one ", cfgPath)
		err = config.Write()

	}
	log.Info("PublicKey: ", config.PublicKey, "     PrivateKey: ", config.PrivateKey)
	if err != nil {
		log.Info("Error", err)
	}
	return config
}

func (config *WgConf) Write() error {
	data, err := json.MarshalIndent(config, "", " ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(config.configPath, data, 0600)
}

func (config *WgConf) GetUSerConfig(user string) *UserConf {
	us, ok := config.Users[user]
	if !ok {
		log.Info("This user is not existing: ", user, " Making one righ now.....")
		us = &UserConf{
			Name:    user,
			Clients: make(map[string]*ClientConfig),
		}
		config.Users[user] = us
	}
	return us
}

func NewClientConfig(ip net.IP, Name, Info string) *ClientConfig {
	keys, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Fatal("Failed to generate keys :: ", err)
	}
	config := ClientConfig{
		Name:       Name,
		PrivateKey: keys.String(),
		PublicKey:  keys.PublicKey().String(),
		IP:         ip,
		Created:    time.Now().Format(time.RFC3339),
		Modified:   time.Now().Format(time.RFC3339),
		Info:       Info,
	}
	return &config
}
