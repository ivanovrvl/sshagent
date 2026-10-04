package main

import (
	"encoding/json"
	"os"
)

var Config *ConfigObject

type User struct {
	Pwd        string `json:"pwd"`
	Key        string `json:"key"`
	RemotePort bool   `json:"remotePort"`
}

type ConfigObject struct {
	BindAddr  string          `json:"bindAddr"`
	ProxyType string          `json:"proxyType"`
	ProxyHost string          `json:"proxyHost"`
	ProxyPort int             `json:"proxyPort"`
	ProxyPwd  string          `json:"proxyPwd"`
	Users     map[string]User `json:"users"`
	KeyFile   string          `json:"keyFile"`
}

func LoadConfig() error {
	var newConfig ConfigObject

	configData, err := os.ReadFile("config.json")
	if err != nil {
		return err
	}

	err = json.Unmarshal(configData, &newConfig)
	if err != nil {
		return err
	}
	Config = &newConfig
	return nil
}
