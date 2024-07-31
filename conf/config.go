package conf

import (
	"encoding/json"
	"io"
	"os"
)

var Conf struct {
	Ethereum ethConf `json:"ethereum"`
}

type ethConf struct {
	Addr      string       `json:"addr"`
	Accounts  []EthAccount `json:"accounts"`
	TokenAddr string       `json:"tokenAddr"`
}

type EthAccount struct {
	Addr       string `json:"addr"`
	PrivateKey string `json:"privateKey"`
}

func LoadJSON(path string, cfg interface{}) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	bs, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		return err
	}
	if err = json.Unmarshal(bs, cfg); err != nil {
		return err
	}
	return nil
}
