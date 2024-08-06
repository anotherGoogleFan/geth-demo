package main

import (
	"crypto/ecdsa"
	"log/slog"
	"os"

	"geth-demo/conf"
	"geth-demo/gethResorce"
)

var myAccounts [7]myAccount

type myAccount struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

// 02.初始化客户端
func init() {
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(h))
	if err := conf.LoadJSON("geth.json", &conf.Conf); err != nil {
		slog.Error("init config fail", slog.Any("err", err))
		os.Exit(0)
	}
	if len(conf.Conf.Ethereum.Accounts) < 7 {
		slog.Error("invalid accounts in conf")
		os.Exit(0)
	}
	if err := gethResorce.Init(conf.Conf.Ethereum.Addr); err != nil {
		slog.Error("init geth resource fail", slog.Any("err", err))
		os.Exit(0)
	}
	for i, accountConf := range conf.Conf.Ethereum.Accounts[:7:7] {
		privateKey, err := gethResorce.HexToPrivateKey(accountConf.PrivateKey)
		if err != nil {
			slog.Error("init myAccounts private key fail", slog.Any("idx", i), slog.Any("private hex", accountConf.PrivateKey), slog.Any("err", err))
			os.Exit(0)
		}
		publicKey, err := gethResorce.GetPublickKeyFromPrivateKey(privateKey)
		if err != nil {
			slog.Error("init myAccounts public key fail", slog.Any("idx", i), slog.Any("private hex", accountConf.PrivateKey), slog.Any("err", err))
			os.Exit(0)
		}
		if publicAddr := gethResorce.GetAddrByPublicKey(publicKey).Hex(); publicAddr != accountConf.Addr {
			slog.Error("init myAccounts public address check fail", slog.Any("idx", i), slog.Any("public addr", publicAddr), slog.Any("public in conf", accountConf.Addr))
			os.Exit(0)
		}
		myAccounts[i] = myAccount{
			privateKey: privateKey,
			publicKey:  publicKey,
		}
	}
}

func main() {
	// Basic()
	Contract()
}
