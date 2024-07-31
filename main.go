package main

import (
	"log/slog"
	"os"

	"geth-demo/conf"
	"geth-demo/gethResorce"
	"geth-demo/logic"
	"geth-demo/token"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

// 02.初始化客户端
func init() {
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(h))
	if err := conf.LoadJSON("geth.json", &conf.Conf); err != nil {
		slog.Error("init config fail", slog.Any("err", err))
		os.Exit(0)
	}
	if err := gethResorce.InitClient(conf.Conf.Ethereum.Addr); err != nil {
		slog.Error("init geth client fail", slog.Any("err", err))
		os.Exit(0)
	}
}

func main() {
	rangeAccountBalance()
	getTokenInfoByAddr()
	genNewWallet()
	genKeystoreAccount()
	importKeystoreAccount()
}

// 03.账户
// 04.账户余额
func rangeAccountBalance() {
	for i := uint8(0); i < 7; i++ {
		balance, _ := logic.GetBalanceByAccountIdx(i)
		slog.Info("account balance", slog.Any("index", i), slog.Any("balance", logic.WeiToEth(balance)))
	}
}

// 05.账户代币余额
func getTokenInfoByAddr() {
	tokenAddr := conf.Conf.Ethereum.TokenAddr
	client := gethResorce.GetClient()
	tokenAddress := common.HexToAddress(tokenAddr)
	tk, err := token.NewToken(tokenAddress, client)
	if err != nil {
		slog.Error("get token info fail", slog.Any("addr", tokenAddr), slog.Any("err", err))
		return
	}
	callOpts := &bind.CallOpts{}
	tkName, _ := tk.Name(callOpts)
	tkSymbol, _ := tk.Symbol(callOpts)
	decimals, _ := tk.Decimals(callOpts)
	slog.Info("token info", slog.Any("addr", tokenAddr), slog.Any("name", tkName), slog.Any("symbol", tkSymbol), slog.Any("decimals", decimals))
}

// 06.生成新钱包
func genNewWallet() {
	newWalletPrivate, newWalletPublic, err := gethResorce.GetNewWallet()
	if err != nil {
		slog.Error("generate new wallet fail", slog.Any("err", err))
		return
	}
	privateKey := gethResorce.PrivateKeyToHex(newWalletPrivate)
	publicKey := gethResorce.PublicKeyToHex(newWalletPublic)
	walletAddr := gethResorce.GetAddrByPublicKey(newWalletPublic)
	slog.Info("generate new wallet", slog.Any("publicKey", publicKey), slog.Any("privateKey", privateKey), slog.Any("wallet addr", walletAddr.Hex()))
}

// 07.KeyStores
func genKeystoreAccount() {
	account, err := gethResorce.GenKeystoreAccountByPassword("myPassword")
	if err != nil {
		slog.Error("generate new keystore account fail", slog.Any("err", err))
		return
	}
	slog.Info("generate new keystore account", slog.Any("account", account.Address.Hex()))
}

// 07.KeyStores
func importKeystoreAccount() {
	account, err := gethResorce.GetKeystoreAccountFromFileByPassword("./wallet1/UTC--2024-07-31T13-52-11.772568000Z--07986f634c3b5de73e7026f0cc677943bbdeea11", "myPassword", "myNewPassword")
	if err != nil {
		slog.Error("import keystore account fail", slog.Any("err", err))
		return
	}
	slog.Info("import keystore account", slog.Any("account", account.Address.Hex()))
}
