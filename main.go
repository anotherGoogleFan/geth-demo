package main

import (
	"context"
	"crypto/ecdsa"
	"log/slog"
	"math"
	"math/big"
	"os"
	"sync"

	"geth-demo/conf"
	"geth-demo/gethResorce"
	"geth-demo/logic"
	"geth-demo/token"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
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
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go subscribeNewBlock(wg)
	rangeAccountBalance()
	getTokenInfoByAddr()
	genNewWallet()
	genKeystoreAccount()
	importKeystoreAccount()
	isContractAddr()
	getBlockInfo()
	getTransaction()
	transaction()
	transToken()
	wg.Wait()
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

// 09.地址检查
func isContractAddr() {
	addr := common.HexToAddress("0xe41d2489571d322189246dafa5ebde1f4699f498")
	isContractAddr, err := gethResorce.IsContractAddr(addr)
	if err != nil {
		slog.Error("iscontract fail", slog.Any("err", err))
		return
	}
	slog.Info("contract addr judge", slog.Any("is contract addr", isContractAddr))
}

// 10.查询区块
func getBlockInfo() {
	ctx := context.TODO()
	header, err := gethResorce.GetBlockHeaderByNumber(ctx, nil)
	if err != nil {
		slog.Error("get block head fail", slog.Any("err", err))
		return
	}
	slog.Info("newest head", slog.Any("number", header.Number.String()))
	block, err := gethResorce.GetBlockByNumber(ctx, header.Number)
	if err != nil {
		slog.Error("get block fail", slog.Any("err", err))
		return
	}
	transCount, err := gethResorce.GetTransactionCountByBlockHash(ctx, block.Hash())
	if err != nil {
		slog.Error("get transcount fail", slog.Any("err", err))
		return
	}
	slog.Info("get transcount", slog.Any("count", transCount))
}

// 11.查询交易
func getTransaction() {
	ctx := context.TODO()
	block, err := gethResorce.GetBlockByNumber(ctx, nil)
	if err != nil {
		slog.Error("get block fail", slog.Any("err", err))
		return
	}
	slog.Info("newest block time", slog.Any("timestamp", block.Time()))
	transCount, err := gethResorce.GetTransactionCountByBlockHash(ctx, block.Hash())
	if err != nil {
		slog.Error("get transcount fail", slog.Any("err", err))
		return
	}
	slog.Info("newest block trans count", slog.Any("count", transCount))
	for i, tx := range block.Transactions() {
		txFrom, _ := gethResorce.GetTransactionFrom(ctx, tx)
		slog.Info("block transaction info", slog.Any("idx", i), slog.Any("tx hash", tx.Hash().Hex()), slog.Any("tx value", tx.Value().String()), slog.Any("tx gas", tx.Gas()),
			slog.Any("price", tx.GasPrice().Uint64()), slog.Any("nonce", tx.Nonce()), slog.Any("data", tx.Data()), slog.Any("from", txFrom.Hex()), slog.Any("to", tx.To().Hex()))
	}
}

// 12.转账以太币ETH
func transaction() {
	// 发送1ETH
	value := big.NewInt(int64(math.Pow10(18)))
	// 账号2发送到账号3
	if err := gethResorce.Trans(myAccounts[1].privateKey, gethResorce.GetAddrByPublicKey(myAccounts[2].publicKey), value); err != nil {
		slog.Error("transaction fail", slog.Any("err", err))
		return
	}
	slog.Info("transaction success")
}

// 13.代币的转账
func transToken() {
	toAddr := gethResorce.GetAddrByPublicKey(myAccounts[1].publicKey)
	tokenAddress := common.HexToAddress("0x28b149020d2152179873ec60bed6bf7cd705775d")
	if err := logic.TransToken(context.TODO(), myAccounts[0].privateKey, toAddr, tokenAddress, big.NewInt(1)); err != nil {
		slog.Error("trans token fail", slog.Any("err", err))
		return
	}
	slog.Info("trans token success")
}

// 14.订阅新区块
func subscribeNewBlock(wg *sync.WaitGroup) {
	defer wg.Done()
	headers := make(chan *types.Header)
	defer close(headers)
	sub, err := gethResorce.GetClient().SubscribeNewHead(context.Background(), headers)
	if err != nil {
		slog.Error("subscribe fail", slog.Any("err", err))
		return
	}
	for {
		select {
		case err = <-sub.Err():
			slog.Error("subscribing fail", slog.Any("err", err))
			return
		case header := <-headers:
			slog.Info("new header success", slog.Any("header hash", header.Hash().Hex()))
		}
	}
}

//
