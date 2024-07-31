package gethResorce

import (
	"context"
	"log/slog"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

var client *ethclient.Client

func InitClient(ethAddr string) error {
	eClient, err := ethclient.Dial(ethAddr)
	if err != nil {
		return err
	}
	client = eClient
	slog.Info("geth client init success")
	return nil
}

func GetClient() *ethclient.Client {
	return client
}

func GetBalanceByAccountAddr(ctx context.Context, addr string) (*big.Int, error) {
	account := common.HexToAddress(addr)
	return client.BalanceAt(ctx, account, nil)
}

// 是否为合约地址
func IsContractAddr(addr common.Address) (bool, error) {
	bytecode, err := client.CodeAt(context.Background(), addr, nil) // nil is latest block
	if err != nil {
		return false, err
	}
	return len(bytecode) != 0, nil
}