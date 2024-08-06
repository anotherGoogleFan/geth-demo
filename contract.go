package main

import (
	"context"
	"log/slog"
	"math/big"

	"geth-demo/contract/store"
	"geth-demo/gethResorce"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

func Contract() {
	deploy()
}

// 18.部署智能合约
func deploy() common.Address {
	client := gethResorce.GetClient()
	fromAddr := gethResorce.GetAddrByPublicKey(myAccounts[0].publicKey)
	nonce, err := client.PendingNonceAt(context.TODO(), fromAddr)
	if err != nil {
		slog.Error("deploy contract: nonce fail", slog.Any("err", err))
		return common.Address{}
	}
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		slog.Error("deploy contract: gas price fail", slog.Any("err", err))
		return common.Address{}
	}
	chainID := gethResorce.GetChainID()
	auth, err := bind.NewKeyedTransactorWithChainID(myAccounts[0].privateKey, chainID)
	if err != nil {
		slog.Error("deploy contract: auth fail", slog.Any("err", err))
		return common.Address{}
	}
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)
	auth.GasLimit = uint64(300000)
	auth.GasPrice = gasPrice

	input := "1.0"
	address, tx, _, err := store.DeployStore(auth, client, input)
	if err != nil {
		slog.Error("deploy contract: deploy fail", slog.Any("err", err))
		return common.Address{}
	}
	slog.Info("deploy contract success", slog.Any("address", address.Hex()), slog.Any("tx", tx.Hash().Hex()))
	return address
}
