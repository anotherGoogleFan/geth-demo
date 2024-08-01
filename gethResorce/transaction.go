package gethResorce

import (
	"context"
	"crypto/ecdsa"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func Trans(privateKey *ecdsa.PrivateKey, toAddr common.Address, value *big.Int) error {
	publicKey, err := GetPublickKeyFromPrivateKey(privateKey)
	if err != nil {
		return err
	}
	fromAddr := GetAddrByPublicKey(publicKey)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddr)
	if err != nil {
		return err
	}
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return err
	}
	gasLimit := uint64(21000)
	tx := types.NewTransaction(nonce, toAddr, value, gasLimit, gasPrice, nil)
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return err
	}
	return client.SendTransaction(context.Background(), signedTx)
}
