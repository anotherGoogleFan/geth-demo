package gethResorce

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

var chainID *big.Int

func initChaiID() error {
	eChainID, err := client.NetworkID(context.TODO())
	if err != nil {
		return err
	}
	chainID = eChainID
	return nil
}

func GetChainID() *big.Int {
	return chainID
}

func GetBlockHeaderByNumber(ctx context.Context, blockNumber *big.Int) (*types.Header, error) {
	return client.HeaderByNumber(ctx, blockNumber)
}

func GetBlockByNumber(ctx context.Context, blockNumber *big.Int) (*types.Block, error) {
	return client.BlockByNumber(ctx, blockNumber)
}

func GetTransactionCountByBlockHash(ctx context.Context, blockHash common.Hash) (uint, error) {
	return client.TransactionCount(ctx, blockHash)
}

func GetTransactionFrom(ctx context.Context, tx *types.Transaction) (common.Address, error) {
	return types.Sender(types.NewEIP155Signer(chainID), tx)
}
