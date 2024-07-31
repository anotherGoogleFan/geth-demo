package logic

import (
	"context"
	"errors"
	"math"
	"math/big"

	"geth-demo/conf"
	"geth-demo/gethResorce"
)

func GetBalanceByAccountIdx(idx uint8) (*big.Int, error) {
	if idx >= 7 {
		return nil, errors.New("index must < 7")
	}
	return gethResorce.GetBalanceByAccountAddr(context.TODO(), conf.Conf.Ethereum.Accounts[idx].Addr)
}

func WeiToEth(wei *big.Int) *big.Float {
	if wei == nil {
		return nil
	}
	f, _ := big.NewFloat(0).SetString(wei.String())
	return big.NewFloat(0).Quo(f, big.NewFloat(math.Pow10(18)))
}
