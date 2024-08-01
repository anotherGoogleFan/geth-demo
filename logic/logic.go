package logic

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"math"
	"math/big"

	"geth-demo/conf"
	"geth-demo/gethResorce"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"golang.org/x/crypto/sha3"
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

// 转移代币
func TransToken(ctx context.Context, privateKey *ecdsa.PrivateKey, toAddr, tokenAddr common.Address, amount *big.Int) error {
	publicKey, err := gethResorce.GetPublickKeyFromPrivateKey(privateKey)
	if err != nil {
		return err
	}
	fromAddr := gethResorce.GetAddrByPublicKey(publicKey)
	client := gethResorce.GetClient()
	nonce, err := client.PendingNonceAt(context.Background(), fromAddr)
	if err != nil {
		return err
	}
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return err
	}
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte("transfer(address,uint256)"))
	methodID := hash.Sum(nil)[:4]
	paddedAddress := common.LeftPadBytes(tokenAddr.Bytes(), 32)
	paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)
	data := make([]byte, 68)
	copy(data[:4], methodID)
	copy(data[4:36], paddedAddress)
	copy(data[36:68], paddedAmount)
	gasLimit, err := client.EstimateGas(ctx, ethereum.CallMsg{
		To:   &tokenAddr,
		Data: data,
	})
	if err != nil {
		return err
	}
	tx := types.NewTransaction(nonce, tokenAddr, big.NewInt(0), gasLimit, gasPrice, data)
	chainID := gethResorce.GetChainID()
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return err
	}
	return client.SendTransaction(ctx, signedTx)
}
