package gethResorce

import (
	"crypto/ecdsa"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// 返回 publicKey, privateKey
func GetNewWallet() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := GetPublickKeyFromPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

func GetPublickKeyFromPrivateKey(privateKey *ecdsa.PrivateKey) (*ecdsa.PublicKey, error) {
	if privateKey == nil {
		return nil, nil
	}
	publicKey := privateKey.Public()
	pk, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid public key")
	}
	return pk, nil
}

func HexToPrivateKey(privateKeyHex string) (*ecdsa.PrivateKey, error) {
	privateKeyBytes, err := hexutil.Decode(privateKeyHex)
	if err != nil {
		return nil, err
	}
	return crypto.ToECDSA(privateKeyBytes)
}

func PrivateKeyToHex(privateKey *ecdsa.PrivateKey) string {
	if privateKey == nil {
		return ""
	}
	privateKeyBytes := crypto.FromECDSA(privateKey)
	return hexutil.Encode(privateKeyBytes)
}

func PublicKeyToHex(publicKey *ecdsa.PublicKey) string {
	if publicKey == nil {
		return ""
	}
	publicKeyBytes := crypto.FromECDSAPub(publicKey)
	return hexutil.Encode(publicKeyBytes)
}

func GetAddrByPublicKey(publicKey *ecdsa.PublicKey) common.Address {
	if publicKey == nil {
		return common.Address{}
	}
	return crypto.PubkeyToAddress(*publicKey)
}
