package gethResorce

import (
	"os"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
)

func GenKeystoreAccountByPassword(password string) (accounts.Account, error) {
	ks := keystore.NewKeyStore("./wallet1", keystore.StandardScryptN, keystore.StandardScryptP)
	return ks.NewAccount(password)
}

func GetKeystoreAccountFromFileByPassword(file, password, newPassword string) (accounts.Account, error) {
	jsonBytes, err := os.ReadFile(file)
	if err != nil {
		return accounts.Account{}, err
	}
	ks := keystore.NewKeyStore("./wallet2", keystore.StandardScryptN, keystore.StandardScryptP)
	return ks.Import(jsonBytes, password, newPassword)
}
