package main

import (
	"context"
	"log/slog"
	"math/big"
	"strings"
	"sync"

	"geth-demo/contract/store"
	"geth-demo/gethResorce"
	"geth-demo/token"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func Contract() {
	contractAddr := deploy()
	if contractAddr == (common.Address{}) {
		return
	}
	st := loadContract(contractAddr)
	if st == nil {
		return
	}
	queryContract(st)
	SetContract(st)
	getContractByteCode(contractAddr)
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go subscribeContractLog(wg, contractAddr)
	readErc20LogEvent()
	wg.Wait()
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

// 19.加载智能合约
func loadContract(contractAddr common.Address) *store.Store {
	client := gethResorce.GetClient()
	st, err := store.NewStore(contractAddr, client)
	if err != nil {
		slog.Error("load contract fail", slog.Any("err", err))
		return nil
	}
	slog.Info("load contract success")
	return st
}

// 20.查询智能合约
func queryContract(st *store.Store) {
	ver, err := st.Version(nil)
	if err != nil {
		slog.Error("get contract version fail", slog.Any("err", err))
		return
	}
	slog.Info("get contract version", slog.Any("version", ver))
}

// 21.写入智能合约
func SetContract(st *store.Store) {
	client := gethResorce.GetClient()
	fromAddr := gethResorce.GetAddrByPublicKey(myAccounts[0].publicKey)
	ctx := context.TODO()
	nonce, err := client.PendingNonceAt(ctx, fromAddr)
	if err != nil {
		slog.Error("set contract: nonce fail", slog.Any("err", err))
		return
	}
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		slog.Error("set contract: gesPrice fail", slog.Any("err", err))
		return
	}
	chainID := gethResorce.GetChainID()
	auth, err := bind.NewKeyedTransactorWithChainID(myAccounts[0].privateKey, chainID)
	if err != nil {
		slog.Error("set contract: auth fail", slog.Any("err", err))
		return
	}
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)
	auth.GasLimit = uint64(300000)
	auth.GasPrice = gasPrice
	key := [32]byte{}
	value := [32]byte{}
	copy(key[:], []byte("foo"))
	copy(value[:], []byte("bar"))
	tx, err := st.SetItem(auth, key, value)
	if err != nil {
		slog.Error("set contract: tx fail", slog.Any("err", err))
		return
	}
	slog.Info("set contract tx", slog.Any("tx", tx.Hash().Hex()))
	result, err := st.Items(nil, key)
	if err != nil {
		slog.Error("set contract: result fail", slog.Any("err", err))
		return
	}
	slog.Info("set conract", slog.Any("result", string(result[:])))
}

// 22.读取智能合约的字节码
func getContractByteCode(contractAddr common.Address) {
	client := gethResorce.GetClient()
	byteCode, err := client.CodeAt(context.TODO(), contractAddr, nil)
	if err != nil {
		slog.Error("get contract bytecode fail", slog.Any("err", err))
		return
	}
	slog.Info("get contract bytecode success", slog.Any("byteCode", byteCode))
}

// 23.订阅事件日志
// 24.读取日志事件
func subscribeContractLog(wg *sync.WaitGroup, contractAddr common.Address) {
	defer wg.Done()
	client := gethResorce.GetClient()
	query := ethereum.FilterQuery{
		Addresses: []common.Address{contractAddr},
	}
	logChan := make(chan types.Log)
	defer close(logChan)
	sub, err := client.SubscribeFilterLogs(context.TODO(), query, logChan)
	if err != nil {
		slog.Error("subscribe log fail", slog.Any("err", err))
		return
	}
	contractABI, err := abi.JSON(strings.NewReader(store.StoreABI))
	if err != nil {
		slog.Error("subscribe log event fail: contractABI", slog.Any("err", err))
		return
	}
	slog.Info("subscribe log event success")
	for {
		select {
		case <-sub.Err():
			slog.Error("subscribe log receive fail", slog.Any("err", err))
			return
		case vLog := <-logChan:
			slog.Info("receive log", slog.Any("vLog", vLog))
			readLogEvent(contractABI, vLog)
		}
	}
}

// 24.读取日志事件
func readLogEvent(contractABI abi.ABI, vLog types.Log) {
	var event struct {
		Key   [32]byte
		Value [32]byte
	}
	if err := contractABI.UnpackIntoInterface(&event, "ItemSet", vLog.Data); err != nil {
		slog.Error("read log event fail: unpack", slog.Any("err", err))
		return
	}
	slog.Info("read log event success", slog.Any("event", event))
}

// 25.读取ERC-20代币的事件日志
func readErc20LogEvent() {
	contractAddress := common.HexToAddress("0xe41d2489571d322189246dafa5ebde1f4699f498")
	query := ethereum.FilterQuery{
		FromBlock: big.NewInt(6383820),
		ToBlock:   big.NewInt(6383840),
		Addresses: []common.Address{
			contractAddress,
		},
	}
	client := gethResorce.GetClient()
	logs, err := client.FilterLogs(context.Background(), query)
	if err != nil {
		slog.Error("read erc20 log event fail: filter logs", slog.Any("err", err))
		return
	}
	contractAbi, err := abi.JSON(strings.NewReader(token.TokenABI))
	if err != nil {
		slog.Error("read erc20 log event fail: contract abi", slog.Any("err", err))
		return
	}
	logTransferSigHash := crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)"))
	logApprovalSigHash := crypto.Keccak256Hash([]byte("Approval(address,address,uint256)"))
	for _, vLog := range logs {
		slog.Info("vlog info", slog.Any("block number", vLog.BlockNumber), slog.Any("log index", vLog.Index))
		if len(vLog.Topics[0]) == 0 {
			slog.Info("empty topic")
			continue
		}
		switch vLog.Topics[0] {
		case logTransferSigHash:
			var transferEvent struct {
				From   common.Address
				To     common.Address
				Tokens *big.Int
			}
			if err = contractAbi.UnpackIntoInterface(&transferEvent, "Transfer", vLog.Data); err != nil {
				slog.Error("unpack transfer log", slog.Any("err", err))
				continue
			}
			transferEvent.From = common.HexToAddress(vLog.Topics[1].Hex())
			transferEvent.To = common.HexToAddress(vLog.Topics[2].Hex())
			slog.Info("erc20 log: transfer", slog.Any("from", transferEvent.From.Hex()), slog.Any("to", transferEvent.To.Hex()), slog.Any("Tokens", transferEvent.Tokens.String()))
		case logApprovalSigHash:
			var approvalEvent struct {
				TokenOwner common.Address
				Spender    common.Address
				Tokens     *big.Int
			}
			if err = contractAbi.UnpackIntoInterface(&approvalEvent, "Approval", vLog.Data); err != nil {
				slog.Error("unpack approval log", slog.Any("err", err))
				continue
			}
			approvalEvent.TokenOwner = common.HexToAddress(vLog.Topics[1].Hex())
			approvalEvent.Spender = common.HexToAddress(vLog.Topics[2].Hex())
			slog.Info("erc20 log: approval", slog.Any("owner", approvalEvent.TokenOwner.Hex()), slog.Any("spender", approvalEvent.Spender.Hex()), slog.Any("Tokens", approvalEvent.Tokens.String()))
		}
	}
	slog.Info("erc20 log success")
}
