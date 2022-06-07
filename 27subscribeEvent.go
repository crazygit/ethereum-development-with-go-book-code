package main

import (
	"context"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	client, err := ethclient.Dial("wss://mainnet.infura.io/ws/v3/28d5693e8bee4b58a61f0c627d62331e")
	if err != nil {
		log.Fatal(err)
	}

	contractAddress := common.HexToAddress("0xf1EEfEE62A8651c3772cd8D7ba9031b7029316f7")
	// 设置日志过滤条件
	query := ethereum.FilterQuery{
		Addresses: []common.Address{contractAddress},
	}

	logs := make(chan types.Log)
	// 也可以使用 client.FilterLogs根据过滤条件来查询日志
	sub, err := client.SubscribeFilterLogs(context.Background(), query, logs)
	if err != nil {
		log.Fatal(err)
	}

	for {
		select {
		case err := <-sub.Err():
			log.Fatal(err)
		case vLog := <-logs:
			fmt.Println(vLog) // pointer to event log
		}
	}
}
