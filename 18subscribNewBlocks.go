package main

import (
	"context"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	client, err := ethclient.Dial("wss://mainnet.infura.io/ws/v3/28d5693e8bee4b58a61f0c627d62331e")
	if err != nil {
		log.Fatal(err)
	}

	headers := make(chan *types.Header)
	sub, err := client.SubscribeNewHead(context.Background(), headers)
	if err != nil {
		log.Fatal(err)
	}

	for {
		select {
		case err := <-sub.Err():
			log.Fatal(err)
		case header := <-headers:
			fmt.Printf("Header Hash: %s\n", header.Hash().Hex())

			block, err := client.BlockByHash(context.Background(), header.Hash())
			if err != nil {
				log.Fatal(err)
			}

			fmt.Printf("Block Hash: %s\n", block.Hash().Hex())
			fmt.Printf("Block Number: %d\n", block.Number().Uint64())
			fmt.Printf("Block Time: %d\n", block.Time())
			fmt.Printf("Block None:%d\n", block.Nonce())
			fmt.Printf("TTransactions Numbers: %d", len(block.Transactions()))
		}
	}
}
