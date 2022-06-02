package main

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/ethclient"
	"log"
	"math/big"
)

func main() {
	client, err := ethclient.Dial("https://cloudflare-eth.com")
	if err != nil {
		log.Fatal(err)
	}

	blockNumber := big.NewInt(14883178)
	// 第二个参数nil，表示返回最新的区块信息
	block, err := client.BlockByNumber(context.Background(), blockNumber)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Block Number: %s\n", block.Number())
	fmt.Printf("Block Time: %d\n", block.Time())
	fmt.Printf("Block Difficulty: %d\n", block.Difficulty())
	fmt.Printf("Block GasUsed: %d\n", block.GasUsed())
	fmt.Printf("Block GasLimit: %d\n", block.GasLimit())
	// 查询区块上交易的数目
	fmt.Printf("Block Transactions Count: %d\n", len(block.Transactions()))
	// 另一种查询区块交易数目的方法
	count, err := client.TransactionCount(context.Background(), block.Hash())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Block Transactions Count: %d\n", count)
}
