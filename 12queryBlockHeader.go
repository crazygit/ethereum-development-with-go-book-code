package main

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/ethclient"
	"log"
)

func main() {
	client, err := ethclient.Dial("https://cloudflare-eth.com")
	if err != nil {
		log.Fatal(err)
	}

	// 第二个参数nil，表示返回最新的区块头信息
	header, err := client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Block Number: %s\n", header.Number.String())
	fmt.Printf("Block Time: %d\n", header.Time)
	fmt.Printf("Block Difficulty: %d\n", header.Difficulty)
	fmt.Printf("Block GasUsed: %d\n", header.GasUsed)
	fmt.Printf("Block GasLimit: %d\n", header.GasLimit)

}
