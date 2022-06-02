package main

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"log"
	"math/big"
)

// queryTransactionsByBlock 遍历区块中的所有交易信息
func queryTransactionsByBlock(client *ethclient.Client) {
	blockNumber := big.NewInt(14883178)
	// 第二个参数nil，表示返回最新的区块信息
	block, err := client.BlockByNumber(context.Background(), blockNumber)
	if err != nil {
		log.Fatal(err)
	}

	for _, transaction := range block.Transactions() {
		fmt.Printf("Transcation: %s\n", transaction.Hash().Hex())
	}
}

// queryTransactionByIndexInBlock 通过TransactionInBlock方法根据交易索引位置查询交易信息
func queryTransactionByIndexInBlock(client *ethclient.Client) {
	blockHash := common.HexToHash("0x9e8751ebb5069389b855bba72d94902cc385042661498a415979b7b6ee9ba4b9")
	count, err := client.TransactionCount(context.Background(), blockHash)
	if err != nil {
		log.Fatal(err)
	}

	for idx := uint(0); idx < count; idx++ {
		tx, err := client.TransactionInBlock(context.Background(), blockHash, idx)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Transcation: %s\n", tx.Hash().Hex())
	}
}

// queryTransactionByTransactionHash 通过交易的hash值来查询交易信息
func queryTransactionByTransactionHash(client *ethclient.Client) {
	txHash := common.HexToHash("0x6ea1993af8b721c56c0ad1f79683f51011d214baeb8fdb575ac4ec00e1eba94e")
	tx, isPending, err := client.TransactionByHash(context.Background(), txHash)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(tx.Hash().Hex()) // 0x5d49fcaa394c97ec8a9c3e7bd9e8388d420fb050a52083ca52ff24b3b65bc9c2
	fmt.Println(isPending)
}

func main() {
	client, err := ethclient.Dial("https://mainnet.infura.io/v3/28d5693e8bee4b58a61f0c627d62331e")
	if err != nil {
		log.Fatal(err)
	}
	queryTransactionsByBlock(client)
	queryTransactionByIndexInBlock(client)
	queryTransactionByTransactionHash(client)
}
