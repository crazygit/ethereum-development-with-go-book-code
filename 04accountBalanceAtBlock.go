package main

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"log"
	"math/big"
)

func main() {
	client, err := ethclient.Dial("https://mainnet.infura.io/v3/28d5693e8bee4b58a61f0c627d62331e")
	if err != nil {
		log.Fatal(err)
	}

	account := common.HexToAddress("0x71c7656ec7ab88b098defb751b7401b5f6d8976f")

	// blockNumber的值不能太老，否则会报
	// Invalid Request. Requested data is older than 128 blocks.
	// 或者报错
	// 403 Forbidden: {"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"project ID does not have access to archive state","data":{"see":"https://infura.io/dashboard"}}}
	blockNumber := big.NewInt(14882318)
	balanceAt, err := client.BalanceAt(context.Background(), account, blockNumber)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(balanceAt)

}
