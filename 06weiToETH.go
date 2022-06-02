package main

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"log"
	"math"
	"math/big"
)

func weiToEther(value *big.Int) *big.Float {
	floatValue := new(big.Float)
	floatValue.SetString(value.String())
	return new(big.Float).Quo(floatValue, big.NewFloat(math.Pow10(18)))
}

func main() {
	client, err := ethclient.Dial("https://cloudflare-eth.com")
	if err != nil {
		log.Fatal(err)
	}

	account := common.HexToAddress("0x71c7656ec7ab88b098defb751b7401b5f6d8976f")

	// balance in wei
	balance, err := client.BalanceAt(context.Background(), account, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(balance)
	fmt.Println(weiToEther(balance))
}
