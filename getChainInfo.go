package main

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/ethclient"
	"log"
)

func main() {
	// chainID 和networkID是同样的东西
	client, err := ethclient.Dial("https://ropsten.infura.io/v3/28d5693e8bee4b58a61f0c627d62331e")
	if err != nil {
		log.Fatal(err)
	}

	networkID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Network ID: %d\n", networkID)

	chainID, err := client.ChainID(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Chain ID: %d\n", chainID)
}
