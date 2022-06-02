package main

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"log"
)

func isContractAddress(client *ethclient.Client, address common.Address) (bool, error) {
	bytecode, err := client.CodeAt(context.Background(), address, nil) // nil is latest block
	if err != nil {
		return false, err
	}
	return len(bytecode) > 0, nil
}

func main() {
	// 这里使用cloudflare 提供的gateway作为连接入口，也可以使用infra, alchemy等服务提供的连接
	client, err := ethclient.Dial("https://cloudflare-eth.com")
	if err != nil {
		log.Fatal(err)
	}

	// 0x Protocol Token (ZRX) smart contract address
	address := common.HexToAddress("0xe41d2489571d322189246dafa5ebde1f4699f498")
	if isContract, err := isContractAddress(client, address); err != nil {
		log.Fatal(err)
	} else {
		fmt.Printf("Addess %s is contract: %t\n", address.String(), isContract)
	}
	// a random user account address
	address = common.HexToAddress("0x8e215d06ea7ec1fdb4fc5fd21768f4b34ee92ef4")
	if isContract, err := isContractAddress(client, address); err != nil {
		log.Fatal(err)
	} else {
		fmt.Printf("Addess %s is contract: %t\n", address.String(), isContract)
	}
}
