package main

import (
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	store "github.com/crazygit/ethereum-development-with-go-book-code/contracts"
)

func main() {
	client, err := ethclient.Dial("https://ropsten.infura.io/v3/28d5693e8bee4b58a61f0c627d62331e")
	if err != nil {
		log.Fatal(err)
	}
	// 部署的合约地址
	address := common.HexToAddress("0xDe348Ff064D244e6b983B9198E0bFbb9D4C5CD69")
	instance, err := store.NewStore(address, client)
	if err != nil {
		log.Fatal(err)
	}

	// 查询在合约中设置的Version变量
	version, err := instance.Version(nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Version: %s\n", version)

	key := [32]byte{}
	copy(key[:], "foo")
	result, err := instance.Items(nil, key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s => %s\n", string(key[:]), string(result[:]))
}
