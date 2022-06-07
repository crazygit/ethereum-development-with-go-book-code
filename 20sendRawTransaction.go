package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"log"
)

func main() {
	client, err := ethclient.Dial("https://ropsten.infura.io/v3/28d5693e8bee4b58a61f0c627d62331e")
	if err != nil {
		log.Fatal(err)
	}
	// 这里是前面createRawTransaction脚本生成的原始交易字符串
	// 可以看到，发送原始交易信息时，不再需要加载私钥和签名了，原始交易字符串里已经包含这些信息了
	rawTx := "f86d8207548455d4a809825208944592d8f8d7b001e72cb26a73e4fa1806a51ac79d880de0b6b3a7640000802aa067b8d876ae5f053fb33beaefec3451dd30086cb8a2f545ae624617ff18aed542a06e0f076b9cbe148bb2c6cbcd052ffd8e94b0da9748bc81ed244adf8509447682"
	rawTxBytes, err := hex.DecodeString(rawTx)

	tx := new(types.Transaction)
	err = rlp.DecodeBytes(rawTxBytes, &tx)
	if err != nil {
		log.Fatal(err)
	}

	err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("tx sent: %s", tx.Hash().Hex())

}
