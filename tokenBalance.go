package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"log"
	"math/big"
	"net/http"
)

type ethHandlerResult struct {
	Result string `json:"result"`
	Error  struct {
		Code    int64  `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func main() {
	address := "0x42B44E52b4Fd2dc199048B61c94E19EBec7DBD14"         // Account Address here
	contractAddress := "0xc994def97ba4C461933D3e7F88f291ee7F37563C" // Contract address
	data := crypto.Keccak256Hash([]byte("balanceOf(address)")).String()[0:10] + "000000000000000000000000" + address[2:]
	postBody, _ := json.Marshal(map[string]interface{}{
		"id":      1,
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params": []interface{}{
			map[string]string{
				"to":   contractAddress,
				"data": data,
			},
			"latest",
		},
	})
	requestBody := bytes.NewBuffer(postBody)
	resp, err := http.Post("https://ropsten.infura.io/v3/28d5693e8bee4b58a61f0c627d62331e", "application/json", requestBody)
	if err != nil {
		log.Fatal(err)
	}
	ethResult := new(ethHandlerResult)
	if err := json.NewDecoder(resp.Body).Decode(&ethResult); err != nil {
		log.Fatal(err)
	}
	balance := new(big.Int)
	balance.SetString(ethResult.Result[2:], 16)
	fmt.Println(balance)
}
