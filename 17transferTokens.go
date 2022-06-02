package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/crypto/sha3"
	"log"
	"math/big"
	"os"
)

func main() {
	// 0. 初始化客户端
	client, err := ethclient.Dial("https://ropsten.infura.io/v3/28d5693e8bee4b58a61f0c627d62331e")
	if err != nil {
		log.Fatal(err)
	}

	// 1. 加载私钥
	privateKey, err := crypto.HexToECDSA(os.Getenv("PRIVATE_KEY"))
	if err != nil {
		log.Fatal(err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	fmt.Printf("From Address: %s\n", common.HexToAddress(fromAddress.Hex()))
	// 2. 获得账户创建转账交易需要的的随机数nonce
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal(err)
	}

	// 接受转账代币的账户的地址
	toAddress := common.HexToAddress("0x42B44E52b4Fd2dc199048B61c94E19EBec7DBD14")
	// 代币合约地址 https://ropsten.etherscan.io/token/0xc994def97ba4c461933d3e7f88f291ee7f37563c
	tokenAddress := common.HexToAddress("0xc994def97ba4C461933D3e7F88f291ee7F37563C")

	// 3. 计算Data信息
	transferFnSignature := []byte("transfer(address,uint256)")
	hash := sha3.NewLegacyKeccak256()
	hash.Write(transferFnSignature)
	methodID := hash.Sum(nil)[:4]
	fmt.Printf("MethodID: %s\n", hexutil.Encode(methodID))

	paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
	fmt.Printf("paddedAddress: %s\n", hexutil.Encode(paddedAddress))
	amount := new(big.Int)
	amount.SetString("1000000000000000000", 10) // sets the value to 0.1 tokens, in the token denomination

	paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)
	fmt.Printf("paddedAmount: %s\n", hexutil.Encode(paddedAmount))

	var data []byte
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)

	// 转移代币不需要传输ETH，因此将交易"值"设置为"0"。
	value := big.NewInt(0) // in wei (0 eth)
	// 获取估算的gasPrice
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	// 也可以手动设置gasPrice
	//gasPrice := new(big.Int)
	//gasPrice.SetString("1000", 10)
	fmt.Printf("gasPrice: %d\n", gasPrice)
	// 获取估算的gasLimit
	//gasLimit, err := client.EstimateGas(context.Background(), ethereum.CallMsg{
	//	To:   &tokenAddress,
	//	Data: data,
	//})
	//if err != nil {
	//	log.Fatal(err)
	//}

	// 手动设置gasLimit
	gasLimit := uint64(100000)
	fmt.Printf("gasLimit: %d\n", gasLimit) //

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &tokenAddress, // 注意这里是代币的合约地址
		Value:    value,
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     data,
	})
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), privateKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("SendTransaction")
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("tx sent: %s\n", signedTx.Hash().Hex())
	// 转账成功的示例交易可以查看
	// https://ropsten.etherscan.io/tx/0x53b76c8b0ee2fd373b327d4224c1507d7c88e0ac3b9d016660774380cdc5aa17
}
