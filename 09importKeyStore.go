package main

import (
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	file := "./wallets/UTC--2022-06-01T03-51-52.417968000Z--4705be12a15c870cf451e0853584539c8556b247"
	// 导入的文件会被保存在tmp目录下
	password := "secret"
	importSaveDIr := "./tmp"
	ks := keystore.NewKeyStore(importSaveDIr, keystore.StandardScryptN, keystore.StandardScryptP)
	jsonBytes, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	// 导入的keystore文件时可以通过第三个参数重新设置一个密码，
	// 这里保持密码不变
	account, err := ks.Import(jsonBytes, password, password)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(account.Address.Hex()) // 0x20F8D42FB0F667F2E53930fed426f225752453b3
	// 删除已经被导入的文件
	if err := os.Remove(file); err != nil {
		log.Fatal(err)
	}
}
