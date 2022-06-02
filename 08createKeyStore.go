package main

import (
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"log"
)

func main() {
	// 生成keystore文件保存的目录
	saveDir := "./wallets"
	// keystore的密码
	password := "secret"

	ks := keystore.NewKeyStore(saveDir, keystore.StandardScryptN, keystore.StandardScryptP)
	account, err := ks.NewAccount(password)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(account.Address.Hex())
}
