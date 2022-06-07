package main

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"log"
	"os"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	privateKey, err := crypto.HexToECDSA(os.Getenv("PRIVATE_KEY"))
	if err != nil {
		log.Fatal(err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	// 获取字节格式的公钥
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	// 计算原始数据的hash
	data := []byte("hello")
	hash := crypto.Keccak256Hash(data)
	fmt.Printf("hash hex: %s\n", hash.Hex())

	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Signature: %s\n", hexutil.Encode(signature))
	// 从签名信息提取签名使用的公钥信息
	sigPublicKey, err := crypto.Ecrecover(hash.Bytes(), signature)
	if err != nil {
		log.Fatal(err)
	}
	// 比较签名使用的公钥和从私钥导出的公钥是否一致
	matches := bytes.Equal(sigPublicKey, publicKeyBytes)
	fmt.Printf("match: %t\n", matches) // true
	// SigToPub方法做同样的事情，区别是它将返回ECDSA类型中的签名公钥。
	sigPublicKeyECDSA, err := crypto.SigToPub(hash.Bytes(), signature)
	if err != nil {
		log.Fatal(err)
	}

	sigPublicKeyBytes := crypto.FromECDSAPub(sigPublicKeyECDSA)
	matches = bytes.Equal(sigPublicKeyBytes, publicKeyBytes)
	fmt.Printf("match: %t\n", matches) // true

	//为方便起见，go-ethereum/crypto包提供了VerifySignature函数，该函数接收原始数据的签名，哈希值和字节格式的公钥。
	// 它返回一个布尔值，如果公钥与签名的签名者匹配，则为true。
	//一个重要的问题是我们必须首先删除signature的最后一个字节，因为它是ECDSA恢复ID，不能包含它。
	signatureNoRecoverID := signature[:len(signature)-1] // remove recovery id
	verified := crypto.VerifySignature(publicKeyBytes, hash.Bytes(), signatureNoRecoverID)
	fmt.Printf("verified: %t\n", verified) // true
}
