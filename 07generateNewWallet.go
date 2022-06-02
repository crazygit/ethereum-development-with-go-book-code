package main

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
	"log"
)

func privateKeyToHuman(privateKey *ecdsa.PrivateKey) string {
	// 我们可以通过导入crypto/ecdsa包
	// 并使用FromECDSA方法将其转换为字节。
	privateKeyBytes := crypto.FromECDSA(privateKey)
	// 我们现在可以使用hexutil包将它转换为十六进制字符串，该包提供了一个带有字节切片的Encode方法。
	// 然后我们在十六进制编码之后删除“0x”。
	// 生成的就是用于签署交易的私钥，将被视为密码，永远不应该被共享给别人，因为谁拥有它可以访问你的所有资产。
	return hexutil.Encode(privateKeyBytes)[2:]
}

func publicKeyToHuman1(publicKey *ecdsa.PublicKey) string {
	//	现在我们拥有公钥，就可以轻松生成你经常看到的公共地址。
	//	为了做到这一点，go-ethereum加密包有一个PubkeyToAddress方法，它接受一个ECDSA公钥，并返回公共地址。
	return crypto.PubkeyToAddress(*publicKey).Hex()
}

// publicKeyToHuman2 实际就是publicKeyToHuman1方法中crypto.PubkeyToAddress方法的实现方式
func publicKeyToHuman2(publicKey *ecdsa.PublicKey) string {
	publicKeyBytes := crypto.FromECDSAPub(publicKey)
	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKeyBytes[1:])
	return hexutil.Encode(hash.Sum(nil)[12:])
}

func main() {
	// 要生成一个新的钱包，我们需要导入go-ethereum的crypto包
	// 该包提供用于生成随机私钥的GenerateKey方法。
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Private key: %s\n", privateKeyToHuman(privateKey))

	// 由于公钥是从私钥派生的，因此go-ethereum的加密私钥具有一个返回公钥的Public方法。
	publicKey := privateKey.Public()
	// 将其转换为十六进制的过程与我们使用转化私钥的过程类似
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	fmt.Printf("Public Key: %s\n", publicKeyToHuman1(publicKeyECDSA))
	fmt.Printf("Public Key: %s\n", publicKeyToHuman2(publicKeyECDSA))
}
