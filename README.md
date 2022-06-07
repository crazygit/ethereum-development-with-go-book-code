# ethereum-development-with-go-book 示例代码重写

[ethereum-development-with-go-book](https://goethereumbook.org)是一本介绍使用go语言进行以太坊开发的书籍。
书中详细的介绍了使用go语言进行以太坊开发时的各种使用场景，是一本非常不错的参考书籍。

不过随着`github.com/ethereum/go-ethereum`库的更新，书中部分代码例子的写法已经过时, 也有部分内容介绍是点到即止，没有讲得太详细，比如在解析`Transaction`部分，只介绍了如何解析`Transaction`部分，但是对于`input data`
却没有介绍到。

在学习过程中,根据书籍的目录结构, 重写了书中的示例，并加上了自己的一些理解，方便后期参考。


# 项目初始化
```shell
$ mkdir -p go-ethereum
$ cd go-ethereum
$ go mod init github.com/crazygit/ethereum-development-with-go-book-code
# 安装go-ethereum SDK，使用当前的最新版本v1.10.18
$ go get github.com/ethereum/go-ethereum@v1.10.18
```

# 客户端
## 初始化客户端
```go
package main

import (
   "fmt"
   "github.com/ethereum/go-ethereum/ethclient"
   "log"
)

func main() {
   // 这里使用cloudflare 提供的gateway作为连接入口，也可以使用infra, alchemy等服务提供的连接
   client, err := ethclient.Dial("https://cloudflare-eth.com")
   if err != nil {
      log.Fatal(err)
   }

   fmt.Println("we have a connection")
   _ = client // we'll use this in the upcoming sections
}
```

### 查询结果异常
不同的provider url在查询数据时，可能存在一些限制。尤其是查询一些归档数据时。比如Infra的

[Introducing A Simplified Infura Plan, With Free Access to Ethereum Archive Data and All Networks](https://blog.infura.io/post/introducing-a-simplified-infura-plan-with-free-access-to-ethereum-archive-data-and-all-network-apis) 。


比如使用`infra`在查询一些较老的block信息时，会报没有权限的错误。

```go
package main

import (
   "context"
   "fmt"
   "github.com/ethereum/go-ethereum/common"
   "github.com/ethereum/go-ethereum/ethclient"
   "log"
   "math/big"
)

func main() {
   client, err := ethclient.Dial("https://mainnet.infura.io/v3/28d5693e8bee4b58a61f0c627d62331e")
   if err != nil {
      log.Fatal(err)
   }

   account := common.HexToAddress("0x71c7656ec7ab88b098defb751b7401b5f6d8976f")

   blockNumber := big.NewInt(14882318)
   balanceAt, err := client.BalanceAt(context.Background(), account, blockNumber)
   if err != nil {
      log.Fatal(err)
   }
   fmt.Println(balanceAt)
}
```
上面的代码会报错
```
403 Forbidden: {"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"project ID does not have access to archive state","data":{"see":"https://infura.io/dashboard"}}}
```

使用`cloudflare`通过交易hash值查询交易信息时，会报查询不到的情况。

```go
package main

import (
   "context"
   "fmt"
   "github.com/ethereum/go-ethereum/common"
   "github.com/ethereum/go-ethereum/ethclient"
   "log"
)

func main() {
   client, err := ethclient.Dial("https://cloudflare-eth.com")
   if err != nil {
      log.Fatal(err)
   }
   txHash := common.HexToHash("0x6ea1993af8b721c56c0ad1f79683f51011d214baeb8fdb575ac4ec00e1eba94e")
   tx, isPending, err := client.TransactionByHash(context.Background(), txHash)
   if err != nil {
      log.Fatal(err)
   }
   fmt.Println(tx.Hash().Hex())
   fmt.Println(isPending)
}
```

上面的查询会报`not found`错误，实际上该交易通过`infra`是可以查询到的。

```
2022/06/01 14:49:23 not found
exit status 1
```

>[!info]
>当查询数据明显感觉结果异常时，切换provider url可能可以解决。

## 账户
### 地址格式转换
在go里面使用以太坊地址时，需要使用把地址转换为`common.Address`类型

```go
package main

import (
   "fmt"
   "github.com/ethereum/go-ethereum/common")

func main() {
   address := common.HexToAddress("0x71c7656ec7ab88b098defb751b7401b5f6d8976f")
   fmt.Println(address.Hex())        // 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
   fmt.Println(address.Hash().Hex()) // 0x00000000000000000000000071c7656ec7ab88b098defb751b7401b5f6d8976f
   fmt.Println(address.Bytes())  // [113 199 101 110 199 171 136 176 152 222 251 117 27 116 1 181 246 216 151 111]
}
```

### 余额查询
使用`BalanceAt`方法查询账户的当前余额
#### 查询最新的余额
`blockNumber`参数设置为`nil`,表示查询当前最新的余额。
```go
package main

import (
   "context"
   "fmt"
   "github.com/ethereum/go-ethereum/common"
   "github.com/ethereum/go-ethereum/ethclient"
   "log"
)

func main() {
   client, err := ethclient.Dial("https://cloudflare-eth.com")
   if err != nil {
      log.Fatal(err)
   }

   account := common.HexToAddress("0x71c7656ec7ab88b098defb751b7401b5f6d8976f")

   balance, err := client.BalanceAt(context.Background(), account, nil)
   if err != nil {
      log.Fatal(err)
   }
   fmt.Println(balance)
}
```

#### 查询指定区块时的余额
可以指定`blockNumber`参数，查询某个区块时的余额

```go
package main

import (
   "context"
   "fmt"
   "github.com/ethereum/go-ethereum/common"
   "github.com/ethereum/go-ethereum/ethclient"
 . "log"
   "math/big"
)

func main() {
   client, err := ethclient.Dial("https://cloudflare-eth.com")
   if err != nil {
      log.Fatal(err)
   }

   account := common.HexToAddress("0x71c7656ec7ab88b098defb751b7401b5f6d8976f")

   // blockNumber的值不能太老，否则会报
   // Invalid Request. Requested data is older than 128 blocks.
   blockNumber := big.NewInt(14882318)
   balanceAt, err := client.BalanceAt(context.Background(), account, blockNumber)
   if err != nil {
      log.Fatal(err)
   }
   fmt.Println(balanceAt)

}
```
#### 查询延迟状态的余额
使用`PendingBalanceAt`方法
```go
package main

import (
   "context"
   "fmt"
   "github.com/ethereum/go-ethereum/common"
   "github.com/ethereum/go-ethereum/ethclient"
   "log"
)

func main() {
   client, err := ethclient.Dial("https://cloudflare-eth.com")
   if err != nil {
      log.Fatal(err)
   }

   account := common.HexToAddress("0x71c7656ec7ab88b098defb751b7401b5f6d8976f")

   pendingBalance, err := client.PendingBalanceAt(context.Background(), account)
   fmt.Println(pendingBalance)
}
```

#### 余额单位转换(wei => ether)
查询的账户都是以`wei`为单位时，看起来不是很方便。
```go
package main

import (
   "context"
   "fmt"
   "github.com/ethereum/go-ethereum/common"
   "github.com/ethereum/go-ethereum/ethclient"
   "log"
   "math"
   "math/big"
)

func weiToEther(value *big.Int) *big.Float {
   floatValue := new(big.Float)
   floatValue.SetString(value.String())
   return new(big.Float).Quo(floatValue, big.NewFloat(math.Pow10(18)))
}

func main() {
   client, err := ethclient.Dial("https://cloudflare-eth.com")
   if err != nil {
      log.Fatal(err)
   }

   account := common.HexToAddress("0x71c7656ec7ab88b098defb751b7401b5f6d8976f")

   // balance in wei
   balance, err := client.BalanceAt(context.Background(), account, nil)
   if err != nil {
      log.Fatal(err)
   }
   fmt.Println(balance)
   fmt.Println(weiToEther(balance))
}
```

### ERC20代币余额查询
代币的余额查询，本质上就是调用代币合约的`balanceOf`方法

```solidity
function balanceOf(address _owner) constant returns (uint balance);
```
在知道Token合约ABI的情况下，可以加载合约的ABI然后直接调用`balanceOf`方法, 实现参考[[#查询ERC20合约]].

另一个做法就是通过网关接口直接查询
```go
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
```
### 钱包

#### 私钥
用下面的方法可以生成私钥，生成的私钥可以导入metamask等钱包直接使用,
导入metamask的方法可以参考[Import using a private key](https://metamask.zendesk.com/hc/en-us/articles/360015489331-How-to-import-an-Account#h_01G01W07NV7Q94M7P1EBD5BYM4)

```go
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
   // 现在我们拥有公钥，就可以轻松生成你经常看到的公共地址。
   // 为了做到这一点，go-ethereum加密包有一个PubkeyToAddress方法，它接受一个ECDSA公钥，并返回公共地址。
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
```
#### KeyStore

[[#直接生成私钥]] 不利于记忆，容易被盗，因此有了KeyStore。Keystore常见于以太坊钱包，它并不是私钥，而是将私钥以加密的方式保存为一份 JSON 文件，这份 JSON 文件就是 keystore，所以它就是加密后的私钥。但是Keystore必须配合钱包密码才能使用该账号，所以只有Keystore文件，并不能掌控账号。对于助记词和私钥就不一样了，只要知道助记词或者私钥就能掌控该账号了。

#####  创建KeyStore

创建的KeyStore Json文件也可以直接导入metamask使用,导入方法可以参考[Import using a JSON](https://metamask.zendesk.com/hc/en-us/articles/360015489331-How-to-import-an-Account#h_01G01W0D3TGE72A7ZBV0FMSZX1)

```go
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
```
上面的命令，会在`wallets`目录下，创建一个KeyStore的json文件，样子如下:
```shell
$ cat wallets/UTC--2022-06-01T03-51-52.417968000Z--4705be12a15c870cf451e0853584539c8556b247|jq
{
  "address": "4705be12a15c870cf451e0853584539c8556b247",
  "crypto": {
    "cipher": "aes-128-ctr",
    "ciphertext": "467ace7bf61b299f478688d6da5cb693825a6ebae4d0187601abe4f2216f0ed9",
    "cipherparams": {
      "iv": "1d9cb4a99d27faff141a01ecfa872056"
    },
    "kdf": "scrypt",
    "kdfparams": {
      "dklen": 32,
      "n": 262144,
      "p": 1,
      "r": 8,
      "salt": "1dc63a3883d6c61b70f504e55659495ecfee6b0ad0819dd2933386a26bb39d32"
    },
    "mac": "e182afb01c021f83cd4004459c2bb6ba17b7d22a646e3654ed124eb427f39123"
  },
  "id": "8f3e43e2-42e4-4bf0-b7ab-7e643a389ad7",
  "version": 3
}
```


##### 导入KeyStore文件
```go
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
   password := "secret"
   // 导入的文件会被保存在tmp目录下
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
```

#### 助记词
私钥是64位长度的十六进制的字符，不利于记录且容易记错，所以用算法将一串随机数转化为了一串12 ~ 24个容易记住的单词，方便保存记录。所以有的同学有了下面的结论：

-   助记词是私钥的另一种表现形式。
-   还有同学说助记词=私钥，这是不正确的说法，**通过助记词可以获取相关联的多个私钥**，但是通过其中一个私钥是不能获取助记词的，因此**助记词≠私钥**。

##### BIP

要弄清楚助记词与私钥的关系，得清楚BIP协议，是`Bitcoin Improvement Proposals`的缩写，意思是Bitcoin 的改进建议，用于提出 Bitcoin 的新功能或改进措施。BIP协议衍生了很多的版本，主要有BIP32、BIP39、BIP44。

##### HD钱包

通过BIP协议生成账号的钱包叫做HD钱包。这个HD钱包，并不是`Hardware Wallet`硬件钱包，这里的 HD 是`Hierarchical Deterministic`的缩写，意思是分层确定性，所以HD钱包的全称为比特币分成确定性钱包 。

使用库[go-ethereum-hdwallet](https://github.com/miguelmota/go-ethereum-hdwallet) 可以创建HD钱包

### 地址验证
#### 账户地址有效性验证
可以使用正则表达式，简单验证一个地址是否有效

```go
package main

import (
   "fmt"
   "regexp"
)

func main() {
   re := regexp.MustCompile("^0x[0-9a-fA-F]{40}$")

   fmt.Printf("is valid: %v\n", re.MatchString("0x323b5d4c32345ced77393b3530b1eed0f346429d")) // is valid: true
   fmt.Printf("is valid: %v\n", re.MatchString("0xZYXb5d4c32345ced77393b3530b1eed0f346429d")) // is valid: false
}
```

#### 合约地址验证
若在该地址存储了字节码，该地址是智能合约

```go
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
```

## 交易
### 区块信息查询

#### 区块头信息

使用`HeaderByNumber()`函数查询区块的头信息

```go
package main

import (
   "context"
   "fmt"
   "github.com/ethereum/go-ethereum/ethclient"
   "log"
)

func main() {
   client, err := ethclient.Dial("https://cloudflare-eth.com")
   if err != nil {
      log.Fatal(err)
   }

   // 第二个参数nil，表示返回最新的区块头信息
   header, err := client.HeaderByNumber(context.Background(), nil)
   if err != nil {
      log.Fatal(err)
   }

   fmt.Printf("Block Number: %s\n", header.Number.String())
   fmt.Printf("Block Time: %d\n", header.Time)
   fmt.Printf("Block Difficulty: %d\n", header.Difficulty)
   fmt.Printf("Block GasUsed: %d\n", header.GasUsed)
   fmt.Printf("Block GasLimit: %d\n", header.GasLimit)
}
```
#### 整个区块的信息
使用`BlockByNumber()`函数查询整个区块的信息
```go
package main

import (
   "context"
   "fmt"
   "github.com/ethereum/go-ethereum/ethclient"
   "log"
   "math/big"
)

func main() {
   client, err := ethclient.Dial("https://cloudflare-eth.com")
   if err != nil {
      log.Fatal(err)
   }

   blockNumber := big.NewInt(14883178)
   // 第二个参数nil，表示返回最新的区块信息
   block, err := client.BlockByNumber(context.Background(), blockNumber)
   if err != nil {
      log.Fatal(err)
   }

   fmt.Printf("Block Number: %s\n", block.Number())
   fmt.Printf("Block Time: %d\n", block.Time())
   fmt.Printf("Block Difficulty: %d\n", block.Difficulty())
   fmt.Printf("Block GasUsed: %d\n", block.GasUsed())
   fmt.Printf("Block GasLimit: %d\n", block.GasLimit())
   // 查询区块上交易的数目
   fmt.Printf("Block Transactions Count: %d\n", len(block.Transactions()))
   // 另一种查询区块交易数目的方法
   count, err := client.TransactionCount(context.Background(), block.Hash())
   if err != nil {
      log.Fatal(err)
   }

   fmt.Printf("Block Transactions Count: %d\n", count)
}
```

### 交易信息查询

交易的查询有三种方式：

- 遍历`block`的`transactions`来获取交易信息
- 通过`transcation`在`block`中的索引来获取交易信息
- 通过交易的hash值来查询交易信息

```go
package main

import (
   "context"
   "fmt"
   "github.com/ethereum/go-ethereum/common"
   "github.com/ethereum/go-ethereum/ethclient"
   "log"
   "math/big"
)

// queryTransactionsByBlock 遍历区块中的所有交易信息
func queryTransactionsByBlock(client *ethclient.Client) {
   blockNumber := big.NewInt(14883178)
   // 第二个参数nil，表示返回最新的区块信息
   block, err := client.BlockByNumber(context.Background(), blockNumber)
   if err != nil {
      log.Fatal(err)
   }

   for _, transaction := range block.Transactions() {
      fmt.Printf("Transcation: %s\n", transaction.Hash().Hex())
   }
}

// queryTransactionByIndexInBlock 通过TransactionInBlock方法根据交易索引位置查询交易信息
func queryTransactionByIndexInBlock(client *ethclient.Client) {
   blockHash := common.HexToHash("0x9e8751ebb5069389b855bba72d94902cc385042661498a415979b7b6ee9ba4b9")
   count, err := client.TransactionCount(context.Background(), blockHash)
   if err != nil {
      log.Fatal(err)
   }

   for idx := uint(0); idx < count; idx++ {
      tx, err := client.TransactionInBlock(context.Background(), blockHash, idx)
      if err != nil {
         log.Fatal(err)
      }

      fmt.Printf("Transcation: %s\n", tx.Hash().Hex())
   }
}

// queryTransactionByTransactionHash 通过交易的hash值来查询交易信息
func queryTransactionByTransactionHash(client *ethclient.Client) {
   txHash := common.HexToHash("0x6ea1993af8b721c56c0ad1f79683f51011d214baeb8fdb575ac4ec00e1eba94e")
   tx, isPending, err := client.TransactionByHash(context.Background(), txHash)
   if err != nil {
      log.Fatal(err)
   }

   fmt.Println(tx.Hash().Hex()) // 0x5d49fcaa394c97ec8a9c3e7bd9e8388d420fb050a52083ca52ff24b3b65bc9c2
   fmt.Println(isPending)
}

func main() {
   client, err := ethclient.Dial("https://mainnet.infura.io/v3/28d5693e8bee4b58a61f0c627d62331e")
   if err != nil {
      log.Fatal(err)
   }
   queryTransactionsByBlock(client)
   queryTransactionByIndexInBlock(client)
   queryTransactionByTransactionHash(client)
}
```

### 解析交易信息

需要注意的是:

- 为了获得交易的调用者信息，需要调用交易的`AsMessage`方法，把交易转化为`Message`才可以。具体实现参考下面的`GetTransactionMessage`方法
- 每个交易都有一个收据，其中包含执行交易的结果，例如任何返回值和日志，以及为“1”（成功）或“0”（失败）的事件结果状态。具体实现参考下面的`GetTransactionReceipt`

```go
package main

import (
   "context"
   "encoding/hex"
   "fmt"
   "github.com/ethereum/go-ethereum/accounts/abi"
   "github.com/ethereum/go-ethereum/common"
   "github.com/ethereum/go-ethereum/core/types"
   "github.com/ethereum/go-ethereum/ethclient"
   "github.com/go-resty/resty/v2"
   "log"
   "strings"
)

type (
   RawABIResponse struct {
      Status  *string `json:"status"`
      Message *string `json:"message"`
      Result  *string `json:"result"`
   }
)

func GetContractRawABI(address string, apiKey string) (*RawABIResponse, error) {
   client := resty.New()
   rawABIResponse := &RawABIResponse{}
   resp, err := client.R().
      SetQueryParams(map[string]string{
         "module":  "contract",
         "action":  "getabi",
         "address": address,
         "apikey":  apiKey,
      }).
      SetResult(rawABIResponse).
      Get("https://api-ropsten.etherscan.io/api")

   if err != nil {
      return nil, err
   }
   if !resp.IsSuccess() {
      return nil, fmt.Errorf(fmt.Sprintf("Get contract raw abi failed: %s\n", resp))
   }
   if *rawABIResponse.Status != "1" {
      return nil, fmt.Errorf(fmt.Sprintf("Get contract raw abi failed: %s\n", *rawABIResponse.Result))
   }

   return rawABIResponse, nil
}

// refer
// https://github.com/ethereum/web3.py/blob/master/web3/contract.py#L435
func DecodeTransactionInputData(contractABI *abi.ABI, data []byte) {
   methodSigData := data[:4]
   inputsSigData := data[4:]
   method, err := contractABI.MethodById(methodSigData)
   if err != nil {
      log.Fatal(err)
   }
   inputsMap := make(map[string]interface{})
   if err := method.Inputs.UnpackIntoMap(inputsMap, inputsSigData); err != nil {
      log.Fatal(err)
   } else {
      fmt.Println(inputsMap)
   }
   fmt.Printf("Method Name: %s\n", method.Name)
   fmt.Printf("Method inputs: %v\n", inputsMap)
}

func GetTransactionMessage(tx *types.Transaction) types.Message {
   msg, err := tx.AsMessage(types.LatestSignerForChainID(tx.ChainId()), nil)
   if err != nil {
      log.Fatal(err)
   }
   return msg
}

func ParseTransactionBaseInfo(tx *types.Transaction) {
   fmt.Printf("Hash: %s\n", tx.Hash().Hex())
   fmt.Printf("ChainId: %d\n", tx.ChainId())
   fmt.Printf("Value: %s\n", tx.Value().String())
   fmt.Printf("From: %s\n", GetTransactionMessage(tx).From().Hex())
   fmt.Printf("To: %s\n", tx.To().Hex())
   fmt.Printf("Gas: %d\n", tx.Gas())
   fmt.Printf("Gas Price: %d\n", tx.GasPrice().Uint64())
   fmt.Printf("Nonce: %d\n", tx.Nonce())
   fmt.Printf("Transaction Data in hex: %s\n", hex.EncodeToString(tx.Data()))
}

func DecodeTransactionLogs(receipt *types.Receipt, contractABI *abi.ABI) {
   for _, vLog := range receipt.Logs {
      // topic[0] is the event name
      event, err := contractABI.EventByID(vLog.Topics[0])
      if err != nil {
         log.Fatal(err)
      }
      fmt.Printf("Event Name: %s\n", event.Name)
      // topic[1:] is other indexed params in event
      if len(vLog.Topics) > 1 {
         for i, param := range vLog.Topics[1:] {
            fmt.Printf("Indexed params %d in hex: %s\n", i, param)
            fmt.Printf("Indexed params %d decoded %s\n", i, common.HexToAddress(param.Hex()))
         }
      }
      if len(vLog.Data) > 0 {
         fmt.Printf("Log Data in Hex: %s\n", hex.EncodeToString(vLog.Data))
         outputDataMap := make(map[string]interface{})
         err = contractABI.UnpackIntoMap(outputDataMap, event.Name, vLog.Data)
         if err != nil {
             log.Fatal(err)
         }
         fmt.Printf("Event outputs: %v\n", outputDataMap)
      }
   }
}

func GetContractABI(contractAddress, etherscanAPIKey string) *abi.ABI {
   rawABIResponse, err := GetContractRawABI(contractAddress, etherscanAPIKey)
   if err != nil {
      log.Fatal(err)
   }

   contractABI, err := abi.JSON(strings.NewReader(*rawABIResponse.Result))
   if err != nil {
      log.Fatal(err)
   }
   return &contractABI
}

func GetTransactionReceipt(client *ethclient.Client, txHash common.Hash) *types.Receipt {
   receipt, err := client.TransactionReceipt(context.Background(), txHash)
   if err != nil {
      log.Fatal(err)
   }
   return receipt
}

func main() {
   // get etherscanAPIKEY from https://docs.etherscan.io/getting-started/viewing-api-usage-statistics
   const etherscanAPIKEY = "M3SF4WTDC4NWQIIVNAZDFXBW1SW49QWDNZ"
   const providerUrl = "https://ropsten.infura.io/v3/28d5693e8bee4b58a61f0c627d62331e"

   client, err := ethclient.Dial(providerUrl)
   if err != nil {
      log.Fatal(err)
   }
   // https://ropsten.etherscan.io/tx/0x7e605f68ff30509eb2bf3238936ef65a01bfa25243488c007244aabe645d0ec9
   txHash := common.HexToHash("0x7e605f68ff30509eb2bf3238936ef65a01bfa25243488c007244aabe645d0ec9")
   tx, isPending, err := client.TransactionByHash(context.Background(), txHash)
   if err != nil {
      log.Fatal(err)
   }
   fmt.Printf("tx isPending: %t\n", isPending)
   ParseTransactionBaseInfo(tx)
   contractABI := GetContractABI(tx.To().String(), etherscanAPIKEY)
   DecodeTransactionInputData(contractABI, tx.Data())
   // 每个事务都有一个收据，其中包含执行事务的结果，例如任何返回值和日志，以及为“1”（成功）或“0”（失败）的事件结果状态。
   receipt := GetTransactionReceipt(client, txHash)
   fmt.Printf("receipt status: %d", receipt.Status)
   DecodeTransactionLogs(receipt, contractABI)
}
```

### ETH转账
转账分为如下几个步骤
0. 初始化客户端
1. 加载私钥
2. 获得账户创建转账交易需要的的随机数nonce
3. 设置转账交易信息，比如转账的数量，gasLimit, gasPrice，可选的Data信息等。gasPrice可以从链上获取建议的`client.SuggestGasPrice()`, gasLimit也可以从链上获取建议`client.EstimateGas()`。需要注意的是: **估算的值仅做参考，不代表估算的值一定适用**
4. 使用私钥对转账交易签名
5. 发布交易

```go
package main

import (
   "context"
   "crypto/ecdsa"
   "fmt"
   "github.com/ethereum/go-ethereum"
   "log"
   "math/big"
   "os"
   "github.com/ethereum/go-ethereum/common"
   "github.com/ethereum/go-ethereum/core/types"
   "github.com/ethereum/go-ethereum/crypto"
   "github.com/ethereum/go-ethereum/ethclient"
)

func main() {
   //0. 初始化客户端
   client, err := ethclient.Dial("https://ropsten.infura.io/v3/28d5693e8bee4b58a61f0c627d62331e")
   if err != nil {
      log.Fatal(err)
   }

   // 1. 加载私钥
   privateKey, err := crypto.HexToECDSA(os.Getenv("PRIVATE_KEY"))
   if err != nil {
      log.Fatal(err)
   }

   //之后我们需要获得帐户的随机数(nonce)。 每笔交易都需要一个nonce。 根据定义，nonce是仅使用一次的数字。 如果是发送交易的新帐户，则该随机数将为“0”。
   //来自帐户的每个新事务都必须具有前一个nonce增加1的nonce。很难对所有nonce进行手动跟踪，
   //于是ethereum客户端提供一个帮助方法PendingNonceAt，它将返回你应该使用的下一个nonce。
   //该函数需要我们发送的帐户的公共地址 - 这个我们可以从私钥派生。
   publicKey := privateKey.Public()
   publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
   if !ok {
      log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
   }

   fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
   fmt.Printf("from address: %s\n", common.HexToAddress(fromAddress.Hash().Hex()))
   toAddress := common.HexToAddress("0xf1EEfEE62A8651c3772cd8D7ba9031b7029316f7")
   fmt.Printf("to address: %s\n", common.HexToAddress(toAddress.Hash().Hex()))
   // 2. 获得账户创建转账交易需要的的随机数nonce
   nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
   if err != nil {
      log.Fatal(err)
   }
   fmt.Printf("nonce: %d\n", nonce)
   // 3. 设置转账交易信息
   // 转账1ETH
   value := big.NewInt(1000000000000000000) // in wei (1 eth)
   var data []byte
   //手动设置ETH转账的燃气应设上限为"40000”单位
   //gasLimit := uint64(40000) // in units
   //   // 也可根据Data估算的gasLimit
   gasLimit, err := client.EstimateGas(context.Background(), ethereum.CallMsg{
      To:   &toAddress,
      Data: data,
   })
   if err != nil {
      log.Fatal(err)
   }
   // 燃气价格总是根据市场需求和用户愿意支付的价格而波动的，因此对燃气价格进行硬编码有时并不理想。
   // go-ethereum客户端提供SuggestGasPrice函数，用于根据'x'个先前块来获得平均燃气价格。
   gasPrice, err := client.SuggestGasPrice(context.Background())
   if err != nil {
      log.Fatal(err)
   }
   fmt.Printf("SuggestGasPrice: %d\n", gasPrice)

   tx := types.NewTx(&types.LegacyTx{
      Nonce:    nonce,
      To:       &toAddress,
      Value:    value,
      Gas:      gasLimit,
      GasPrice: gasPrice,
      Data:     data,
   })
   //下一步是使用发件人的私钥对事务进行签名。 为此，我们调用SignTx方法，该方法接受一个未签名的事务和我们之前构造的私钥。
   // SignTx方法需要EIP155签名者，这个也需要我们先从客户端拿到链ID。
   chainID, err := client.NetworkID(context.Background())
   if err != nil {
      log.Fatal(err)
   }
   // 4. 使用私钥对转账交易签名
   signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), privateKey)
   if err != nil {
      log.Fatal(err)
   }
   // 5. 发布交易
   err = client.SendTransaction(context.Background(), signedTx)
   if err != nil {
      log.Fatal(err)
   }

   fmt.Printf("tx sent: %s\n", signedTx.Hash().Hex())
}
```

### ERC-20代币转账
ERC-20代币转账的方式跟ETH转账的方式类似。不同的在于2点:
1. 交易的接受地址为代币的合约地址
2. 转账的信息是通过`data`形式来体现，即在交易的`data`字段里设置要调用代币合约的`transfer(address,uint256)`方法以及接受转账的账户地址信息来实现。

```go
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
   // 代币合约地址 https://ropsten.etherscan.io/token/0xc994def97ba4c461933d3e7f88f291ee7f37563c   tokenAddress := common.HexToAddress("0xc994def97ba4C461933D3e7F88f291ee7F37563C")

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
   // To:   &tokenAddress,
   // Data: data,
   //})
   //if err != nil {
   // log.Fatal(err)
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
```

### 订阅新区块的信息
需要使用`websocket`形式的provider url,然后通过`client.SubscribeNewHead()`方法订阅新区块的信息

```go
package main

import (
   "context"
   "fmt"
   "log"
   "github.com/ethereum/go-ethereum/core/types"
   "github.com/ethereum/go-ethereum/ethclient"
)


func main() {
   client, err := ethclient.Dial("wss://mainnet.infura.io/ws/v3/28d5693e8bee4b58a61f0c627d62331e")
   if err != nil {
      log.Fatal(err)
   }

   headers := make(chan *types.Header)
   sub, err := client.SubscribeNewHead(context.Background(), headers)
   if err != nil {
      log.Fatal(err)
   }

   for {
      select {
      case err := <-sub.Err():
         log.Fatal(err)
      case header := <-headers:
         fmt.Printf("Header Hash: %s\n", header.Hash().Hex())

         block, err := client.BlockByHash(context.Background(), header.Hash())
         if err != nil {
            log.Fatal(err)
         }

         fmt.Printf("Block Hash: %s\n", block.Hash().Hex())
         fmt.Printf("Block Number: %d\n", block.Number().Uint64())
         fmt.Printf("Block Time: %d\n", block.Time())
         fmt.Printf("Block None:%d\n", block.Nonce())
         fmt.Printf("TTransactions Numbers: %d", len(block.Transactions()))
      }
   }
}
```


### 创建原始交易的字符串
与发送交易的流程一样的，加载私钥，设置交易信息，签名。只是最后一步不是发送交易，而是把交易转换成了十六进制的字符串。

```go
package main

import (
   "bytes"
   "context"
   "crypto/ecdsa"
   "encoding/hex"
   "fmt"
   "log"
   "math/big"
   "os"
   "github.com/ethereum/go-ethereum/common"
   "github.com/ethereum/go-ethereum/core/types"
   "github.com/ethereum/go-ethereum/crypto"
   "github.com/ethereum/go-ethereum/ethclient"
)

func main() {
   client, err := ethclient.Dial("https://ropsten.infura.io/v3/28d5693e8bee4b58a61f0c627d62331e")
   if err != nil {
      log.Fatal(err)
   }

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
   nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
   if err != nil {
      log.Fatal(err)
   }

   value := big.NewInt(1000000000000000000) // in wei (1 eth)
   gasLimit := uint64(21000)                // in units
   gasPrice, err := client.SuggestGasPrice(context.Background())
   if err != nil {
      log.Fatal(err)
   }

   toAddress := common.HexToAddress("0x4592d8f8d7b001e72cb26a73e4fa1806a51ac79d")
   var data []byte
   tx := types.NewTx(&types.LegacyTx{
      Nonce:    nonce,
      To:       &toAddress,
      Value:    value,
      Gas:      gasLimit,
      GasPrice: gasPrice,
      Data:     data,
   })

   chainID, err := client.NetworkID(context.Background())
   if err != nil {
      log.Fatal(err)
   }

   signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
   if err != nil {
      log.Fatal(err)
   }

   ts := types.Transactions{signedTx}
   b := new(bytes.Buffer)
   ts.EncodeIndex(0, b)
   rawTxBytes := b.Bytes()
   rawTxHex := hex.EncodeToString(rawTxBytes)

   fmt.Printf(rawTxHex) // f86...772
}
```

### 发送原始交易的字符串

上面发送的交易字符串，可以直接发送，不再需要私钥信息了，使用方式上来讲，也算是对私钥的一种保护吧。

```go
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
```

## 智能合约

### 编写合约和生成ABI文件

#### 安装solidity编译器

```shell
brew update
brew tap ethereum/ethereum
brew install solidity
```

为了调用合约，需要安装`abigen`工具，将合约的ABI信息转换为可以在go语言里使用的格式。


#### 安装abigen


##### 直接安装geth
一般情况下，如果只是使用命令行工具，可以直接通过

```shell
$ brew tap ethereum/ethereum
$ brew install ethereum
```
安装即可，安装好之后。在`/usr/local/bin/`目录下，便有了
* `abigen`
* `bootnode`
* `checkpoint-admin`
* `clef`
* `devp2p`
* `ethkey`
* `evm`
* `faucet`
* `geth`
* `p2psim`
* `puppeth`
* `rlpdump`
* `wnode`

命令可用。每个命令的作用可以参考[这里](https://github.com/ethereum/go-ethereum#executab

##### 从源码安装

开发时，为了使用`go-ethereum`中的代码，我们需要从源码安装

```bash
$ go get -d github.com/ethereum/go-ethereum
```

上面的命令只会将`go-ethereum`的代码安装到本地，并不会自动安装`github.com/ethereum/go-ethereum/cmd`目录下的各种命令行工具。

可以使用下面的命令单独安装一个命令行工具`geth`

```bash
$ go install github.com/ethereum/go-ethereum/cmd/geth
```

也可先进入到`$GOPATH`的工作空间`$HOME/go/pkg/mod/github.com/ethereum/go-ethereum@v1.10.18`目录下，然后执行如下命令安装所有`github.com/ethereum/go-ethereum/cmd`目录下命令工具。

```bash
# 这里 ./... 表示安装当前目录ethereum/go-ethereum以及当前目录ethereum/go-ethereum下的所有目录的工具
$ go install ./...
```

#### 创建合约

```shell
$ mkdir contracts
$ cd contracts
```

变现一个测试合约`Store.sol`

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.4.16 <0.9.0;

contract Store {
    event ItemSet(bytes32 key, bytes32 value);

    string public version;
    mapping (bytes32 => bytes32) public items;

    constructor(string memory _version) {
        version = _version;
    }

    function setItem(bytes32 key, bytes32 value) external {
        items[key] = value;
        emit ItemSet(key, value);
    }
}
```

在`build`目录下生成`Store.abi`文件和十六进制格式的二进制文件`Store.bin`

```shell
$ solc --abi --bin Store.sol -o build
$ cd build
$ ls
Store.abi  Store.bin
```
使用`abigen`生成可以在go程序里直接使用的`Store.go`文件

```shell
$ abigen --bin=./build/Store.bin --abi=./build/Store.abi --pkg=store --out=Store.go
```

生成的`Store.go`文件里包含了`abi`信息和合约的二进制信息。

### 部署合约
部署合约的流程如下:
1. 加载私钥
2. 使用`bind.NewKeyedTransactorWithChainID`生成交易选项然后
3. 直接使用前面通过`abigen`生成的`Store.go`文件里的`DeployStore()`方法即可部署合约。

>[!info]
> 1. 通过abigen生成部署合约的方法都是以`Deploy` + `合约名`的形式
> 2. 合约地址在没有部署成功的时候就已经生成了，并不是部署完才有合约地址

```go
package main

import (
   "context"
   "crypto/ecdsa"
   "fmt"
   "log"
   "math/big"
   "os"
   "github.com/ethereum/go-ethereum/accounts/abi/bind"
   "github.com/ethereum/go-ethereum/crypto"
   "github.com/ethereum/go-ethereum/ethclient"
   store "github.com/crazygit/ethereum-development-with-go-book-code/contracts"
)

func main() {
   client, err := ethclient.Dial("https://ropsten.infura.io/v3/28d5693e8bee4b58a61f0c627d62331e")
   if err != nil {
      log.Fatal(err)
   }

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
   nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
   if err != nil {
      log.Fatal(err)
   }

   gasPrice, err := client.SuggestGasPrice(context.Background())
   if err != nil {
      log.Fatal(err)
   }
   chainID, err := client.ChainID(context.Background())
   if err != nil {
      log.Fatal(err)
   }
   auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
   if err != nil {
      log.Fatal(err)
   }
   auth.Nonce = big.NewInt(int64(nonce))
   auth.Value = big.NewInt(0)      // in wei
   auth.GasLimit = uint64(1000000) // in units
   auth.GasPrice = gasPrice

   input := "1.0"
   // 部署合约的方法名称始终以单词Deploy开头，后跟合约名称，在本例中为Store
   address, tx, instance, err := store.DeployStore(auth, client, input)
   if err != nil {
      log.Fatal(err)
   }

   fmt.Printf("Contract Address: %s\n", address.Hex())
   fmt.Printf("Transaction Hash: %s\n", tx.Hash().Hex())

   _ = instance
}
```

### 加载合约

在拥有合约的`abi`文件和合约地址的情况下，可以直接使用`New<ContractName>`加载合约

```go
package main

import (
   "fmt"
   "log"
   "github.com/ethereum/go-ethereum/common"   "github.com/ethereum/go-ethereum/ethclient"
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

   fmt.Println("contract is loaded")
   _ = instance
}
```

### 查询合约
合约加载之后，就可以调用`abi`里的相关方法来查询合约信息了。比如查询合约里之前设置的`version`变量和`items`信息

```go
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
```

### 写入智能合约

跟部署合约类似，先记载私钥，然后使用`bind.NewKeyedTransactorWithChainID()`方法完成发起交易的相关信息，最后调用abi文件`Store.go`里的`SetItem()`方法来修改合约的`items`变量。

```go
package main

import (
   "context"
   "crypto/ecdsa"
   "fmt"
   "github.com/ethereum/go-ethereum/crypto"
   "log"
   "math/big"
   "os"
   "github.com/ethereum/go-ethereum/accounts/abi/bind"
   "github.com/ethereum/go-ethereum/common"
   "github.com/ethereum/go-ethereum/ethclient"
   store "github.com/crazygit/ethereum-development-with-go-book-code/contracts"
)

func main() {
   client, err := ethclient.Dial("https://ropsten.infura.io/v3/28d5693e8bee4b58a61f0c627d62331e")
   if err != nil {
      log.Fatal(err)
   }

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
   nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
   if err != nil {
      log.Fatal(err)
   }

   gasPrice, err := client.SuggestGasPrice(context.Background())
   if err != nil {
      log.Fatal(err)
   }
   chainID, err := client.ChainID(context.Background())
   if err != nil {
      log.Fatal(err)
   }
   auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
   auth.Nonce = big.NewInt(int64(nonce))
   auth.Value = big.NewInt(0)      // in wei
   auth.GasLimit = uint64(1000000) // in units
   auth.GasPrice = gasPrice
   address := common.HexToAddress("0xDe348Ff064D244e6b983B9198E0bFbb9D4C5CD69")  // 部署的合约地址
   instance, err := store.NewStore(address, client)
   if err != nil {
      log.Fatal(err)
   }

   key := [32]byte{}
   value := [32]byte{}
   copy(key[:], "foo")
   copy(value[:], "bar")

   tx, err := instance.SetItem(auth, key, value)
   if err != nil {
      log.Fatal(err)
   }

   fmt.Printf("tx sent: %s\n", tx.Hash().Hex())

   result, err := instance.Items(nil, key)
   if err != nil {
      log.Fatal(err)
   }

   fmt.Println(string(result[:])) // "bar"
}
```

### 读取合约的字节码信息

使用`client.CodeAt()`方法,可以直接读取合约的字节码信息

```go
package main

import (
   "context"
   "encoding/hex"
   "fmt"
   "log"
   "github.com/ethereum/go-ethereum/common"
   "github.com/ethereum/go-ethereum/ethclient"
)

func main() {
   client, err := ethclient.Dial("https://ropsten.infura.io/v3/28d5693e8bee4b58a61f0c627d62331e")
   if err != nil {
      log.Fatal(err)
   }
   // 部署的合约地址
   contractAddress := common.HexToAddress("0xDe348Ff064D244e6b983B9198E0bFbb9D4C5CD69")
   bytecode, err := client.CodeAt(context.Background(), contractAddress, nil) // nil is latest block
   if err != nil {
      log.Fatal(err)
   }

   fmt.Println(hex.EncodeToString(bytecode))
}
```

### 查询ERC20合约

所有的ERC20合约都实现了同样的一些方法，因此为了查询ERC20合约，我们只需要定义一个ERC20接口，生成ABI文件就可以使用了.
```shell
$ mkdir contracts_erc20
$ cd contracts_erc20
```

创建`erc20.sol`.  也可以直接使用[openzeppelin](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/IERC20.sol) 的定义

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.4.16 <0.9.0;


interface ERC20 {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);

    function totalSupply() external view returns (uint);
    function balanceOf(address tokenOwner) external view returns (uint balance);
    function allowance(address tokenOwner, address spender) external view returns (uint remaining);
    function transfer(address to, uint tokens) external returns (bool success);
    function approve(address spender, uint tokens) external returns (bool success);
    function transferFrom(address from, address to, uint tokens) external returns (bool success);

    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
}
```

编译生成可以让go使用的文件

```shell
$ solc --abi erc20.sol -o build
$ abigen --abi=./build/ERC20.abi --pkg=token --out=erc20.go
```

然后使用生成的`erc20.go`可以直接读取所有的ERC20合约

```go
package main

import (
   "fmt"
   "github.com/ethereum/go-ethereum/accounts/abi/bind"
   "github.com/ethereum/go-ethereum/common"
   "github.com/ethereum/go-ethereum/ethclient"
   "log"
   "math"
   "math/big"
   "strconv"
   token "github.com/crazygit/ethereum-development-with-go-book-code/contracts_erc20"
)

func main() {
   client, err := ethclient.Dial("https://cloudflare-eth.com")
   if err != nil {
      log.Fatal(err)
   }

   // Golem (GNT) Address
   tokenAddress := common.HexToAddress("0xa74476443119A942dE498590Fe1f2454d7D4aC0d")
   instance, err := token.NewToken(tokenAddress, client)
   if err != nil {
      log.Fatal(err)
   }

   address := common.HexToAddress("0x0536806df512d6cdde913cf95c9886f65b1d3462")
   bal, err := instance.BalanceOf(&bind.CallOpts{}, address)
   if err != nil {
      log.Fatal(err)
   }

   name, err := instance.Name(&bind.CallOpts{})
   if err != nil {
      log.Fatal(err)
   }

   symbol, err := instance.Symbol(&bind.CallOpts{})
   if err != nil {
      log.Fatal(err)
   }

   decimals, err := instance.Decimals(&bind.CallOpts{})
   if err != nil {
      log.Fatal(err)
   }

   fmt.Printf("name: %s\n", name)         // "name: Golem Network"
   fmt.Printf("symbol: %s\n", symbol)     // "symbol: GNT"
   fmt.Printf("decimals: %v\n", decimals) // "decimals: 18"

   fmt.Printf("wei: %s\n", bal)

   fbal := new(big.Float)
   fbal.SetString(bal.String())
   n, err := strconv.Atoi(decimals.String())
   if err != nil {
      log.Fatal(err)
   }
   value := new(big.Float).Quo(fbal, big.NewFloat(math.Pow10(n)))

   fmt.Printf("balance: %f", value)
}
```


## 事件日志
与[[#订阅新区块的信息]] 一样，订阅事件日志还是需要使用`websocket`连接。

下面分步骤介绍了解析事件日志，完整的例子可以参考[[#解析交易信息]]
### 订阅日志事件
使用 `client.SubscribeFilterLogs()` 订阅日志事件
也可以使用`client.FilterLogs()`一次性查询日志事件。

订阅和查询条件都是通过`ethereum.FilterQuery()`来设置的。

```go
package main

import (
   "context"
   "fmt"
   "log"
   "github.com/ethereum/go-ethereum"
   "github.com/ethereum/go-ethereum/common"
   "github.com/ethereum/go-ethereum/core/types"
   "github.com/ethereum/go-ethereum/ethclient"
)

func main() {
   client, err := ethclient.Dial("wss://mainnet.infura.io/ws/v3/28d5693e8bee4b58a61f0c627d62331e")
   if err != nil {
      log.Fatal(err)
   }

   contractAddress := common.HexToAddress("0xf1EEfEE62A8651c3772cd8D7ba9031b7029316f7")
   // 设置日志过滤条件
   query := ethereum.FilterQuery{
      Addresses: []common.Address{contractAddress},
   }

   logs := make(chan types.Log)
   // 也可以使用 client.FilterLogs根据过滤条件来查询日志
   sub, err := client.SubscribeFilterLogs(context.Background(), query, logs)
   if err != nil {
      log.Fatal(err)
   }

   for {
      select {
      case err := <-sub.Err():
         log.Fatal(err)
      case vLog := <-logs:
         fmt.Println(vLog) // pointer to event log
      }
   }
}
```

### 解析日志事件
解析日志事件需要使用合约的ABI信息。加载ABI信息后，使用
`contractAbi.UnpackIntoInterface()`来解析日志的数据。

#### 主题(Topics)

若solidity事件包含`indexed`事件类型，那么它们将成为**主题**而不是日志的数据属性的一部分。在solidity中您最多只能有4个主题，但只有3个可索引的事件类型。第一个主题总是事件的签名。

```go
package main

import (
   "context"
   "fmt"
   "log"
   "math/big"
   "strings"
   "github.com/ethereum/go-ethereum"
   "github.com/ethereum/go-ethereum/accounts/abi"
   "github.com/ethereum/go-ethereum/common"
   "github.com/ethereum/go-ethereum/crypto"
   "github.com/ethereum/go-ethereum/ethclient"
   store "github.com/crazygit/ethereum-development-with-go-book-code/contracts"
)

func main() {
   client, err := ethclient.Dial("wss://rinkeby.infura.io/ws/v3/28d5693e8bee4b58a61f0c627d62331e")
   if err != nil {
      log.Fatal(err)
   }

   contractAddress := common.HexToAddress("0x147B8eb97fD247D06C4006D269c90C1908Fb5D54")
   // 查询指定区块的日志
   query := ethereum.FilterQuery{
      FromBlock: big.NewInt(2394201),
      ToBlock:   big.NewInt(2394201),
      Addresses: []common.Address{
         contractAddress,
      },
   }
   //
   logs, err := client.FilterLogs(context.Background(), query)
   if err != nil {
      log.Fatal(err)
   }

   contractAbi, err := abi.JSON(strings.NewReader(store.StoreMetaData.ABI))
   if err != nil {
      log.Fatal(err)
   }

   for _, vLog := range logs {
      fmt.Println(vLog.BlockHash.Hex()) // 0x3404b8c050aa0aacd0223e91b5c32fee6400f357764771d0684fa7b3f448f1a8
      fmt.Println(vLog.BlockNumber)     // 2394201
      fmt.Println(vLog.TxHash.Hex())    // 0x280201eda63c9ff6f305fcee51d5eb86167fab40ca3108ec784e8652a0e2b1a6

      event := struct {
         Key   [32]byte
         Value [32]byte
      }{}
      err := contractAbi.UnpackIntoInterface(&event, "ItemSet", vLog.Data)
      if err != nil {
         log.Fatal(err)
      }

      fmt.Println(string(event.Key[:]))
      fmt.Println(string(event.Value[:]))

      var topics [4]string
      for i := range vLog.Topics {
         topics[i] = vLog.Topics[i].Hex()
      }

      fmt.Println(topics[0]) // 0xe79e73da417710ae99aa2088575580a60415d359acfad9cdd3382d59c80281d4
   }

   eventSignature := []byte("ItemSet(bytes32,bytes32)")
   hash := crypto.Keccak256Hash(eventSignature)
   fmt.Println(hash.Hex()) // 0xe79e73da417710ae99aa2088575580a60415d359acfad9cdd3382d59c80281d4
}
```

### 解析ERC20合约的日志
跟[[#查询ERC20合约]] 的流程基本一致

```go
package main

import (
   "context"
   "fmt"
   "log"
   "math/big"
   "strings"
   token "github.com/crazygit/ethereum-development-with-go-book-code/contracts_erc20"
   "github.com/ethereum/go-ethereum"
   "github.com/ethereum/go-ethereum/accounts/abi"
   "github.com/ethereum/go-ethereum/common"
   "github.com/ethereum/go-ethereum/crypto"
   "github.com/ethereum/go-ethereum/ethclient"
)

// LogTransfer ..type LogTransfer struct {
   From   common.Address
   To     common.Address
   Tokens *big.Int
}

// LogApproval ..type LogApproval struct {
   TokenOwner common.Address
   Spender    common.Address
   Tokens     *big.Int
}

func main() {
   client, err := ethclient.Dial("https://mainnet.infura.io/v3/28d5693e8bee4b58a61f0c627d62331e")
   if err != nil {
      log.Fatal(err)
   }

   // 0x Protocol (ZRX) token address
   contractAddress := common.HexToAddress("0xe41d2489571d322189246dafa5ebde1f4699f498")
   query := ethereum.FilterQuery{
      FromBlock: big.NewInt(6383820),
      ToBlock:   big.NewInt(6383840),
      Addresses: []common.Address{
         contractAddress,
      },
   }

   logs, err := client.FilterLogs(context.Background(), query)
   if err != nil {
      log.Fatal(err)
   }

   contractAbi, err := abi.JSON(strings.NewReader(string(token.TokenMetaData.ABI)))
   if err != nil {
      log.Fatal(err)
   }

   logTransferSig := []byte("Transfer(address,address,uint256)")
   LogApprovalSig := []byte("Approval(address,address,uint256)")
   logTransferSigHash := crypto.Keccak256Hash(logTransferSig)
   logApprovalSigHash := crypto.Keccak256Hash(LogApprovalSig)

   for _, vLog := range logs {
      fmt.Printf("Log Block Number: %d\n", vLog.BlockNumber)
      fmt.Printf("Log Index: %d\n", vLog.Index)

      switch vLog.Topics[0].Hex() {
      case logTransferSigHash.Hex():
         fmt.Printf("Log Name: Transfer\n")

         var transferEvent LogTransfer

         err := contractAbi.UnpackIntoInterface(&transferEvent, "Transfer", vLog.Data)
         if err != nil {
            log.Fatal(err)
         }

         transferEvent.From = common.HexToAddress(vLog.Topics[1].Hex())
         transferEvent.To = common.HexToAddress(vLog.Topics[2].Hex())

         fmt.Printf("From: %s\n", transferEvent.From.Hex())
         fmt.Printf("To: %s\n", transferEvent.To.Hex())
         fmt.Printf("Tokens: %s\n", transferEvent.Tokens.String())

      case logApprovalSigHash.Hex():
         fmt.Printf("Log Name: Approval\n")

         var approvalEvent LogApproval

         err := contractAbi.UnpackIntoInterface(&approvalEvent, "Approval", vLog.Data)
         if err != nil {
            log.Fatal(err)
         }

         approvalEvent.TokenOwner = common.HexToAddress(vLog.Topics[1].Hex())
         approvalEvent.Spender = common.HexToAddress(vLog.Topics[2].Hex())

         fmt.Printf("Token Owner: %s\n", approvalEvent.TokenOwner.Hex())
         fmt.Printf("Spender: %s\n", approvalEvent.Spender.Hex())
         fmt.Printf("Tokens: %s\n", approvalEvent.Tokens.String())
      }

      fmt.Printf("\n\n")
   }
}
```

## 签名
数字签名允许不可否认性，因为这意味着签署消息的人必须拥有私钥，来证明消息是真实的。 任何人都可以验证消息的真实性，只要它们具有原始数据的散列和签名者的公钥即可。 签名是区块链的基本组成部分，我们将在接下来的几节课中学习如何生成和验证签名。

### 生成签名信息

生成签名信息的需要两个信息:

- 签名者私钥
- 要签名的数据的哈希

可以使用任何输出为32字节的哈希算法。 我们将使用Keccak-256作为哈希算法，这是以太坊常常使用的算法。

```go
package main

import (
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

   data := []byte("hello")
   hash := crypto.Keccak256Hash(data)
   fmt.Printf("hash hex: %s\n", hash.Hex())

   signature, err := crypto.Sign(hash.Bytes(), privateKey)
   if err != nil {
      log.Fatal(err)
   }

   fmt.Printf("signature: %s\n", hexutil.Encode(signature))
}
```

### 验证签名

我们需要有3样数据来验证签名:

- 签名本身
- 原始数据的哈希
- 签名者的公钥

利用这些信息，我们可以确定公钥对的私钥持有者是否确实签署了该消息。

首先验证签名里提取的公钥信息是否和我们从私钥里导出的公钥信息是否一致, 再验证签名自身。

```go
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
```
