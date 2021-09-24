package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	cryprand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var id = ""
var msgid int
var msgs = make(map[int]string)
var roomid string
var aeskey []byte
var relation = map[string]string{"0": "无关系", "1": "喜欢", "2": "拉黑"}

// RSA加密
func RSA_Encrypt(plainText []byte, path string) []byte {
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	block, _ := pem.Decode(buf)

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	publicKey := publicKeyInterface.(*rsa.PublicKey)
	cipherText, err := rsa.EncryptPKCS1v15(cryprand.Reader, publicKey, plainText)
	if err != nil {
		panic(err)
	}
	return cipherText
}

// AES加密的一部分
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// AES加密的一部分
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// AES加密
func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

// AES解密
func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

// 获取长度为l的只含数字和小写字母的随机字符串
func GetRandomString(l int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyz"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}

// 从连接读取一次数据并解密
func readstring(conn net.Conn) (string, error) {
	// 先进行base64解码后aes解密
	res, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
	}

	bytesPass, err := base64.StdEncoding.DecodeString(res)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	finalres, err := AesDecrypt(bytesPass, aeskey)
	return string(finalres), err
}

// 向连接发送消息
func sendmsg(conn net.Conn, info string) (int, error) {
	// aes加密后base64发送
	encbyte, _ := AesEncrypt([]byte(info), []byte(aeskey))
	enctext := base64.StdEncoding.EncodeToString(encbyte)
	return conn.Write([]byte(enctext + "\n"))
}

// 监听消息循环
func listen(conn net.Conn) {
	for {
		data, err := readstring(conn)
		if err != nil {
			break
		}
		data = strings.Replace(data, "\n", "", -1)
		res := strings.Split(data, "|")

		if res[0] == "ret" {
			// 如果消息头是返回值，则将数据填充至对应序列号的返回值
			cnt, _ := strconv.ParseInt(res[1], 10, 64)
			msgs[int(cnt)] = data
		}
		if res[0] == "msg" {
			// 如果消息头是消息，则显示出来
			if strings.HasPrefix(res[1], "from") {
				if strings.Replace(res[1], "from", "", 1) != id {
					fmt.Println("来自"+strings.Replace(res[1], "from", "", 1)+"的私聊消息:", strings.Replace(res[2], "{{shu}}", "|", -1))
				}
			} else {
				if res[1] != id {
					fmt.Println("来自"+res[1]+"的消息:", strings.Replace(res[2], "{{shu}}", "|", -1))
				}
			}
		}
	}
}

// 发送一个请求
func sendreq(conn net.Conn, opt string, msg string) (string, error) {
	// 为请求分配序列号，同时等待返回值被填充
	msgid++
	thisid := msgid
	msgs[thisid] = ""
	strid := fmt.Sprintf("%d", thisid)
	_, err := sendmsg(conn, opt+"|"+strid+"|"+msg)
	if err != nil {
		return "", err
	}

	// 循环等待请求返回
	for i := 0; i < 1000; i++ {
		if msgs[thisid] != "" {
			return msgs[thisid], err
		}
		time.Sleep(time.Duration(50) * time.Millisecond)
	}
	return "", errors.New("timeout")
}

func main() {
	conn, err := net.Dial("tcp", ":2300")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	msgid = 0
	roomid = "0"
	// 生成aeskey
	aeskey = []byte(GetRandomString(16))
	cipherText := base64.StdEncoding.EncodeToString(RSA_Encrypt(aeskey, "public.pem"))
	var data string
	// 发送aeskey并等待返回
	for {
		conn.Write([]byte("aeskey|" + cipherText + "\n"))
		if r, _ := readstring(conn); r == "success" {
			break
		} else {
			fmt.Println(r)
		}
	}

	// 启动监听循环
	go listen(conn)
	// 登录流程
	for {
		fmt.Println("login id pwd登录系统")
		fmt.Println("register id pwd name注册系统")
		in := bufio.NewReader(os.Stdin)
		data, _ = in.ReadString('\n')
		data = strings.Replace(data, "|", "{{shu}}", -1)
		data = strings.Replace(data, "\n", "", -1)
		data = strings.Replace(data, "\r", "", -1)
		res := strings.Split(data, " ")

		if res[0] == "login" {
			ret, err := sendreq(conn, "login", res[1]+"|"+res[2])
			if err != nil {
				panic(err)
			}
			r := strings.Split(ret, "|")
			if r[2] == "success" {
				id = res[1]
				fmt.Println("登陆成功，您可以发送消息了，您的id:", id)
			} else {
				fmt.Println(r[2])
			}
		}
		if res[0] == "register" {
			ret, err := sendreq(conn, "register", res[1]+"|"+res[2]+"|"+res[3])
			if err != nil {
				panic(err)
			}
			r := strings.Split(ret, "|")
			if r[2] == "success" {
				fmt.Println("注册成功，请登录")
			} else {
				fmt.Println(r[2])
			}
		}
		if id != "" {
			break
		}
	}
	// 处理用户输入
	for {
		in := bufio.NewReader(os.Stdin)
		data, _ = in.ReadString('\n')
		data = strings.Replace(data, "|", "{{shu}}", -1)
		data = strings.Replace(data, "\n", "", -1)
		data = strings.Replace(data, "\r", "", -1)
		if data == "" {
			continue
		}
		if data == "exit" {
			break
		}
		if strings.HasPrefix(data, "&") {
			// 处理指令输入
			res := strings.Split(data, " ")
			res[0] = strings.Replace(res[0], "&", "", -1)
			if res[0] == "gethistory" {
				// 历史查询指令
				ret := ""
				if len(res) > 1 {
					ret, _ = sendreq(conn, "gethistory", roomid+"|"+res[1])
				} else {
					ret, _ = sendreq(conn, "gethistory", roomid+"|10")
				}
				his := strings.Split(ret, "|")
				nums := (len(his) - 2) / 3
				fmt.Println(nums)
				for i := nums - 1; i >= 0; i-- {
					fmt.Println(his[i*3+2], his[i*3+3], his[i*3+4])
				}
			}
			if res[0] == "changeroom" {
				// 更改房间
				ret := ""
				if len(res) > 1 {
					if strings.HasPrefix(res[1], "to") {
						fmt.Println("不能切换至私人房")
						continue
					}
					ret, _ = sendreq(conn, "changeroom", res[1])
					roomid = res[1]
				} else {
					ret, _ = sendreq(conn, "changeroom", "0")
					roomid = "0"
				}
				his := strings.Split(ret, "|")
				fmt.Print("该房间中当前有:")
				for i := len(his) - 1; i >= 2; i-- {
					fmt.Print(his[i] + ",")
				}
				fmt.Print("\n")
			}
			if res[0] == "touser" {
				// 切换至私人房
				ret := ""
				if len(res) > 1 {
					ret, _ = sendreq(conn, "touser", res[1])
					if id > res[1] {
						roomid = "to" + res[1] + "&" + id
					} else {
						roomid = "to" + id + "&" + res[1]
					}
				}
				his := strings.Split(ret, "|")
				if his[2] == "success" {
					fmt.Println("已切换到与" + res[1] + "的私人聊天")
				} else {
					fmt.Println(res[1] + his[2])
				}
				fmt.Print("\n")
			}
			if res[0] == "getrelation" {
				// 查询关系
				ret := ""
				ret, _ = sendreq(conn, "getrelation", "")
				his := strings.Split(ret, "|")
				nums := (len(his) - 2) / 2
				fmt.Println(nums)
				for i := nums - 1; i >= 0; i-- {
					fmt.Println(his[i*2+2], relation[his[i*2+3]])
				}
			}
			if res[0] == "getreltome" {
				// 查询对我的关系
				ret := ""
				ret, _ = sendreq(conn, "getreltome", "")
				his := strings.Split(ret, "|")
				nums := (len(his) - 2) / 2
				fmt.Println(nums)
				for i := nums - 1; i >= 0; i-- {
					fmt.Println(his[i*2+2], relation[his[i*2+3]])
				}
			}
			if res[0] == "like" {
				// 喜欢/关注某人
				ret := ""
				ret, _ = sendreq(conn, "setstatus", res[1]+"|1")
				his := strings.Split(ret, "|")
				fmt.Println(his[2])
			}
			if res[0] == "black" {
				// 拉黑某人
				ret := ""
				ret, _ = sendreq(conn, "setstatus", res[1]+"|2")
				his := strings.Split(ret, "|")
				fmt.Println(his[2])
			}
			if res[0] == "unblack" || res[0] == "unlike" {
				// 取消关系
				ret := ""
				ret, _ = sendreq(conn, "setstatus", res[1]+"|0")
				his := strings.Split(ret, "|")
				fmt.Println(his[2])
			}

		} else {
			// 处理消息输入
			_, err := sendmsg(conn, "msg|"+roomid+"|"+data+"\n")
			if err != nil {
				break
			}
		}
	}
}
