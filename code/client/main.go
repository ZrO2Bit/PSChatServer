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
var rcvmode = 0
var onsendfile = ""
var onrecvfilename = ""
var onrecvfilesize = 0
var onfileuser = ""

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

// int转string
func itos(i int) string {
	strid := fmt.Sprintf("%d", i)
	return strid
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
		fmt.Println(err, "1", string(res))
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
		if rcvmode == 0 {
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
			if res[0] == "file" {
				// 如果消息头是文件信息，则询问是否接收文件
				fmt.Println("收到来自"+res[1]+"的文件"+res[2]+",大小为"+res[3], "输入&recv开始接收")
				onfileuser = res[1]
				onrecvfilename = res[2]
				onrecvfilesize, _ = strconv.Atoi(res[3])
			}
			if res[0] == "recvfile" {
				// 接收文件
				fmt.Println("开始接收来自" + res[1] + "的文件" + res[2] + ",大小为" + res[3])
				onrecvfilename = res[2]
				onrecvfilesize, _ = strconv.Atoi(res[3])
				onfileuser = res[1]

				// 进入接收文件状态
				rcvmode = 3
			}
			if res[0] == "sendfile" {
				// 发送文件
				fmt.Println("开始发送给" + res[1] + "的文件" + res[2] + ",大小为" + res[3])
				sendmsg(conn, "gotosend")
				fl, err := os.OpenFile(onsendfile, os.O_RDONLY, 0644)
				if err != nil {
					fmt.Println(err.Error())
				}
				for {
					// 分块发送文件
					filedata := make([]byte, 2048)
					n, _ := fl.Read(filedata)
					filedata = filedata[:n]
					if n == 0 {
						break
					}
					encbyte, _ := AesEncrypt(filedata, []byte(aeskey))
					conn.Write(encbyte)

					// 接收确认包
					ret := make([]byte, 1024)
					cnts, _ := conn.Read(ret)
					ret = ret[:cnts]
					ret, _ = AesDecrypt(ret, []byte(aeskey))
					if string(ret) != "success\n" {
						fmt.Println(string(ret))
					}
				}

				// 发送结束包
				encbyte, _ := AesEncrypt([]byte("end\n"), []byte(aeskey))
				conn.Write(encbyte)

				// 接收确认包
				ret := make([]byte, 1024)
				cnts, _ := conn.Read(ret)
				ret = ret[:cnts]
				ret, _ = AesDecrypt(ret, []byte(aeskey))
				if string(ret) != "success\n" {
					fmt.Println(string(ret))
				}
				fmt.Println("文件发送完毕")
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
		} else if rcvmode == 3 {
			// 接收文件块
			encdata := make([]byte, 4096)
			cnts, err := conn.Read(encdata)
			if err != nil {
				fmt.Println(err.Error())
			}
			encdata = encdata[:cnts]
			rewdata, _ := AesDecrypt(encdata, []byte(aeskey))

			// 发送确认包
			byts := []byte("success\n")
			byts, _ = AesEncrypt(byts, []byte(aeskey))
			conn.Write(byts)

			if string(rewdata) == "end\n" {
				// 接收完毕
				rcvmode = 0
				fmt.Println("文件接受完毕")
				continue
			}

			// 写入文件
			fl, err := os.OpenFile(onrecvfilename, os.O_APPEND|os.O_CREATE, 0644)
			if err != nil {
				fmt.Println(err.Error())
			}
			n, err := fl.Write(rewdata)
			fl.Close()
			if err == nil && n < len(rewdata) {
				fmt.Println(err.Error(), n)
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
			// 登录
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
			// 注册
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
	fmt.Println("直接输入消息即发送")
	fmt.Println("gethistory <nums=10> 获取nums条历史记录")
	fmt.Println("changeroom <roomid=0> 进入roomid房间")
	fmt.Println("touser <userid=0> 进入与userid私聊房间")
	fmt.Println("getrelation 获取关注/拉黑列表")
	fmt.Println("getreltome 获取被关注/拉黑列表")
	fmt.Println("like id 关注某人")
	fmt.Println("black id 拉黑某人")
	fmt.Println("unblack/unlike id 取消拉黑/关注某人")
	fmt.Println("sendfile path 发送文件,建议填写全路径")
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
			if res[0] == "gethistory" || res[0] == "gh" {
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
					ts, _ := strconv.ParseInt(his[i*3+4], 10, 64)
					datetime := time.Unix(ts/1000, 0).Format("2006-01-02 15:04:05")
					fmt.Println("来自" + his[i*3+2] + "于" + datetime + "发送的消息:")
					fmt.Println(his[i*3+3])
				}
			}
			if res[0] == "changeroom" || res[0] == "cr" {
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
			if res[0] == "touser" || res[0] == "tu" {
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
			if res[0] == "getrelation" || res[0] == "gr" {
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
			if res[0] == "getreltome" || res[0] == "gm" {
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
			if res[0] == "like" || res[0] == "lk" {
				// 喜欢/关注某人
				ret := ""
				ret, _ = sendreq(conn, "setstatus", res[1]+"|1")
				his := strings.Split(ret, "|")
				fmt.Println(his[2])
			}
			if res[0] == "black" || res[0] == "bl" {
				// 拉黑某人
				ret := ""
				ret, _ = sendreq(conn, "setstatus", res[1]+"|2")
				his := strings.Split(ret, "|")
				fmt.Println(his[2])
			}
			if res[0] == "unblack" || res[0] == "unlike" || res[0] == "ub" || res[0] == "ul" {
				// 取消关系
				ret := ""
				ret, _ = sendreq(conn, "setstatus", res[1]+"|0")
				his := strings.Split(ret, "|")
				fmt.Println(his[2])
			}
			if res[0] == "sendfile" || res[0] == "sf" {
				// 提交文件发送申请
				if !strings.HasPrefix(roomid, "to") {
					fmt.Println("你只可以在私人房间里发送文件")
					continue
				}
				if len(res) == 1 {
					fmt.Println("请输入路径")
					continue
				}
				file, err := os.Open(res[1])
				if err != nil {
					fmt.Println(err)
					continue
				}
				fileinfo, err := file.Stat()
				if err != nil {
					fmt.Println(err)
					continue
				}
				filesize := fileinfo.Size()
				filename := fileinfo.Name()
				onsendfile = res[1]
				file.Close()
				ret, _ := sendreq(conn, "sendfile", filename+"|"+itos(int(filesize)))
				his := strings.Split(ret, "|")
				if his[0] == "success" {
					fmt.Println("等待对方同意接收文件")
				}
			}
			if res[0] == "recv" {
				// 确认接收文件
				if onrecvfilename == "" {
					fmt.Println("当前无等待接收的文件")
					continue
				}
				sendmsg(conn, "recv|"+onrecvfilename+"|\n")
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
