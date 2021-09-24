package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"

	"bytes"
	"crypto/aes"
	"crypto/cipher"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

// 生成RSA私钥和公钥，保存到文件中
func GenerateRSAKey(bits int) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	X509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	privateFile, err := os.Create("private.pem")
	if err != nil {
		panic(err)
	}
	defer privateFile.Close()
	privateBlock := pem.Block{Type: "RSA Private Key", Bytes: X509PrivateKey}
	pem.Encode(privateFile, &privateBlock)

	publicKey := privateKey.PublicKey
	X509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	publicFile, err := os.Create("public.pem")
	if err != nil {
		panic(err)
	}
	defer publicFile.Close()
	publicBlock := pem.Block{Type: "RSA Public Key", Bytes: X509PublicKey}
	pem.Encode(publicFile, &publicBlock)
}

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
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil {
		panic(err)
	}
	return cipherText
}

// RSA解密
func RSA_Decrypt(cipherText []byte, path string) []byte {
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	block, _ := pem.Decode(buf)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	plainText, _ := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	return plainText
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

// 连接池
var conns = make(map[string]net.Conn)

// 用户接收状态
var rcvmodes = make(map[string]int)

// 用户接受方ip
var rcvip = make(map[string]string)

// 发送方ip寻找接收方
var toip = make(map[string]string)

// 发送文件信息
var onsendfilename = make(map[string]string)
var onsendfilesize = make(map[string]int)

// 在线用户id
var onlineusers = make(map[string]string)

// 链接ip获取id
var iptoid = make(map[string]string)

// 房间信息
var rooms = make(map[string][]string)

// id归属房间
var idbelong = make(map[string]string)

// AES密钥池
var aeskeys = make(map[string]string)

// 关系展示
var relation = map[string]string{"0": "无关系", "1": "喜欢", "2": "拉黑"}

// 数据库连接对象
var Db *sqlx.DB

// 数据库配置
var (
	userName  string = "pschat"
	password  string = "pschat2021"
	ipAddrees string = "127.0.0.1"
	port      int    = 3306
	dbName    string = "pschat"
	charset   string = "utf8"
)

// 连接sql数据库
func connectMysql() *sqlx.DB {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s", userName, password, ipAddrees, port, dbName, charset)
	Db, err := sqlx.Open("mysql", dsn)
	if err != nil {
		fmt.Printf("mysql connect failed, detail is [%v]", err.Error())
	}
	return Db
}

// int转string
func itos(i int) string {
	strid := fmt.Sprintf("%d", i)
	return strid
}

// // 广播消息
// func sendboard(msg string) {
// 	// 从在线用户中循环，向每个在线用户发布信息
// 	for _, addr := range onlineusers {
// 		if addr != "" {
// 			conn := conns[addr]
// 			aeskey := aeskeys[conn.RemoteAddr().String()]
// 			sendmsg(conn, msg, aeskey)
// 		}
// 	}
// }

// 指定用户广播
func sendtouser(msg string, userid string) {
	// 从在线用户中循环，向每个在线用户发布信息
	userip, ok := onlineusers[userid]
	if ok && userip != "" {
		conn := conns[userip]
		aeskey := aeskeys[conn.RemoteAddr().String()]
		sendmsg(conn, msg, aeskey)
	}
}

// 指定房间广播
func sendtoroom(msg string, roomid string) {
	// 从在线用户中循环，向每个在线用户发布信息
	roomusers, ok := rooms[roomid]
	if ok {
		for _, id := range roomusers {
			addr := onlineusers[id]
			if addr != "" {
				conn := conns[addr]
				aeskey := aeskeys[conn.RemoteAddr().String()]
				sendmsg(conn, msg, aeskey)
			}
		}
	}
}

// 发送消息
func sendmsg(conn net.Conn, info string, aeskey string) (int, error) {
	// 对消息进行aes加密后base64，传输密文
	encbyte, _ := AesEncrypt([]byte(info), []byte(aeskey))
	enctext := base64.StdEncoding.EncodeToString(encbyte)
	return conn.Write([]byte(enctext + "\n"))
}

// 从连接读取字符串至换行符
func readstring(conn net.Conn) (string, error) {
	res, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
	}
	return res, err
}

// 添加消息记录到sql
func addmsgrecord(roomid, userid, msg string) {
	_, err := Db.Exec("insert into message (roomid,userid,content,timestamp) values(?,?,?,?)", roomid, userid, msg, itos(int(time.Now().UnixMilli())))
	if err != nil {
		fmt.Printf("data insert faied, error:[%v]", err.Error())
		return
	}
}

// 注册用户
func reguser(conn net.Conn, userid string) string {
	// 如果id未被占用或者占用者为空，则允许注册
	if id, ok := onlineusers[userid]; ok && id != "" {
		return "error"
	}
	rooms["0"] = append(rooms["0"], userid)
	idbelong[userid] = "0"
	onlineusers[userid] = conn.RemoteAddr().String()
	iptoid[conn.RemoteAddr().String()] = userid
	return "success"

}

// 处理连接，消息循环
func handleConnection(conn net.Conn) {
	defer conn.Close()
	aeskey := ""

	for {
		// fmt.Println(rcvmodes[conn.RemoteAddr().String()])
		if rcvmodes[conn.RemoteAddr().String()] == 0 {
			data, err := readstring(conn)
			if err != nil {
				onlineusers[iptoid[conn.RemoteAddr().String()]] = ""
				for i, j := range rooms[idbelong[iptoid[conn.RemoteAddr().String()]]] {
					if j == iptoid[conn.RemoteAddr().String()] {
						rooms[idbelong[iptoid[conn.RemoteAddr().String()]]] = append(rooms[idbelong[iptoid[conn.RemoteAddr().String()]]][:i], rooms[idbelong[iptoid[conn.RemoteAddr().String()]]][i+1:]...)
					}
				}
				break
			}

			data = strings.Replace(data, "\n", "", -1)
			res := strings.Split(data, "|")

			if len(res) > 1 {
				if res[0] == "aeskey" {
					// 如果传来信息为aeskey，则不进行解密
					aeskeybyte, _ := base64.StdEncoding.DecodeString(res[1])
					aeskey = string(RSA_Decrypt(aeskeybyte, "private.pem"))
					aeskeys[conn.RemoteAddr().String()] = aeskey
					fmt.Println(conn.RemoteAddr().String(), "aeskey", aeskey)
					sendmsg(conn, "success", aeskey)
				}
			} else {
				// 否则解密后进行解析
				bytesPass, _ := base64.StdEncoding.DecodeString(data)
				fmt.Println("res", data)
				databyte, _ := AesDecrypt(bytesPass, []byte(aeskey))
				data = string(databyte)

				data = strings.Replace(data, "\n", "", -1)
				data = strings.Replace(data, "\r", "", -1)
				fmt.Println(conn.RemoteAddr().String(), data)

				res := strings.Split(data, "|")
				if res[0] == "reg" {
					// 注册消息
					sendmsg(conn, "ret|"+res[1]+"|"+reguser(conn, res[2]), aeskey)
				}
				if res[0] == "msg" {
					// 发送消息
					if strings.HasPrefix(res[1], "to") {
						touserstr := strings.Replace(res[1], "to", "", 1)
						tousers := strings.Split(touserstr, "&")
						for _, touser := range tousers {
							touserip, ok := onlineusers[touser]
							if ok {
								if rcvmodes[touserip] != 0 {
									sendmsg(conn, "msg|系统消息|"+touser+"正忙,无法收到此消息", aeskey)
									break
								}
								sendtouser("msg|from"+iptoid[conn.RemoteAddr().String()]+"|"+res[2], touser)
							}
						}
						addmsgrecord(res[1], iptoid[conn.RemoteAddr().String()], res[2])
					} else {
						addmsgrecord(res[1], iptoid[conn.RemoteAddr().String()], res[2])
						sendtoroom("msg|"+iptoid[conn.RemoteAddr().String()]+"|"+res[2], res[1])
					}
				}
				if res[0] == "register" {
					// 注册用户
					cnt, err := Db.Query("select count(*) from user where userid=?", res[2])
					usercnt := 0
					if err != nil {
						fmt.Printf("query faied, error:[%v]", err.Error())
						return
					}
					cnt.Next()
					cnt.Scan(&usercnt)
					fmt.Println("查询到用户数量", res[2], usercnt)
					if usercnt == 0 {
						_, err := Db.Exec("insert into user (userid,pwd,username) values(?,?,?)", res[2], res[3], res[4])
						if err != nil {
							fmt.Printf("data insert faied, error:[%v]", err.Error())
							return
						}
						sendmsg(conn, "ret|"+res[1]+"|"+"success", aeskey)
					} else {
						sendmsg(conn, "ret|"+res[1]+"|"+"id已被占用", aeskey)
					}
				}
				if res[0] == "login" {
					// 登录用户
					_, ok := onlineusers[res[2]]
					if ok {
						sendmsg(conn, "ret|"+res[1]+"|"+"当前用户已登录", aeskey)
						continue
					}
					user, err := Db.Query("select userid,pwd from user where userid=?", res[2])
					id, pwd := "", ""
					if err != nil {
						fmt.Printf("query faied, error:[%v]", err.Error())
						return
					}
					user.Next()
					e := user.Scan(&id, &pwd)
					if e == nil && id == res[2] && pwd == res[3] {
						reguser(conn, res[2])
						sendmsg(conn, "ret|"+res[1]+"|"+"success", aeskey)
					} else {
						sendmsg(conn, "ret|"+res[1]+"|"+"用户名或密码有误", aeskey)
					}
				}
				if res[0] == "changeroom" {
					// 更换房间
					roominfo, ok := rooms[res[2]]
					if !ok {
						rooms[res[2]] = []string{}
					}
					for i, j := range rooms[idbelong[iptoid[conn.RemoteAddr().String()]]] {
						if j == iptoid[conn.RemoteAddr().String()] {
							rooms[idbelong[iptoid[conn.RemoteAddr().String()]]] = append(rooms[idbelong[iptoid[conn.RemoteAddr().String()]]][:i], rooms[idbelong[iptoid[conn.RemoteAddr().String()]]][i+1:]...)
						}
					}
					rooms[res[2]] = append(rooms[res[2]], iptoid[conn.RemoteAddr().String()])
					idbelong[iptoid[conn.RemoteAddr().String()]] = res[2]
					retmsg := ""
					for _, j := range roominfo {
						retmsg = retmsg + "|" + j
					}
					sendmsg(conn, "ret|"+res[1]+retmsg, aeskey)
				}
				if res[0] == "touser" {
					// 更换房间
					uid, ok := onlineusers[res[2]]
					if !ok || uid == "" {
						sendmsg(conn, "ret|"+res[1]+"|用户不在线", aeskey)
						continue
					}
					if rcvmodes[conn.RemoteAddr().String()] != 0 {
						sendmsg(conn, "ret|"+res[1]+"|对方暂时无法接受此消息", aeskey)
						continue
					}
					chatroom := ""
					if iptoid[conn.RemoteAddr().String()] > res[2] {
						chatroom = "to" + res[2] + "&" + iptoid[conn.RemoteAddr().String()]
					} else {
						chatroom = "to" + iptoid[conn.RemoteAddr().String()] + "&" + res[2]
					}
					_, ok = rooms[chatroom]
					if !ok {
						rooms[chatroom] = []string{}
					}
					for i, j := range rooms[idbelong[iptoid[conn.RemoteAddr().String()]]] {
						if j == iptoid[conn.RemoteAddr().String()] {
							rooms[idbelong[iptoid[conn.RemoteAddr().String()]]] = append(rooms[idbelong[iptoid[conn.RemoteAddr().String()]]][:i], rooms[idbelong[iptoid[conn.RemoteAddr().String()]]][i+1:]...)
						}
					}
					rooms[chatroom] = append(rooms[chatroom], iptoid[conn.RemoteAddr().String()])
					idbelong[iptoid[conn.RemoteAddr().String()]] = chatroom
					sendmsg(conn, "ret|"+res[1]+"|success", aeskey)
				}
				if res[0] == "gethistory" {
					// 查询历史
					rows, err := Db.Query("select userid,content,timestamp from message where roomid=? ORDER BY timestamp DESC;", res[2])
					var result = ""
					if err != nil {
						fmt.Printf("query faied, error:[%v]", err.Error())
						continue
					}
					var cnt = 0
					maxcnt, _ := strconv.ParseInt(res[3], 10, 64)
					fmt.Print("kkk", maxcnt)
					for rows.Next() {
						//定义变量接收查询数据
						var userid, content, timestamp string

						err := rows.Scan(&userid, &content, &timestamp)
						if err != nil {
							fmt.Printf("query faied, error:[%v]", err.Error())
							break
						}
						if cnt >= int(maxcnt) {
							break
						}
						cnt++
						result = result + "|" + userid + "|" + content + "|" + timestamp
					}
					rows.Close()
					fmt.Println("res", result)
					sendmsg(conn, "ret|"+res[1]+result, aeskey)
				}
				if res[0] == "getrelation" {
					// 查询关系
					rows, err := Db.Query("select targetuser,status from userrel where sourceuser=?;", iptoid[conn.RemoteAddr().String()])
					var result = ""
					if err != nil {
						fmt.Printf("query faied, error:[%v]", err.Error())
						continue
					}
					for rows.Next() {
						//定义变量接收查询数据
						var targetuser, status string

						err := rows.Scan(&targetuser, &status)
						if err != nil {
							fmt.Printf("query faied, error:[%v]", err.Error())
							break
						}
						if status != "0" {
							result = result + "|" + targetuser + "|" + status
						}
					}
					rows.Close()
					fmt.Println("res", result)
					sendmsg(conn, "ret|"+res[1]+result, aeskey)
				}
				if res[0] == "getreltome" {
					// 查询对自己的关系
					rows, err := Db.Query("select sourceuser,status from userrel where targetuser=?;", iptoid[conn.RemoteAddr().String()])
					var result = ""
					if err != nil {
						fmt.Printf("query faied, error:[%v]", err.Error())
						continue
					}
					for rows.Next() {
						//定义变量接收查询数据
						var sourceuser, status string

						err := rows.Scan(&sourceuser, &status)
						if err != nil {
							fmt.Printf("query faied, error:[%v]", err.Error())
							break
						}
						if status != "0" {
							result = result + "|" + sourceuser + "|" + status
						}
					}
					rows.Close()
					fmt.Println("res", result)
					sendmsg(conn, "ret|"+res[1]+result, aeskey)
				}
				if res[0] == "setstatus" {
					// 更改关系
					// 检查当前关系
					user, err := Db.Query("select userid from user where userid=?", res[2])
					id := ""
					if err != nil {
						fmt.Printf("query faied, error:[%v]", err.Error())
						return
					}
					user.Next()
					e := user.Scan(&id)
					if e != nil {
						sendmsg(conn, "ret|"+res[1]+"|用户"+res[2]+"不存在", aeskey)
						continue
					}

					// 修改关系
					rows, err := Db.Query("select status from userrel where sourceuser=? and targetuser=?;", iptoid[conn.RemoteAddr().String()], res[2])
					if err != nil {
						fmt.Printf("query faied, error:[%v]", err.Error())
						continue
					}
					rows.Next()
					var pre string
					err = rows.Scan(&pre)
					if err == nil {
						_, err := Db.Exec("update userrel set status = ? where sourceuser=? and targetuser=?;", res[3], iptoid[conn.RemoteAddr().String()], res[2])
						if err != nil {
							fmt.Printf("query faied, error:[%v]", err.Error())
							continue
						}
						sendmsg(conn, "ret|"+res[1]+"|与"+res[2]+"的关系从"+relation[pre]+"修改为"+relation[res[3]], aeskey)
					} else {
						_, err := Db.Exec("insert into userrel (targetuser,sourceuser,status) values(?,?,?)", res[2], iptoid[conn.RemoteAddr().String()], res[3])
						if err != nil {
							fmt.Printf("query faied, error:[%v]", err.Error())
							continue
						}
						sendmsg(conn, "ret|"+res[1]+"|与"+res[2]+"的关系修改为"+relation[res[3]], aeskey)
					}
				}
				if res[0] == "sendfile" {
					// 处理发送文件请求
					onsendfilename[conn.RemoteAddr().String()] = res[2]
					onsendfilesize[conn.RemoteAddr().String()], _ = strconv.Atoi(res[3])

					// 确认对方状态
					if strings.HasPrefix(idbelong[iptoid[conn.RemoteAddr().String()]], "to") {
						touserstr := strings.Replace(idbelong[iptoid[conn.RemoteAddr().String()]], "to", "", 1)
						tousers := strings.Split(touserstr, "&")
						for _, touser := range tousers {
							touserip, ok := onlineusers[touser]
							if ok && touserip != conn.RemoteAddr().String() {
								rcvip[touserip] = conn.RemoteAddr().String()
								toip[conn.RemoteAddr().String()] = touserip
								if rcvmodes[touserip] != 0 {
									sendmsg(conn, "msg|系统消息|"+touser+"正忙,无法收到此消息", aeskey)
									break
								}
								sendtouser("file|"+iptoid[conn.RemoteAddr().String()]+"|"+res[2]+"|"+res[3], touser)
							}
						}
						addmsgrecord(idbelong[iptoid[conn.RemoteAddr().String()]], iptoid[conn.RemoteAddr().String()], "文件消息"+res[2])
					}
					sendmsg(conn, "ret|"+res[1]+"|success", aeskey)
				}
				if res[0] == "recv" {
					// 处理接收文件请求
					if rcvmodes[rcvip[conn.RemoteAddr().String()]] != 0 {
						sendmsg(conn, "msg|系统消息|"+iptoid[rcvip[conn.RemoteAddr().String()]]+"正忙,无法收到此消息", aeskey)
						continue
					}
					flname := onsendfilename[rcvip[conn.RemoteAddr().String()]]
					flsize := onsendfilesize[rcvip[conn.RemoteAddr().String()]]
					if flname != res[1] {
						sendmsg(conn, "msg|系统消息|"+flname+"已经被对方取消发送", aeskey)
					}
					sendmsg(conn, "recvfile|"+iptoid[rcvip[conn.RemoteAddr().String()]]+"|"+flname+"|"+itos(flsize), aeskey)
					sendtouser("sendfile|"+iptoid[conn.RemoteAddr().String()]+"|"+flname+"|"+itos(flsize), iptoid[rcvip[conn.RemoteAddr().String()]])
					rcvmodes[conn.RemoteAddr().String()] = 3
				}
				if res[0] == "gotosend" {
					// 处理状态变更请求
					rcvmodes[conn.RemoteAddr().String()] = 2
				}
			}

		} else if rcvmodes[conn.RemoteAddr().String()] == 2 {
			// 发送文件则作为中转
			encdata := make([]byte, 4096)
			cnts, err := conn.Read(encdata)
			if err != nil {
				fmt.Println(err.Error())
			}
			encdata = encdata[:cnts]
			rewdata, _ := AesDecrypt(encdata, []byte(aeskey))
			if string(rewdata) == "end\n" {
				rcvmodes[conn.RemoteAddr().String()] = 0
				rcvmodes[toip[conn.RemoteAddr().String()]] = 0
				fmt.Println("文件发送结束")
			}
			encdata, _ = AesEncrypt(rewdata, []byte(aeskeys[toip[conn.RemoteAddr().String()]]))
			conns[toip[conn.RemoteAddr().String()]].Write(encdata)
		} else if rcvmodes[conn.RemoteAddr().String()] == 3 {
			// 中转确认消息
			ret := make([]byte, 1024)
			cnts, _ := conn.Read(ret)
			ret = ret[:cnts]
			ret, _ = AesDecrypt(ret, []byte(aeskey))
			if string(ret) == "success\n" {
				byts := []byte("success\n")
				byts, _ = AesEncrypt(byts, []byte(aeskeys[rcvip[conn.RemoteAddr().String()]]))
				conns[rcvip[conn.RemoteAddr().String()]].Write(byts)
			} else {
				byts := []byte("fail\n")
				byts, _ = AesEncrypt(byts, []byte(aeskeys[rcvip[conn.RemoteAddr().String()]]))
				conns[rcvip[conn.RemoteAddr().String()]].Write(byts)
			}
		}
	}
}

func main() {
	Db = connectMysql()
	defer Db.Close()
	listener, err := net.Listen("tcp", ":2300")
	if err != nil {
		log.Fatal(err)
	}
	rooms["0"] = []string{}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(conn.RemoteAddr().String())
		conns[conn.RemoteAddr().String()] = conn
		rcvmodes[conn.RemoteAddr().String()] = 0
		go handleConnection(conn)
	}
}
