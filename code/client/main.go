package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

var id string
var msgid int
var msgs = make(map[int]string)

func readstring(conn net.Conn) (string, error) {
	res, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
	}
	return res, err
}

func sendmsg(conn net.Conn, info string) (int, error) {
	return conn.Write([]byte(info + "\n"))
}

func listen(conn net.Conn) {
	for {
		data, err := readstring(conn)
		if err != nil {
			break
		}
		data = strings.Replace(data, "\n", "", -1)
		res := strings.Split(data, "|")
		if res[0] == "ret" {
			cnt, _ := strconv.ParseInt(res[1], 10, 64)
			msgs[int(cnt)] = res[2]
		}
		if res[0] == "msg" {
			if res[1] != id {
				fmt.Println(res[1], strings.Replace(res[2], "{{shu}}", "|", -1))
			}
		}
	}
}

func sendreq(conn net.Conn, opt string, msg string) (string, error) {
	msgid++
	msgs[msgid] = ""
	strid := fmt.Sprintf("%d", msgid)
	_, err := conn.Write([]byte(opt + "|" + strid + "|" + msg + "\n"))
	if err != nil {
		return "", err
	}

	for i := 0; i < 1000; i++ {
		if msgs[msgid] != "" {
			return msgs[msgid], err
		}
		time.Sleep(time.Duration(50) * time.Millisecond)
	}
	return "", errors.New("timeout")
}

func main() {
	conn, err := net.Dial("tcp", ":2300")
	msgid = 0
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	var data string
	go listen(conn)
	for {
		fmt.Print("请输入您的userid:")
		fmt.Scanln(&id)
		id = strings.Replace(id, "\n", "", -1)
		ret, err := sendreq(conn, "reg", strings.Replace(id, " ", "", -1))
		if err != nil {
			break
		}
		if ret == "success" {
			break
		} else {
			fmt.Print(ret, "请输入您的userid:")
		}
	}
	for {
		fmt.Scanln(&data)
		data = strings.Replace(data, "|", "{{shu}}", -1)
		_, err := sendmsg(conn, "msg|"+data+"\n")
		if err != nil {
			break
		}
	}
}
