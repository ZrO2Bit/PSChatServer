package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
)

var id string

func readstring(conn net.Conn) (string, error) {
	res, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
	}
	return res, err
}

func listen(conn net.Conn) {
	for {
		data, err := readstring(conn)
		if err != nil {
			break
		}
		data = strings.Replace(data, "\n", "", -1)
		res := strings.Split(data, "|")
		if res[0] == "msg" {
			if res[1] != id {
				fmt.Println(res[1], strings.Replace(res[2], "{{shu}}", "|", -1))
			}
		}
	}
}

func main() {
	conn, err := net.Dial("tcp", ":2300")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	var data string
	for {
		fmt.Print("请输入您的userid:")
		fmt.Scanln(&id)
		id = strings.Replace(id, "\n", "", -1)
		_, err := conn.Write([]byte("reg|" + strings.Replace(id, " ", "", -1) + "\n"))
		if err != nil {
			break
		}
		ret, err := readstring(conn)
		if err != nil {
			break
		}
		if ret == "success\n" {
			break
		}
	}
	go listen(conn)
	for {
		fmt.Scanln(&data)
		data = strings.Replace(data, "|", "{{shu}}", -1)
		_, err := conn.Write([]byte("msg|" + data + "\n"))
		if err != nil {
			break
		}
	}
}
