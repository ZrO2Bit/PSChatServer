package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
)

var conns = make(map[string]net.Conn)
var onlineusers = make(map[string]string)
var iptoid = make(map[string]string)

func sendboard(msg string) {
	for _, addr := range onlineusers {
		if addr != "" {
			conn := conns[addr]
			sendmsg(conn, msg)
		}
	}
}

func sendmsg(conn net.Conn, info string) (int, error) {
	return conn.Write([]byte(info + "\n"))
}

func readstring(conn net.Conn) (string, error) {
	res, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
	}
	return res, err
}

func reguser(conn net.Conn, userid string) string {
	if id, ok := onlineusers[userid]; ok && id != "" {
		return "error"
	}
	onlineusers[userid] = conn.RemoteAddr().String()
	iptoid[conn.RemoteAddr().String()] = userid
	return "success"

}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	for {
		data, err := readstring(conn)
		if err != nil {
			onlineusers[iptoid[conn.RemoteAddr().String()]] = ""
			break
		}
		data = strings.Replace(data, "\n", "", -1)
		fmt.Println(conn.RemoteAddr().String(), data)
		res := strings.Split(data, "|")
		if res[0] == "reg" {
			sendmsg(conn, "ret|"+res[1]+"|"+reguser(conn, res[2]))
		}
		if res[0] == "msg" {
			sendboard("msg|" + iptoid[conn.RemoteAddr().String()] + "|" + res[1])
		}
	}
}

func main() {
	listener, err := net.Listen("tcp", ":2300")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(conn.RemoteAddr().String())
		conns[conn.RemoteAddr().String()] = conn
		go handleConnection(conn)
	}
}
