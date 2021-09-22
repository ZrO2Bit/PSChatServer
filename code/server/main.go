package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
)

var conns = make(map[string]net.Conn)

func sendboard(msg []byte) {
	for _, conn := range conns {
		conn.Write(msg)
	}
}

func readstring(conn net.Conn) (string, error) {
	res, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
	}
	return res, err
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	for {
		data, err := readstring(conn)
		if err != nil {
			break
		}
		fmt.Println(conn.RemoteAddr().String(), strings.Replace(data, "\n", "", -1))
		sendboard([]byte(data))
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
