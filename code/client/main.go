package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
)

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
		fmt.Print(data)
	}
}

func main() {
	conn, err := net.Dial("tcp", ":2300")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	go listen(conn)
	for {
		var data string
		fmt.Scanln(&data)
		_, err := conn.Write([]byte(data + "\n"))
		if err != nil {
			break
		}
	}
}
