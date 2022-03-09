package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

type Message struct {
	Id   string
	Code [4]byte
	Msg  string
}

//go:embed public.pem
var pubKey string

//go:embed private.pem
var priKey string

func main() {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", "0.0.0.0:53939")
	chkErr(err)
	tcpListen, err2 := net.ListenTCP("tcp", tcpAddr)
	chkErr(err2)
	chkCmd := make(chan string)
	go func() {
		for {
			inputReader := bufio.NewReader(os.Stdin)
			cmd, err := inputReader.ReadString('\n')
			cmd = strings.Replace(cmd, "priKey", priKey, 1)
			cmd = strings.Replace(cmd, "pubKey", pubKey, 1)
			chkErr(err)
			chkCmd <- cmd
		}
	}()

	for {
		conn, err3 := tcpListen.Accept()
		if err3 != nil {
			continue
		}
		clientMsg := readMsg(conn, 65535)
		fmt.Println(clientMsg)
		if clientMsg.Code == [4]byte{0, 0, 0, 1} {
			var newMsg = Message{Id: clientMsg.Id, Code: [4]byte{0, 0, 0, 2}, Msg: "OK"}
			writeMsg(newMsg, conn)
		}
		if clientMsg.Code == [4]byte{0, 0, 0, 3} {
			var newMsg = Message{Id: clientMsg.Id, Code: [4]byte{0, 0, 0, 4}, Msg: <-chkCmd}
			writeMsg(newMsg, conn)
		}
		err := conn.Close()
		chkErr(err)
	}
}

func chkErr(err error) {
	if err != nil {
		log.Println(err)
	}
}

func writeMsg(message Message, conn net.Conn) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(message)
	chkErr(err)
	_, err = conn.Write(buf.Bytes())
	chkErr(err)
}

func readMsg(conn net.Conn, bufSize int) Message {
	rawData := make([]byte, bufSize)
	var msg = Message{}
	n, err := conn.Read(rawData)
	chkErr(err)
	dec := gob.NewDecoder(bytes.NewBuffer(rawData[0:n]))
	if err := dec.Decode(&msg); err != nil {
		log.Println(err)
	}
	return msg
}
