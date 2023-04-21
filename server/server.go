package main

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	utils "github.com/RealJasomo/go-download-client-server/utils"
)

func resolveFile(filename string, client_key *rsa.PublicKey) ([]byte, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	// hash public key
	hashed_key := utils.HashKey(client_key)
	file, err := os.Open(wd + "/store/" + hashed_key + "/" + filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	fileinfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	filesize := fileinfo.Size()
	buffer := make([]byte, filesize)
	file.Read(buffer)
	return buffer, nil
}

func handleClientCommand(conn net.Conn, client_key *rsa.PublicKey, wg *sync.WaitGroup) {
	// read command from client
	// if command is "iWant", read file name and send file
	// if command is "uTake", read file name and receive file
	for {
		buffer := make([]byte, 4096)
		conn.Read(buffer)
		switch command := strings.Trim(string(buffer), "\x00"); command {
		case "iWant":
			conn.Write([]byte("OK"))
			buffer := make([]byte, 4096)
			conn.Read(buffer)
			file_name := strings.Trim(string(buffer), "\x00")
			file, err := resolveFile(file_name, client_key)
			if err != nil {
				conn.Write([]byte("FILE_NOT_FOUND"))
				if strings.Contains(file_name, "/") {
					continue
				}
				buffer := make([]byte, 4096)
				conn.Read(buffer)
				directory := strings.Trim(string(buffer), "\x00")
				file, err = resolveFile(directory+"/"+file_name, client_key)
				if err != nil {
					conn.Write([]byte("FILE_NOT_FOUND"))
					continue
				}
			}
			buffer = make([]byte, 4096)
			file_size_message := "BYTES " + fmt.Sprint(len(file))
			copy(buffer, []byte(file_size_message))
			conn.Write(buffer)
			conn.Write(file)

		case "uTake":
			conn.Write([]byte("OK"))
			buffer := make([]byte, 4096)
			conn.Read(buffer)
			if strings.Trim(string(buffer), "\x00") == "FILE_NOT_FOUND" {
				continue
			}
			directory := strings.Trim(string(buffer), "\x00")
			buffer = make([]byte, 4096)
			conn.Read(buffer)
			fileName := strings.Trim(string(buffer), "\x00")
			buffer = make([]byte, 4096)
			fmt.Println(directory, fileName)
			conn.Read(buffer)
			file_size_message := strings.Trim(string(buffer), "\x00")
			parsed_file_size := strings.Split(file_size_message, " ")
			file_size, err := strconv.Atoi(parsed_file_size[1])
			if err != nil {
				panic(err)
			}
			file := make([]byte, file_size)
			conn.Read(file)
			fmt.Println("Received file: " + fileName + " in directory: " + directory)
			conn.Write([]byte("OK"))
			wd, err := os.Getwd()
			if err != nil {
				panic(err)
			}
			path := wd + "/store/" + utils.HashKey(client_key) + "/" + directory
			newFile, err := os.Open(path)
			if err != nil {
				os.MkdirAll(path, 0777)
			}
			newFile, err = os.Create(path + "/" + fileName)
			if err != nil {
				panic(err)
			}
			defer newFile.Close()
			newFile.Write(file)
		case "exit":
			wg.Done()
			return
		default:
			conn.Write([]byte("INV_CMD"))
		}
	}

}

func handleKeyExchange(conn net.Conn) *rsa.PublicKey {
	// read public key of client
	buffer := make([]byte, 524)
	conn.Read(buffer)
	// buffer contains public key of client
	// generate public key
	rsa_client_public_key, err := x509.ParsePKCS1PublicKey(buffer)
	if err != nil {
		panic(err)
	}
	// send public key to client
	rsa_private_key := utils.ResolveKey("IWUT_SERVER_PRIVATE_KEY")
	blocks := x509.MarshalPKCS1PublicKey(&rsa_private_key.PublicKey)
	conn.Write(blocks)

	return rsa_client_public_key
}

func handleSendCommandsToClient(conn net.Conn) {
	// send commands to client

}

func handleConnection(conn net.Conn, wg *sync.WaitGroup) {
	// read type of request from client, it can only be "iWant" or "uTake"
	// if it is "iWant", read the file name and send the file
	client_key := handleKeyExchange(conn)
	wg.Add(1)
	go handleClientCommand(conn, client_key, wg)
	wg.Done()
}

func main() {
	// read port from arguments
	// if no port is provided, give usage error
	port := os.Args[1]
	if port == "" {
		panic("Usage: ./server <port>")
	}
	datastream, err := net.Listen("tcp", ":"+port)
	defer datastream.Close()
	if err != nil {
		panic(err)
	}
	wg := sync.WaitGroup{}
	for {
		conn, err := datastream.Accept()
		if err != nil {
			panic(err)
		}
		wg.Add(1)
		go handleConnection(conn, &wg)
	}

}
