package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"strings"
)

func handleClientCommand(conn net.Conn, client_key *rsa.PublicKey) {
	// read command from client
	// if command is "iWant", read file name and send file
	// if command is "uTake", read file name and receive file
	buffer := make([]byte, 4096)
	conn.Read(buffer)
	switch command := strings.Trim(string(buffer), "\x00"); command {
	case "iWant":
		conn.Write([]byte("OK"))
	case "uTake":
		conn.Write([]byte("OK"))
	default:
		conn.Write([]byte("INV_CMD"))
	}

}

func handleKeyExchange(conn net.Conn) *rsa.PublicKey {
	// read public key of client
	buffer := make([]byte, 4096)
	conn.Read(buffer)
	// buffer contains public key of client
	// generate public key
	public_key, err := x509.ParsePKIXPublicKey(buffer)
	if err != nil {
		panic(err)
	}
	// send public key to client
	rsa_private_key := resolveKey()
	blocks := x509.MarshalPKCS1PublicKey(&rsa_private_key.PublicKey)
	conn.Write(blocks)

	rsa_client_public_key := public_key.(*rsa.PublicKey)

	return rsa_client_public_key
}

func handleSendCommandsToClient(conn net.Conn) {
	// send commands to client

}

func handleConnection(conn net.Conn) {
	// read type of request from client, it can only be "iWant" or "uTake"
	// if it is "iWant", read the file name and send the file
	client_key := handleKeyExchange(conn)
	go handleClientCommand(conn, client_key)
}

func resolveKey() *rsa.PrivateKey {
	private_key, err := utils.read_private_key("IWUT_SERVER_PRIVATE_KEY")
	if err != nil {
		panic(err)
	}
	marshal, err := private_key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(marshal)
	rsa_private_key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	return rsa_private_key
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

	for {
		conn, err := datastream.Accept()
		if err != nil {
			panic(err)
		}
		go handleConnection(conn)
	}

}
