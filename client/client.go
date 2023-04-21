package main

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/RealJasomo/go-download-client-server/utils"
)

func handleKeyExchange(conn net.Conn) *rsa.PublicKey {
	rsa_private_key := utils.ResolveKey("IWUT_CLIENT_PRIVATE_KEY")
	blocks := x509.MarshalPKCS1PublicKey(&rsa_private_key.PublicKey)
	conn.Write(blocks)
	buffer := make([]byte, 524)
	conn.Read(buffer)
	rsa_server_public_key, err := x509.ParsePKCS1PublicKey(buffer)
	if err != nil {
		panic(err)
	}
	return rsa_server_public_key
}

func handleSendServerCommands(conn net.Conn, server_public_key *rsa.PublicKey) {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		scanner.Scan()
		command := scanner.Text()
		args := strings.Split(command, " ")
		switch args[0] {
		case "iWant":
			conn.Write([]byte("iWant"))
			buffer := make([]byte, 4096)
			conn.Read(buffer)
			if strings.Trim(string(buffer), "\x00") == "OK" {
				buffer := make([]byte, 4096)
				copy(buffer, []byte(args[1]))
				conn.Write(buffer)
				buffer = make([]byte, 4096)
				conn.Read(buffer)
				if strings.Trim(string(buffer), "\x00") == "FILE_NOT_FOUND" {
					if strings.Contains(args[1], "/") {
						fmt.Println("What you talkin bout Willis?  I aint seen that file anywhere!")
						continue
					} else {
						fmt.Println("From Server: not found in default directory, please provide the directory")
						fmt.Print("> ")
						scanner.Scan()
						directory := scanner.Text()
						buffer = make([]byte, 4096)
						copy(buffer, []byte(directory))
						conn.Write(buffer)
						buffer = make([]byte, 4096)
						conn.Read(buffer)
						if strings.Trim(string(buffer), "\x00") == "FILE_NOT_FOUND" {
							fmt.Println("What you talkin bout Willis?  I aint seen that file anywhere!")
							continue
						}
					}
				}
				fmt.Println("What directory would you like to save this file?")
				fmt.Print("> ")
				scanner.Scan()
				directory := scanner.Text()
				wd, err := os.Getwd()
				if err != nil {
					panic(err)
				}
				fileName := strings.Split(args[1], "/")[len(strings.Split(args[1], "/"))-1]
				_, err = os.Stat(wd + "/" + directory)
				if os.IsNotExist(err) {
					fmt.Println("That directory does not exist, would you like to create it? (y/n)")
					fmt.Print("> ")
					scanner.Scan()
					if scanner.Text() == "y" {
						os.Mkdir(directory, 0777)
					} else {
						continue
					}
				}
				file, err := os.Create(wd + "/" + directory + "/" + fileName)
				buffer_size_string := strings.Trim(string(buffer), "\x00")
				buffer_size, err := strconv.Atoi(strings.Split(buffer_size_string, " ")[1])
				if err != nil {
					panic(err)
				}
				buffer = make([]byte, buffer_size)
				fmt.Println("file transfer started...")
				conn.Read(buffer)
				if directory == "." {
					directory = "current directory"
				}
				rsa_private_key := utils.ResolveKey("IWUT_CLIENT_PRIVATE_KEY")
				buffer, err = utils.Decrypt(buffer, rsa_private_key)
				if err != nil {
					panic(err)
				}
				fmt.Printf("file transfer of %d bytes to server complete and placed in %s\n", buffer_size, directory)
				file.Write(buffer)
			}
		case "uTake":
			conn.Write([]byte("uTake"))
			buffer := make([]byte, 4096)
			conn.Read(buffer)
			if strings.Trim(string(buffer), "\x00") == "OK" {
				wd, err := os.Getwd()
				if err != nil {
					panic(err)
				}
				path := wd + "/" + args[1]
				file, err := os.Open(path)
				if err != nil {
					fmt.Println("What you talkin bout Willis?  I aint seen that file anywhere!")
					conn.Write([]byte("FILE_NOT_FOUND"))
					continue
				}
				fileInfo, err := file.Stat()
				if err != nil {
					panic(err)
				}
				fileSize := fileInfo.Size()
				fileBuffer := make([]byte, fileSize)
				file.Read(fileBuffer)
				rsa_private_key := utils.ResolveKey("IWUT_CLIENT_PRIVATE_KEY")
				encryptedFileBuffer, err := utils.Encrypt(fileBuffer, &rsa_private_key.PublicKey)
				if err != nil {
					panic(err)
				}
				file_size_message := "BYTES " + fmt.Sprintf("%d", len(encryptedFileBuffer))
				fmt.Println(file_size_message)
				fmt.Println(" What directory on the server would you like to save this file?")
				fmt.Print("> ")
				scanner.Scan()
				directory := scanner.Text()
				buffer = make([]byte, 4096)
				copy(buffer, []byte(directory))
				conn.Write(buffer)
				buffer = make([]byte, 4096)
				copy(buffer, []byte(fileInfo.Name()))
				conn.Write(buffer)
				buffer = make([]byte, 4096)
				copy(buffer, []byte(file_size_message))
				conn.Write(buffer)
				fmt.Println("file transfer started...")
				conn.Write(encryptedFileBuffer)
				buffer = make([]byte, 4096)
				conn.Read(buffer)
				if strings.Trim(string(buffer), "\x00") == "OK" {
					fmt.Printf("file transfer of %d bytes to server complete and placed in %s\n", len(encryptedFileBuffer), directory)
				}
			}
		case "exit":
			conn.Write([]byte("exit"))
			fmt.Println("See ya!")
			return
		default:
			fmt.Println("That just aint right!")
		}
	}
}

func main() {
	host_name := os.Args[1]
	port := os.Args[2]
	if host_name == "" || port == "" {
		panic("Usage: ./client <host_name> <port>")
	}

	conn, err := net.Dial("tcp", host_name+":"+port)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	server_public_key := handleKeyExchange(conn)
	handleSendServerCommands(conn, server_public_key)

}
