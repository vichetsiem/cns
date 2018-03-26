/*
client.go
code derived from fenriquez1

implements the following in

STEPS
1) socket establishment, 
2) case/switch for packet type/condition, 
3) buffer array check for one password, 
4) send file (handle little/bigEndian)
5) terminate connection/hash file
*/

package main

import (
	// Packages listed are in alphabetical order
	// -----------------------------------------
	
	// Package sha1 implements the SHA-1 hash algorithm
	"crypto/sha1" 
	
	// Package binary implements simple translation between numbers and byte sequences 
	// and encoding and decoding of varints.
	// Will find Little/BigEndian to handle byteOrder
	"encoding/binary" 
	
	// Package fmt implements formatted I/O with functions analogous to C's printf and scanf.
	"fmt"
	
	// Package ioutil implements some I/O utility functions
	// Will find ReadFile reads the file named by filename and returns the contents
	"io/ioutil"
	
	// Package net provides a portable interface for network I/O, including TCP/IP, UDP, 
	// domain name resolution, and Unix domain sockets
	"net"
	
	// Package os provides a platform-independent interface to operating system functionality
	"os"
	
	// Package strconv implements conversions to and from string representations of basic data types
	"strconv"
)

// Let's define the Functional Specification and Packet Formats
const (
	
	// Functional Specifications
	// -------------------------
	// Packet Types are 2-bytes (uint16 / 16-bit integers w/ Range: 0 through 65535.)
	JOIN_REQ    uint16 = 1
	PASS_REQ    uint16 = 2
	PASS_RESP   uint16 = 3
	PASS_ACCEPT uint16 = 4
	DATA        uint16 = 5
	TERMINATE   uint16 = 6
	REJECT      uint16 = 7
	
	// Packet format where int is >= 32-bit (4-bytes)
	// all packets have 2-byte (packet type) + 4-byte (payload length)
	// PASSWORD length <= 50-bytes
	// TERMINATE length = digest (sha1 = 64-bytes)
	HeaderLength	uint16    = 2
	PayloadLength	uint32    = 4
	PacketidLength	int    = 4 // up to 1000 bytes to handle data
)

var (
	serverAddress 	string
	serverPort  	string
	userPasswords	string
	outputFile    	string
	JOIN_REQ_Array = []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00} // packet is 6-bytes
)

func usage() {
	// Presents User input format for argument function
	// text within "< >" are considered arguments
	// agr[0] = client
	// agr[1] = server name
	// agr[2] = server port
	// agr[3] = clientpwd1
	// agr[4] = clientpwd2
	// agr[5] = clientpwd3
	// agr[6] = output file (creates file with name "output file" from 
	//	file received from server program
	
	fmt.Printf("Usage: ./client <server name> <server port> <clientpwd1>" +
		"<clientpwd2> <clientpwd3> <output file>\n")
}

func checkError(err error) {
	// If there is an error, abort!
	if err != nil {
		panic("ABORT")
	}
}

func handleConnection(conn net.Conn) {
	// Client sends a JOIN_REQ
	conn.Write(JOIN_REQ_Array)

	// Allocate buffer as byte array
	buffer := make([]byte, 1010)
	
	// used to cycle through the three user provided passwords, starting at 0
	password := 0

	//
	f, err := os.Create(outfile)
	defer f.Close()
	checkError(err)

	// Pull in user input
	for {
		n, err := conn.Read(buffer)
		checkError(err)
		// handle network byte order
		headerBytes := binary.LittleEndian.Uint16(buffer[0:])

		switch headerBytes {
		case PASS_REQ:
			// Handle server password request
			passRespLen := HeaderLength + PayloadLength + len(userPasswords[password])
			pyldLen := uint32(len(userPasswords[password]))
			response := make([]byte, passRespLen)
			binary.LittleEndian.PutUint16(response[0:], PassResp)
			binary.LittleEndian.PutUint32(response[2:], pyldLen)
			copy(response[6:], []byte(userPasswords[passCheck]))
			_, err := conn.Write(response)
			checkError(err)
			password++
		case PASS_ACCEPT:
			// Handle server accepting password
			// Go to Data case
		case DATA:
			// Handle data server sends
			// pkID := binary.LittleEndian.Uint32(buffer[6:10])
			data := buffer[10:n]
			_, err := f.Write(data)
			checkError(err)
			f.Sync()
		case REJECT:
			fmt.Println("ABORT")
			return
		case TERMINATE:
			verifyDigest(buffer[2:n])
			return
		default:
			fmt.Println("ABORT")
			return
		}
	}
}

func verifyDigest(pk []byte) {
	pyldLen := binary.LittleEndian.Uint32(pk[0:])
	recvDigest := pk[4:]
	if int(pyldLen) != len(recvDigest) {
		fmt.Println("ABORT")
		return
	}

	data, err := ioutil.ReadFile(outputFile)
	checkError(err)

	digest := sha1.Sum(data)

	if len(recvDigest) != len(digest) {
		fmt.Println("ABORT")
		return
	}

	for i := 0; i < len(digest); i++ {
		if recvDigest[i] != digest[i] {
			fmt.Println("ABORT")
			return
		}
	}

	fmt.Println("OK")
}


func main() {
	// Define the arguments to be parsed by program w/o using flags
	// Flags could be "./client -what -do -you -want", 
	// instead, we'll skip arg[0] which would return "client"
	//
	// See example: https://gobyexample.com/command-line-arguments
	//
	args := os.Args
	if len(args) != 7 {
		usage() // parses argument from User input
		return
	}

	// Parse command line argument strings (args)
	serverAddess = args[1] // <server name>
	serverPort = args[2] // <server port>
	userPasswords = args[3:6] // <clientpwd1><clientpwd2><clientpwd3>
	outputFile = args[6] // <output file>

	// Convert string (serverPort) to integer
	_, err := strconv.Atoi(serverPort)
	if err != nil {
		// if there is no error, print to screen expected command arguments
		usage()
		return
	}

	// Connect to server
	hostPort := serverAddress + ":" + serverPort
	
	// Dial function is "tcp/udp" "golang.org:80"
	// establish connection
	conn, err := net.Dial("udp", hostPort)
	defer conn.Close() // defer ensures connection is closed
	checkError(err)

	handleConnection(conn)
}
