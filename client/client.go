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
	joinReq     uint16 = 1
	passReq     uint16 = 2
	passResp    uint16 = 3
	passAccept  uint16 = 4
	data        uint16 = 5
	terminate   uint16 = 6
	reject      uint16 = 7
	
	// Packet format where int is >= 32-bit (4-bytes)
	// all packets have 2-byte (packet type) + 4-byte (payload length)
	// PASSWORD length <= 50-bytes
	// TERMINATE length = digest (sha1 = 64-bytes)
	HeaderLength	uint16    = 2
	PayloadLength	uint32    = 4
	Packetid	int    = 4 //
)

var (
	nameNPort  []string
	passwds    []string
	outfile    string
	joinReqArr = []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
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
	if err != nil {
		panic("ABORT")
	}
}

func verifyDigest(pk []byte) {
	pyldLen := binary.LittleEndian.Uint32(pk[0:])
	recvDigest := pk[4:]
	if int(pyldLen) != len(recvDigest) {
		fmt.Println("ABORT")
		return
	}

	data, err := ioutil.ReadFile(outfile)
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

func handleConnection(conn net.Conn) {
	// Send Join Request
	conn.Write(joinReqArr)

	buff := make([]byte, 1010)

	passCount := 0

	f, err := os.Create(outfile)
	defer f.Close()
	checkError(err)

	// Read responses
	for {
		n, err := conn.Read(buff)
		checkError(err)
		header := binary.LittleEndian.Uint16(buff[0:])

		switch header {
		case PassReq:
			passRespLen := HdrSize + PyldLenSize + len(passwds[passCount])
			pyldLen := uint32(len(passwds[passCount]))
			response := make([]byte, passRespLen)
			binary.LittleEndian.PutUint16(response[0:], PassResp)
			binary.LittleEndian.PutUint32(response[2:], pyldLen)
			copy(response[6:], []byte(passwds[passCount]))
			_, err := conn.Write(response)
			checkError(err)
			passCount++
		case PassAccept:
			//TODO Not sure if there is an action to take here
		case Data:
			// pkID := binary.LittleEndian.Uint32(buff[6:10])
			data := buff[10:n]
			_, err := f.Write(data)
			checkError(err)
			f.Sync()
		case Reject:
			fmt.Println("ABORT")
			return
		case Terminate:
			verifyDigest(buff[2:n])
			return
		default:
			fmt.Println("ABORT")
			return
		}
	}
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

	// Parse command line args
	ipAddessAndPort = args[1:3] //
	passwds = args[3:6]
	outfile = args[6]

	_, err := strconv.Atoi(nameNPort[1])
	if err != nil {
		usage()
		return
	}

	// Connect to server
	hostPort := nameNPort[0] + ":" + nameNPort[1]
	conn, err := net.Dial("udp4", hostPort)
	defer conn.Close()
	checkError(err)

	handleConnection(conn)
}
