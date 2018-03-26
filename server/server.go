/*
server.go

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

	// Package strings implements simple functions to manipulate UTF-8 encoded strings.
	"strings"
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
	HeaderLength	int    = 2
	PayloadLength	int    = 4
	PacketidLength	int    = 4 // up to 1000 bytes to handle data
)

var (
	serverPassword	string
	inputFile	string
	PASS_REQ_Array     	= []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00}
	PASS_ACCEPT_Array  	= []byte{0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
	REJECT_Array      	= []byte{0x07, 0x00, 0x00, 0x00, 0x00, 0x00}
)

func usage() {
	// Presents User input format for argument function
	// text within "< >" are considered arguments
	// agr[0] = server
	// agr[1] = server port
	// agr[2] = password
	// agr[3] = input file (open file to send to client)
	fmt.Printf("Usage: ./server <port> <password> <input file>\n")
}

func checkError(err error) {
	// If there is an error, abort!
	if err != nil {
		panic("ABORT")
	}
}

func terminate(conn net.PacketConn, serverAddr net.Addr) {
	// Get digest and send TERMINATE packet
	data, err := ioutil.ReadFile(inputFile)
	checkError(err)
	digest := sha1.Sum(data)

	packetLength := HeaderLength + PayloadLength + sha1.Size
	packet := make([]byte, packetLength)
	binary.LittleEndian.PutUint16(packet[0:], TERMINATE)
	binary.LittleEndian.PutUint32(packet[2:], uint32(len(digest)))
	copy(packet[6:], digest[0:])
	conn.WriteTo(packet, serverAddr)
	fmt.Println("OK")
}

func sendFile(conn net.PacketConn, serverAddr net.Addr) {
	// Read file from present directory and send
	// NOTE: file must be in working directory or this will fail
	fileObject, err := os.Open(inputFile)
	defer fileObject.Close()
	checkError(err)

	inputFileObject, err := fileObject.Stat() // get FileInfo on source file
	checkError(err)

	dataObject := make([]byte, 1000)
	size := inputFileObject.Size()
	Packetid := uint32(0)
	for i := int64(0); i < size; {
		dobj, err := fileObject.Read(dataObject)
		checkError(err)
		packetLength := HeaderLength + PayloadLength + PackIdSize + dobj
		packet := make([]byte, packetLength)
		binary.LittleEndian.PutUint16(packet[0:], DATA)
		binary.LittleEndian.PutUint32(packet[2:], uint32(dobj))
		binary.LittleEndian.PutUint32(packet[6:], Packetid)
		copy(packet[10:], dataObject[0:dobj])
		conn.WriteTo(packet, serverAddr)
		i += int64(dobj)
		Packetid++
	}
}

func handlePacketConnection(conn net.PacketConn) {

	request := 0
	// Allocate buffer as byte array, where 
	// (HeaderLength==2) +(PayloadLength==4) +(PacketidLength==4)+ (Data <= 1000) ==1010
	bufferObject := make([]byte, 1010)

	for {
		count, serverAddress, err := conn.ReadFrom(bufferObject)
		if err != nil {
			fmt.Println(err)
			return
		}
		frmClient := bufferObject[0:count]
		header := binary.LittleEndian.Uint16(bufferObject[0:])

		switch header {
		case JOIN_REQ:
			conn.WriteTo(PASS_REQ_Array, serverAddress)
			request++
		case PASS_RESP:
			clientPassword := string(frmClient[6:])
			if strings.Compare(clientPassword, serverPassword) == 0 {
				conn.WriteTo(PASS_REQ_Array, serverAddress)
				// Password matches, send file to client
				sendFile(conn, serverAddress)
				// Terminate connection after completion
				terminate(conn, serverAddress)
				return
			}
			if request < 3 {
				conn.WriteTo(PASS_REQ_Array, serverAddress)
				request++
			} else {
				conn.WriteTo(REJECT_Array, serverAddress)
				fmt.Println("ABORT")
				return
			}
		default:
			fmt.Println("ABORT")
			return
		}
		fmt.Printf("Server Address = %s\n", serverAddress)
		fmt.Printf("Buffer = %#4x\n", frmClient)
	}
}

func main() {
	// Define the arguments to be parsed by program w/o using flags
	// Flags could be "./server -what -do -you -want", 
	// instead, we'll skip arg[0] which would return "server"
	//
	// See example: https://gobyexample.com/command-line-arguments
	//
	args := os.Args
	if len(args) != 4 {
		usage() // parses argument from User input
		return
	}

	// Parse command line argument strings (args)
	localPort := args[1] 		// <server port>
	serverPassword = args[2] 	// <password>
	inputFile = args[3] 	// <input file>

	// Convert string (serverPort) to integer
	_, err := strconv.Atoi(localPort)
	if err != nil {
		// if there is no error, print to screen expected command arguments
		usage()
		return
	}

	// Setup addressing for listening call
	serverAddr := ":" + localPort
	// Listen for client to establish connection
	conn, err := net.ListenPacket("udp", serverAddr)
	defer conn.Close() // defer ensures connection is closed
	checkError(err)

	handlePacketConnection(conn)
}
