/*
client.go

Vichet Siem
Spring 2018
CYBR 550
2 APR 2018

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
	
	// Package aes implements AES encryption, FIPS 197
	// 32 byte or 256-bit key = AES-256; 12 rounds
	"crypto/aes"
	
	// Package cipher implements standard block cipher modes
	// NIST SP 800-38A; AEAD
	"crypto/cipher"
	
	// Package rand implements pseudorandom numbers
	// use primeNumber
	"crypto/rand"
	
	// Package sha1 implements the SHA-1 hash algorithm
	"crypto/sha1"
	"crypto/sha256"	
	
	// Package binary implements simple translation between numbers and byte sequences 
	// and encoding and decoding of varints.
	// Will find Little/BigEndian to handle byteOrder
	"encoding/binary" 
	
	// Package fmt implements formatted I/O with functions analogous to C's printf and scanf.
	"fmt"
	
	// Package ioutil implements some I/O utility functions
	// Will find ReadFile reads the file named by filename and returns the contents
	"io"
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
	HeaderLength	int    = 2 // couldn't use unit16
	PayloadLength	int    = 4 // if this was uint32, can't perform add operand
	PacketidLength	int    = 4 // up to 1000 bytes to handle data
	
)

var (
	server  		[]string
	userPasswords	[]string 
	outputFile    	string
	// packet is 6-bytes
	JOIN_REQ_Array = []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00} 
	// Authenticated encryption with associated data (AEAD)
	aes_block		cipher.AEAD	
	primeNumber = make([]byte,12) // twelve rounds, used as IV for encryption
)

func usage() {
	// Presents User input format for argument function
	// text within "< >" are considered arguments
	// 
	// agr[0] = client
	// agr[1] = server name
	// agr[2] = server port
	// agr[3] = clientpwd1
	// agr[4] = clientpwd2
	// agr[5] = clientpwd3
	// agr[6] = output file (creates file with name "output file" from 
	//	file received from server program
	
	fmt.Printf("Usage: ./client <server name> <server port> <clientpwd1> " +
	"<clientpwd2> <clientpwd3> <output file>\n")
	
}

func checkError(err error) {
	// If there is an error, abort!
	if err != nil {
		panic("ABORT")
	}
}

func JOIN_REQ_FUNC(conn net.Conn) {
	// Send the primeNumber as payload with JOIN_REQ packet
	joinReqObject := HeaderLength + PayloadLength + len(primeNumber)
	totalPayloadLength := uint32(len(primeNumber))
	userInput := make([]byte, joinReqObject)
	binary.LittleEndian.PutUint16(userInput[0:], JOIN_REQ)
	binary.LittleEndian.PutUint32(userInput[2:], totalPayloadLength)
	copy(userInput[6:], primeNumber)
	_, err := conn.Write(userInput)
	checkError(err)
}




func cipherFunc() cipher.AEAD {
	// Create key from hash of password
	add := sha256.Sum256([]byte(userPasswords[0]))
	key := add[0:]

	// Create new AES cipher block
	aesCipher, err := aes.NewCipher(key)
	checkError(err)

	// Wrap cipher block in Galois Counter Mode
	cipherGCM, err := cipher.NewGCM(aesCipher)
	checkError(err)

	return cipherGCM
}

func encryptionFunc(plaintext []byte) []byte {
	ciphertext := aes_block.Seal(nil, primeNumber, plaintext, nil)
	return ciphertext
}

func decryptionFunc(ciphertext []byte) []byte {
	plaintext, err := aes_block.Open(nil, primeNumber, ciphertext, nil)
	checkError(err)
	return plaintext
}

func checkDigest(packet []byte) bool {
	// Check the hash of the file, print "OK" or "ABORT"
	totalPayloadLength := binary.LittleEndian.Uint32(packet[0:])
	serverDigest := packet[4:] 
	// This is 0 because digest starts offset at Byte 7
	if int(totalPayloadLength) != len(serverDigest) {
		//fmt.Println("ABORT")
		return false
	}

	data, err := ioutil.ReadFile(outputFile)
	checkError(err)

	// Perform hash using SHA-1 on data
	digest := sha1.Sum(data)

	if len(serverDigest) != len(digest) {
		//fmt.Println("ABORT")
		return false
	}

	for i := 0; i < len(digest); i++ {
		if serverDigest[i] != digest[i] {
			//fmt.Println("ABORT")
			return false
		}
	}
	//fmt.Println("OK")
	return true
}

func handlePacketCONNX(conn net.Conn) {
	// Client sends a JOIN_REQ
	JOIN_REQ_FUNC(conn)

	// Allocate buffer as byte array, where 
	// (Header=2)+(Payload=4)+(Packetid=4)+(Data <= 1000) ==1010
	bufferObject := make([]byte, 1010)
	
	// used to cycle through the three user provided passwords, starting at 0
	password := 0

	// Create file 
	fileObject, err := os.Create(outputFile)
	defer fileObject.Close() // Close Create function
	checkError(err)

	// Pull in user input
	for {
		inputLength, err := conn.Read(bufferObject)
		checkError(err)
		plaintext := decryptionFunc(bufferObject[0:inputLength])
		// handle network byte order
		headerBytes := binary.LittleEndian.Uint16(plaintext[0:])

		switch headerBytes {
		case PASS_REQ:
			// Handle server password request
			passRespObject := HeaderLength + PayloadLength + len(userPasswords[password])
			totalPayloadLength := uint32(len(userPasswords[password]))
			userInput := make([]byte, passRespObject)
			binary.LittleEndian.PutUint16(userInput[0:], PASS_RESP)
			// 0 - 5 Bytes
			binary.LittleEndian.PutUint32(userInput[2:], totalPayloadLength) 
			// 
			copy(userInput[6:], []byte(userPasswords[password]))
			ciphertext := encryptionFunc(userInput)
			_, err := conn.Write(ciphertext)
			checkError(err)
			password++
			
		case PASS_ACCEPT:
			// Handle server accepting password
			// Go to DATA, fallthrough does not work
			
		case DATA:
			// Handle data server sends
			// Packetid := binary.LittleEndian.Uint32(bufferObject[6:10])
			/* data := plaintext[10:inputLength] */
			data := plaintext[10:] 
			// Data starts at Byte 11
			_, err := fileObject.Write(data)
			checkError(err)
			fileObject.Sync() // Sync flushes writes to stable storage
			
		case REJECT:
			fmt.Println("ABORT")
			return 
		case TERMINATE:
			checkDigest(plaintext[2:]) 
			// hash starts at Byte 7
			return 
		default:
			fmt.Println("ABORT")
			return 
		}
	}
}

func main() {

	// Fill primeNumber with random numbers
	if _, err := io.ReadFull(rand.Reader, primeNumber); err != nil {
		checkError(err)
	}

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
	server = args[1:3] 			// <server name> <server port>
	userPasswords = args[3:6] 	// <clientpwd1><clientpwd2><clientpwd3>
	outputFile = args[6] 		// <output file>

	// Convert string (server[1]) to integer
	_, err := strconv.Atoi(server[1])
	if err != nil {
		// if there is no error, print to screen expected command arguments
		usage()
		return
	}
	
	// Convert userPassword []string to []byte for en/decryption
	
	
	aes_block = cipherFunc()

	// Connect to server
	serverAddrPort := server[0] + ":" + server[1]
	
	// Dial function is "tcp/udp" "golang.org:80"
	// establish connection
	conn, err := net.Dial("udp", serverAddrPort)
	defer conn.Close() // defer ensures connection is closed
	checkError(err)

	handlePacketCONNX(conn)
}