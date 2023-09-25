package main

import (
	"fmt"
	"math/rand"
	"net"
	"time"
	"strconv"
	"crypto/rand"
	"math/big"
)

var (
  s=100000
)

func main() {
	// rand.Seed(time.Now().UnixNano())

	conn, err := net.Dial("tcp", "localhost:873")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// s := big.NewInt(6)
	v := schnorr.ComputeV(s)

  // MORE
	r, t := schnorr.ProverStep1(s)

	// Send random value to server
	randomValue := rand.Intn(1000)  // Generating a random integer between 0 and 999
	conn.Write([]byte(strconv.Itoa(randomValue)))

	// Read the server's response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Read error:", err)
		return
	}

  // verify
	c, err := strconv.Atoi(string(buf[:n]))
	if err != nil {
		fmt.Println("Parsing error:", err)
		return
	}

  // send back proof
  u := schnorr.ProverStep2(r, s, c)
	conn.Write([]byte(strconv.Itoa(u)))

	fmt.Printf("ggwp")
}
