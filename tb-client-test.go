package main

import (
	"fmt"
	"net"
	"math/big"
  "tunnelbees/schnorr"
  "encoding/gob"
  // "golang.org/x/crypto/ssh"
	"crypto/sha256"
)

func hashWithSalt(secret, salt *big.Int) *big.Int {
	// Convert big integers to byte slices
	secretBytes := secret.Bytes()
	saltBytes := salt.Bytes()

	// Concatenate the byte slices
	data := append(secretBytes, saltBytes...)

	// Compute the SHA-256 hash
	hash := sha256.Sum256(data)

	// Convert the hash byte slice to a big.Int
	result := new(big.Int).SetBytes(hash[:])

	return result
}

// pre-shared values
var (
	p, _ = new(big.Int).SetString("12588057984461468961966693540164904601152983345615838509514868338002626947197477099497403176194401173056566443611515270833375716896028986193824336206303327", 10)
  g, _ = new(big.Int).SetString("11179447687932368032971008183842477549658090437538077136108714448239465001794961282450659618511557431978875393280381023360031838986891268787469410372745240", 10)
  x, _ = new(big.Int).SetString("6600495238930282724775951968977863908730082011153634922546217452020847861263182799684298041206237926208133583019216464197508425556590763281008607933597182", 10)
  handshakePort = 312
)

func main() {

	conn, err := net.Dial("tcp", fmt.Sprintf(":%d", handshakePort))
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Client does the keygen
	// _, _, _, _ := schnorr.Keygen(512)
  // y := new(big.Int).Exp(g, x, p)  // Compute y using predefined x
	t, r := schnorr.ProverCommitment(p, g)

	encoder := gob.NewEncoder(conn)
	// Send the commitment to the server
	err = encoder.Encode(&struct {
		// P *big.Int
		// G *big.Int
		// Y *big.Int
		T *big.Int
	}{t})

	if err != nil {
		panic(err)
	}

	// Receive challenge from the server
	decoder := gob.NewDecoder(conn)
	var c *big.Int
	err = decoder.Decode(&c)
	if err != nil {
		panic(err)
	}

	// Calculate and send the response
	s := schnorr.ProverResponse(r, c, x, p)
	err = encoder.Encode(s)
	if err != nil {
		panic(err)
	}

	// Receive the verification result from the server
	var verificationResult string
	err = decoder.Decode(&verificationResult)
	if err != nil {
		panic(err)
	}

  if verificationResult == "vs" {
    pq := new(big.Int)
    pq.SetString("4096", 10)
    port := int(hashWithSalt(t, x).Mod(hashWithSalt(t, x), pq).Int64())
    if port == 53 || port == handshakePort { 
      port++
    }
    // calculate the right port

    fmt.Println("ssh open on port for 10s", port)

  }


}
