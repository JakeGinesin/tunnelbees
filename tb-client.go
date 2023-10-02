package main

import (
	"fmt"
	"net"
	"math/big"
  "tunnelbees/schnorr"
  "encoding/gob"
  "golang.org/x/crypto/ssh"
	"io"
	"os"
	"golang.org/x/crypto/ssh/terminal"
  "time"
  "tunnelbees/crypto"
)


// pre-shared values
var (
	p, _ = new(big.Int).SetString("12588057984461468961966693540164904601152983345615838509514868338002626947197477099497403176194401173056566443611515270833375716896028986193824336206303327", 10)
  g, _ = new(big.Int).SetString("11179447687932368032971008183842477549658090437538077136108714448239465001794961282450659618511557431978875393280381023360031838986891268787469410372745240", 10)
  x, _ = new(big.Int).SetString("6600495238930282724775951968977863908730082011153634922546217452020847861263182799684298041206237926208133583019216464197508425556590763281008607933597182", 10)
  handshakePort = 312
  username="testuser"
  host="localhost"
)

func main() {

	conn, err := net.Dial("tcp", fmt.Sprintf(":%d", handshakePort))
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	t, r := schnorr.ProverCommitment(p, g)

	encoder := gob.NewEncoder(conn)

	// Send the commitment to the server
	err = encoder.Encode(&struct {
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
    port := int(crypto.HashWithSalt(t, x).Mod(crypto.HashWithSalt(t, x), pq).Int64())
    if port == 53 || port == handshakePort { 
      port++
    }

    time.Sleep(2 * time.Second)

    // SSH into the determined port
    // super shit lol should be public key
    sshConfig := &ssh.ClientConfig{
        User: "testuser",
        Auth: []ssh.AuthMethod{
            ssh.Password("password"), 
        },
        HostKeyCallback: ssh.InsecureIgnoreHostKey(), // WARNING: This is insecure and should be replaced with proper host key verification for production
    }

    sshAddress := fmt.Sprintf("%s:%d", host, port) // Assuming localhost, replace '127.0.0.1' if needed
    sshClient, err := ssh.Dial("tcp", sshAddress, sshConfig)
    if err != nil {
        panic(err)
    }
    defer sshClient.Close()

		// Step 1: Create an SSH session
		session, err := sshClient.NewSession()
		if err != nil {
			panic(err)
		}
		defer session.Close()

		// Step 2: Setup terminal for interaction
		fd := int(os.Stdin.Fd())
		oldState, err := terminal.MakeRaw(fd)
		if err != nil {
			panic(err)
		}
		defer terminal.Restore(fd, oldState) // restore old terminal settings at the end

		// Redirect IO for communication
		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
		session.Stdin = os.Stdin

		// Create a terminal for this session.
		termWidth, termHeight, err := terminal.GetSize(fd)
		if err != nil {
			termWidth = 80
			termHeight = 24
		}

		// Request pty (pseudo terminal) in xterm with given dimensions
		err = session.RequestPty("xterm", termHeight, termWidth, ssh.TerminalModes{})
		if err != nil {
			panic(err)
		}

		// Step 3: Start a shell
		err = session.Shell()
		if err != nil {
			panic(err)
		}

		// Step 4: Wait until the session completes
		err = session.Wait()
		if err != nil && err != io.EOF {
			panic(err)
		}

  }
}
