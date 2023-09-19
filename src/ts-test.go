package main

import (
	"crypto/rand"
	"crypto/rsa"
  "github.com/creack/pty"
  "os/exec"
	"fmt"
	"log"
	"net"
  "encoding/binary"
	"golang.org/x/crypto/ssh"
  "os"
  "syscall"
  "unsafe"
  "io"
)

const (
	port = ":2022"
)

func main() {
	// Generate RSA Key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	signer, err := ssh.NewSignerFromSigner(privateKey)
	if err != nil {
		log.Fatalf("Failed to create SSH signer from RSA key: %v", err)
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "testuser" && string(pass) == "testpass" {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Failed to listen on %s (%v)", port, err)
	}

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%v)", err)
			continue
		}

		go handleSSHConnection(nConn, config)
	}
}


func handleSSHConnection(nConn net.Conn, config *ssh.ServerConfig) {
    conn, chans, _, err := ssh.NewServerConn(nConn, config)
    if err != nil {
        log.Printf("Failed to handshake (%v)", err)
        return
    }
    log.Printf("New SSH connection from %s (%s)", conn.RemoteAddr(), conn.ClientVersion())

    for newChannel := range chans {
        if newChannel.ChannelType() != "session" {
            newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
            continue
        }
        go handleChannel(newChannel)
    }
}

func SetWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

func parseDims(b []byte) (width, height int) {
    width = int(binary.BigEndian.Uint32(b))
    height = int(binary.BigEndian.Uint32(b[4:]))
    return
}


func handleChannel(newChannel ssh.NewChannel) {
    channel, requests, err := newChannel.Accept()
    if err != nil {
        log.Printf("Could not accept channel: %v", err)
        return
    }
    defer channel.Close()

    var w, h int
    // Ensure all global requests are serviced.
    go func(in <-chan *ssh.Request) {
        for req := range in {
            switch req.Type {
            case "shell":
                req.Reply(true, nil) 
            case "pty-req":
                w, h = parseDims(req.Payload[4:]) // Extracting width and height
                req.Reply(true, nil)
            case "window-change":
                w, h = parseDims(req.Payload)
                // You'd handle terminal resizing here but we need the pty's file descriptor
                continue // no reply for this one
            // We should reply to unknown requests as well, otherwise the SSH client might hang
            default:
                if req.WantReply {
                    req.Reply(false, nil)
                }
            }
        }
    }(requests)

    runShell(channel, w, h)
}

// ...

func runShell(ch ssh.Channel, w int, h int) {
    cmd := exec.Command("/bin/sh")
    
    // Start the command with a pty.
    ptmx, err := pty.Start(cmd)
    if err != nil {
        log.Printf("Failed to start command with pty: %v", err)
        return
    }
    defer func() { _ = ptmx.Close() }() // Safely ignore the error from closing

    SetWinsize(ptmx, w, h)

    go func() {
        _, _ = io.Copy(ch, ptmx)
        ch.Close()
    }()
    go func() {
        _, _ = io.Copy(ptmx, ch)
    }()

    cmd.Wait()
    ch.Close()
}

// SetWinsize as before...


