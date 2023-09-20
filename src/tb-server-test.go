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
  "time"
  "errors"
)

var (
    errBadPassword = errors.New("permission denied")
    privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
    signer, _ = ssh.NewSignerFromSigner(privateKey)
    stopChannels = make(map[int]chan struct{})
    switchStopChannels = make(map[int]chan struct{})
    username="testuser"
    password="password"
)

func main() {
    // logPath := fmt.Sprintf("/var/log/babygorilla-%s.log", time.Now().Format("2006-01-02-15-04-05-000"))
    logPath := fmt.Sprintf("/var/log/tunnelbees.log", time.Now().Format("2006-01-02-15-04-05-000"))
    logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
    if err != nil {
        log.Println("Failed to open log file:", logPath, err)
    } else {
        log.SetOutput(io.MultiWriter(logFile, os.Stdout))
    }

    defer logFile.Close()

    log.SetFlags(log.LstdFlags | log.Lmicroseconds)



    for i := 0; i < 4096; i++ {
        stop := make(chan struct{})
        stopChannels[i] = stop
        go listenToPortHP(i, signer, stop)
    }

    // to close:
    // close(stopChannels[2022])

    // to re-open:
    // stopq := make(chan struct{})
    // stopChannels[2022] = stopq
    // go listenToPortHP(2022, signer, stopq)

    go switchHP(66)


	  time.Sleep(10 * time.Second)
    go stopSwitchHP(66)

    

    wait := make(chan struct{})
    <-wait
}

func listenToPortHP(port int, signer ssh.Signer, stop <-chan struct{}) {
    listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
    if err != nil {
        log.Println("Failed to listen on port:", port, err)
        return
    }

    go func() {
        <-stop
        listener.Close()
    }()

    // randomize server version to mess with nmap
    base := "SSH-2.0-OpenSSH_"
    // random := make([]byte, 65536)
    random := make([]byte, 12)
    rand.Read(random)
    ver := fmt.Sprintf("%s%x", base, random)

    serverConfig := &ssh.ServerConfig{
        MaxAuthTries:     6,
        PasswordCallback: passwordCallbackHP,
        ServerVersion:    ver,
    }

    serverConfig.AddHostKey(signer)

    for {
        conn, err := listener.Accept()
        if err != nil {
            continue
        }
        go handleConnHP(conn, serverConfig)
    }
}

func passwordCallbackHP(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
    log.Println(conn.RemoteAddr(), string(conn.ClientVersion()), conn.User(), string(password))
    return nil, errBadPassword
}

func handleConnHP(conn net.Conn, serverConfig *ssh.ServerConfig) {
    defer conn.Close()
    ssh.NewServerConn(conn, serverConfig)
}

func switchHP(port int) {
  if stopChannels[port] == nil {
    return
  }
  close(stopChannels[port])
  delete(stopChannels, port)

  // wait for sys to refresh so we can re-bind port
	time.Sleep(1 * time.Second)

  defer func(p int) {
      stopq := make(chan struct{})
      stopChannels[p] = stopq
      go listenToPortHP(p, signer, stopq)
  }(port)

  stopCh := make(chan struct{})
  switchStopChannels[port] = stopCh

	hostConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == username && string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

  hostConfig.AddHostKey(signer)

  listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))

  go func() {
      <-stopCh
      listener.Close()
  }()

	if err != nil {
		log.Fatalf("Failed to listen on %s (%v)", port, err)
	}

  for {
      nConn, err := listener.Accept()
      if err != nil {
          if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
              continue
          }
          // This means the error is more serious and we should stop trying to accept connections.
          // For instance, if our listener was closed.
          break
      }

      go handleSSHConnection(nConn, hostConfig)
  }

}

func stopSwitchHP(port int) {
    if ch, ok := switchStopChannels[port]; ok {
        close(ch)
        delete(switchStopChannels, port)
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
