package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// waitTimeout bounds how long a first peer waits for its pair. Previously a
// peer that dialed and disconnected left its conn in the map forever (leak),
// and a second peer would splice to a dead conn.
const waitTimeout = 60 * time.Second

type waiter struct {
	conn net.Conn
	at   time.Time
}

var (
	sessions = make(map[string]waiter)
	mu       sync.Mutex
)

func handle(conn net.Conn) {
	// Bound the handshake read so dead peers can't hold a goroutine forever.
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("relay read session: %v", err)
		conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	line = strings.TrimSpace(line)
	parts := strings.Fields(line)
	if len(parts) < 2 || strings.ToUpper(parts[0]) != "RELAY" {
		log.Printf("invalid relay handshake: %q from %s", line, conn.RemoteAddr())
		conn.Close()
		return
	}
	session := parts[1]
	log.Printf("RELAY %s from %s", session, conn.RemoteAddr())

	mu.Lock()
	w, ok := sessions[session]
	if !ok {
		sessions[session] = waiter{conn: conn, at: time.Now()}
		mu.Unlock()
		log.Printf("Session %s waiting for peer", session)
		// Evict if no pair arrives in time (fixes the map leak).
		time.AfterFunc(waitTimeout, func() {
			mu.Lock()
			if cur, still := sessions[session]; still && cur.conn == conn {
				delete(sessions, session)
				mu.Unlock()
				log.Printf("Session %s wait timeout, closing", session)
				conn.Close()
				return
			}
			mu.Unlock()
		})
		return
	}
	delete(sessions, session)
	mu.Unlock()
	other := w.conn
	log.Printf("Session %s pairing %s <-> %s", session, other.RemoteAddr(), conn.RemoteAddr())

	// Splice both ways. `reader` wraps conn, so copying from `reader` alone
	// covers buffered + future bytes (a second Copy from conn would deadlock
	// on the drained stream).
	go func() {
		_, _ = io.Copy(other, reader)
		other.Close()
		conn.Close()
	}()
	_, _ = io.Copy(conn, other)
	other.Close()
	conn.Close()
	log.Printf("Session %s closed", session)
}

func main() {
	addr := flag.String("addr", ":5590", "relay listen address")
	flag.Parse()
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	fmt.Printf("[*] Relay listening on %s (RELAY <session>)\n", *addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(conn)
	}
}
