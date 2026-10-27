//go:build linux

package egress_test

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/AmanamIsrael/lookout/event"
	"github.com/AmanamIsrael/lookout/sensor/egress"
)

// The probe needs root; run with `sudo -E go test ./tests/egress`.
func TestProbeSeesOutboundConnect(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load eBPF")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	var mu sync.Mutex
	var got []event.Egress
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- egress.Run(ctx, egress.Options{Loopback: true}, func(e event.Egress) {
			mu.Lock()
			got = append(got, e)
			mu.Unlock()
		})
	}()

	time.Sleep(500 * time.Millisecond) // let the probe attach
	for range 3 {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	time.Sleep(200 * time.Millisecond)
	cancel() // flushes the open window
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, e := range got {
		if e.DstPort == port && e.DstIP == "127.0.0.1" && e.PID == uint32(os.Getpid()) {
			if e.Count != 3 {
				t.Fatalf("count = %d, want 3", e.Count)
			}
			if e.Comm == "" {
				t.Fatal("empty comm")
			}
			return
		}
	}
	t.Fatalf("no flow to port %d in %+v", port, got)
}
