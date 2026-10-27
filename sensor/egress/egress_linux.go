// Package egress records outbound TCP connections with eBPF.
//
// A tiny program on the stable tracepoint sock/inet_sock_set_state fires when
// a socket enters SYN_SENT (an outbound connect) and writes the process,
// destination and port to a ring buffer. Userspace aggregates those into
// per-destination flows so a busy host ships a handful of rows a minute.
//
// The program is written with cilium/ebpf's assembler instead of C so the
// sensor builds with the Go toolchain alone. It needs CAP_BPF and CAP_PERFMON
// (or root) and Linux 5.8+ for ring buffers.
package egress

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/AmanamIsrael/lookout/event"
)

// Offsets in the tracepoint record. The layout is stable ABI since 4.16; see
// /sys/kernel/tracing/events/sock/inet_sock_set_state/format.
const (
	tpNewState = 20 // int
	tpDport    = 26 // __u16, host order
	tpFamily   = 28 // __u16
	tpProtocol = 30 // __u16
	tpDaddr    = 36 // __u8[4]
	tpDaddrV6  = 56 // __u8[16]

	tcpSynSent  = 2
	ipprotoTCP  = 6
	afInet      = 2
	afInet6     = 10
	recordSize  = 56
	flushWindow = 10 * time.Second
)

// Record layout written by the program:
//
//	0  u64 pid_tgid   8  u64 uid_gid   16 u16 family   18 u16 dport
//	20 [4]  daddr     24 [16] daddr6   40 [16] comm
func program(events *ebpf.Map) asm.Instructions {
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1), // r6 = tracepoint ctx
		asm.LoadMem(asm.R2, asm.R6, tpNewState, asm.Word),
		asm.JNE.Imm(asm.R2, tcpSynSent, "exit"),
		asm.LoadMem(asm.R2, asm.R6, tpProtocol, asm.Half),
		asm.JNE.Imm(asm.R2, ipprotoTCP, "exit"),

		asm.LoadMapPtr(asm.R1, events.FD()),
		asm.Mov.Imm(asm.R2, recordSize),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnRingbufReserve.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.Mov.Reg(asm.R7, asm.R0), // r7 = record

		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.R7, 0, asm.R0, asm.DWord),
		asm.FnGetCurrentUidGid.Call(),
		asm.StoreMem(asm.R7, 8, asm.R0, asm.DWord),

		asm.LoadMem(asm.R2, asm.R6, tpFamily, asm.Half),
		asm.StoreMem(asm.R7, 16, asm.R2, asm.Half),
		asm.LoadMem(asm.R2, asm.R6, tpDport, asm.Half),
		asm.StoreMem(asm.R7, 18, asm.R2, asm.Half),
		asm.LoadMem(asm.R2, asm.R6, tpDaddr, asm.Word),
		asm.StoreMem(asm.R7, 20, asm.R2, asm.Word),
	}
	for i := int16(0); i < 16; i += 4 {
		insns = append(insns,
			asm.LoadMem(asm.R2, asm.R6, tpDaddrV6+i, asm.Word),
			asm.StoreMem(asm.R7, 24+i, asm.R2, asm.Word),
		)
	}
	return append(insns,
		asm.Mov.Reg(asm.R1, asm.R7),
		asm.Add.Imm(asm.R1, 40),
		asm.Mov.Imm(asm.R2, 16),
		asm.FnGetCurrentComm.Call(),

		asm.Mov.Reg(asm.R1, asm.R7),
		asm.Mov.Imm(asm.R2, 0),
		asm.FnRingbufSubmit.Call(),

		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)
}

// Options configures Run.
type Options struct {
	// Loopback keeps connections to 127.0.0.0/8 and ::1. Off by default:
	// they are mostly the proxy talking to the app.
	Loopback bool
}

type flowKey struct {
	comm string
	uid  uint32
	dst  netip.Addr
	port uint16
}

type flow struct {
	pid   uint32
	count int
}

// Run loads the probe and emits aggregated flows until ctx is done.
// It returns early with an error if the kernel refuses the program.
func Run(ctx context.Context, opts Options, emit func(event.Egress)) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("memlock: %w", err)
	}
	events, err := ebpf.NewMap(&ebpf.MapSpec{Name: "lookout_egress", Type: ebpf.RingBuf, MaxEntries: 1 << 20})
	if err != nil {
		return fmt.Errorf("ring buffer: %w", err)
	}
	defer events.Close()

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "lookout_connect",
		Type:         ebpf.TracePoint,
		License:      "Dual MIT/GPL",
		Instructions: program(events),
	})
	if err != nil {
		return fmt.Errorf("load program: %w", err)
	}
	defer prog.Close()

	tp, err := link.Tracepoint("sock", "inet_sock_set_state", prog, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint: %w", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(events)
	if err != nil {
		return fmt.Errorf("ring reader: %w", err)
	}
	go func() {
		<-ctx.Done()
		rd.Close()
	}()
	slog.Info("egress probe attached")

	flows := map[flowKey]*flow{}
	windowStart := time.Now()
	rd.SetDeadline(windowStart.Add(flushWindow))
	for {
		rec, err := rd.Read()
		switch {
		case errors.Is(err, ringbuf.ErrClosed):
			flushFlows(flows, windowStart, emit)
			return nil
		case errors.Is(err, os.ErrDeadlineExceeded):
			// window boundary with no traffic
		case err != nil:
			return fmt.Errorf("ring read: %w", err)
		default:
			if k, pid, ok := parse(rec.RawSample, opts); ok {
				f := flows[k]
				if f == nil {
					f = &flow{}
					flows[k] = f
				}
				f.pid = pid
				f.count++
			}
		}
		if now := time.Now(); now.Sub(windowStart) >= flushWindow {
			flushFlows(flows, windowStart, emit)
			clear(flows)
			windowStart = now
			rd.SetDeadline(now.Add(flushWindow))
		}
	}
}

func parse(b []byte, opts Options) (flowKey, uint32, bool) {
	if len(b) < recordSize {
		return flowKey{}, 0, false
	}
	ne := binary.NativeEndian
	pid := uint32(ne.Uint64(b[0:8]) >> 32)
	uid := uint32(ne.Uint64(b[8:16]))
	var dst netip.Addr
	switch ne.Uint16(b[16:18]) {
	case afInet:
		dst = netip.AddrFrom4([4]byte(b[20:24]))
	case afInet6:
		dst = netip.AddrFrom16([16]byte(b[24:40])).Unmap()
	default:
		return flowKey{}, 0, false
	}
	if dst.IsLoopback() && !opts.Loopback {
		return flowKey{}, 0, false
	}
	comm := b[40:56]
	n := 0
	for n < len(comm) && comm[n] != 0 {
		n++
	}
	return flowKey{comm: string(comm[:n]), uid: uid, dst: dst, port: ne.Uint16(b[18:20])}, pid, true
}

func flushFlows(flows map[flowKey]*flow, ts time.Time, emit func(event.Egress)) {
	for k, f := range flows {
		emit(event.Egress{
			TS: ts.UTC(), Comm: k.comm, PID: f.pid, UID: k.uid,
			DstIP: k.dst.String(), DstPort: k.port, Count: f.count,
		})
	}
}
