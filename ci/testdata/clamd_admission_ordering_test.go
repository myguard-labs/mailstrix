package mailstrix

import (
	"bytes"
	"encoding/binary"
	"io"
	"runtime"
	"testing"
	"time"
)

// admissionClamdWaiterFrame binds the causal assertion to the production
// admission gate; a rename or relocation must update this fixture.
const admissionClamdWaiterFrame = "github.com/myguard-labs/mailstrix/internal/mailstrix.(*Server).acquireOn"

// TestClamdAdmissionBeforeRead proves INSTREAM takes the shared admission slot
// before consuming any chunk. net.Pipe is unbuffered, so a client Write
// completes only when the server reads it: while the gate is saturated the
// chunk write must stay blocked (no body byte buffered), and it completes only
// after a slot frees.
func TestClamdAdmissionBeforeRead(t *testing.T) {
	const timeout = 20 * time.Second
	body := bytes.Repeat([]byte{'x'}, 4096)
	engine := &clamdTestEngine{}
	s := NewServer(&Config{MaxConcurrent: 1, MaxInflight: 1, MaxBody: 1 << 20,
		BackendTimeout: timeout, ScanTimeout: timeout}, engine)
	for range cap(s.admit) {
		s.admit <- struct{}{}
	}
	released := false
	release := func() {
		if !released {
			released = true
			// Free exactly the slots taken above; a drain loop could steal
			// the slot the woken handler just acquired.
			for range cap(s.admit) {
				<-s.admit
			}
		}
	}
	t.Cleanup(release)

	_, client := clamdPipe(t, s)
	if err := client.SetDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(client, "zINSTREAM\x00"); err != nil {
		t.Fatalf("write command: %v", err)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	chunkDone := make(chan error, 1)
	go func() {
		_, err := client.Write(append(header[:], body...))
		chunkDone <- err
	}()

	stack := make([]byte, 1<<20)
	deadline := time.Now().Add(timeout)
	for {
		n := runtime.Stack(stack, true)
		if bytes.Contains(stack[:n], []byte(admissionClamdWaiterFrame)) {
			break
		}
		select {
		case err := <-chunkDone:
			t.Fatalf("INSTREAM chunk consumed (err=%v) before admission: body would be buffered while saturated", err)
		case <-time.After(time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("no handler reached %s", admissionClamdWaiterFrame)
		}
	}
	select {
	case err := <-chunkDone:
		t.Fatalf("INSTREAM chunk consumed (err=%v) while admission was saturated", err)
	case <-time.After(100 * time.Millisecond):
	}
	if got := engine.calls.Load(); got != 0 {
		t.Fatalf("scans while saturated = %d, want 0", got)
	}

	release()
	select {
	case err := <-chunkDone:
		if err != nil {
			t.Fatalf("chunk write after release: %v", err)
		}
	case <-time.After(timeout):
		t.Fatal("chunk not consumed after admission freed")
	}
	if _, err := client.Write([]byte{0, 0, 0, 0}); err != nil {
		t.Fatalf("write terminator: %v", err)
	}
	reply := make([]byte, len("stream: OK\x00"))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if string(reply) != "stream: OK\x00" {
		t.Fatalf("reply = %q, want stream: OK", reply)
	}
	if got := engine.calls.Load(); got != 1 {
		t.Fatalf("scans = %d, want 1", got)
	}
}
