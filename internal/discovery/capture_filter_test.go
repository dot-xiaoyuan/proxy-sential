package discovery

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/net/bpf"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDiscoveryFilterRejectsUnrelatedTaggedTraffic(t *testing.T) {
	tcpdump, e := exec.LookPath("tcpdump")
	if e != nil {
		t.Skip("tcpdump BPF compiler unavailable")
	}
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header, 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:], 2)
	binary.LittleEndian.PutUint16(header[6:], 4)
	binary.LittleEndian.PutUint32(header[16:], 65535)
	binary.LittleEndian.PutUint32(header[20:], 1)
	path := filepath.Join(t.TempDir(), "empty.pcap")
	if e = os.WriteFile(path, header, 0600); e != nil {
		t.Fatal(e)
	}
	raw, e := exec.Command(tcpdump, "-ddd", "-r", path, DiscoveryCaptureFilter()).Output()
	if e != nil {
		t.Fatalf("%v: %s", e, raw)
	}
	reader := bytes.NewReader(raw)
	var n int
	fmt.Fscan(reader, &n)
	instructions := make([]bpf.RawInstruction, n)
	for i := range instructions {
		if _, e = fmt.Fscan(reader, &instructions[i].Op, &instructions[i].Jt, &instructions[i].Jf, &instructions[i].K); e != nil {
			t.Fatal(e)
		}
	}
	asm, all := bpf.Disassemble(instructions)
	if !all {
		t.Fatal("invalid BPF")
	}
	vm, e := bpf.NewVM(asm)
	if e != nil {
		t.Fatal(e)
	}
	for _, tags := range []int{0, 1, 2} {
		for _, port := range []int{443, 53, 5353, 1900, 3702, 161, 5683, 47808} {
			off := 14 + tags*4
			f := make([]byte, off+28)
			binary.BigEndian.PutUint16(f[12:14], 0x0800)
			for i := 0; i < tags; i++ {
				binary.BigEndian.PutUint16(f[12+i*4:14+i*4], 0x8100)
				binary.BigEndian.PutUint16(f[16+i*4:18+i*4], 0x0800)
			}
			f[off] = 0x45
			f[off+9] = 17
			binary.BigEndian.PutUint16(f[off+22:off+24], uint16(port))
			got, e := vm.Run(f)
			if e != nil {
				t.Fatal(e)
			}
			want := port != 443 && port != 53
			if (got > 0) != want {
				t.Fatalf("tags=%d port=%d got=%d", tags, port, got)
			}
		}
	}
}
