package netutils

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Overlapping fragments with IP options or a truncated capture must be
// rejected, not panic. A panic in the defragger goroutine stops the whole
// process.
func TestIpDefrag_IPv4MalformedOverlapDoesNotPanic(t *testing.T) {
	src := net.IP{10, 0, 0, 1}
	nop := layers.IPv4Option{OptionType: 1, OptionLength: 1}
	truncated := func(p gopacket.Packet, n int) gopacket.Packet {
		return gopacket.NewPacket(p.Data()[:len(p.Data())-n], layers.LayerTypeEthernet, gopacket.Default)
	}

	tests := []struct {
		name  string
		frags []gopacket.Packet
	}{
		{
			name: "IP options on an overlapping fragment",
			frags: []gopacket.Packet{
				newIPv4Fragment(t, src, 7, 0, true, make([]byte, 236), time.Time{}),
				newIPv4Fragment(t, src, 7, 55, true, make([]byte, 64), time.Time{}),
				newIPv4Fragment(t, src, 7, 4, false, make([]byte, 200), time.Time{}, nop, nop, nop, nop),
			},
		},
		{
			name: "truncated overlapping fragment",
			frags: []gopacket.Packet{
				newIPv4Fragment(t, src, 8, 0, true, make([]byte, 16), time.Time{}),
				newIPv4Fragment(t, src, 8, 5, true, make([]byte, 8), time.Time{}),
				truncated(newIPv4Fragment(t, src, 8, 1, false, make([]byte, 24), time.Time{}), 21),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("DefragIP panicked: %v", r)
				}
			}()
			defragger := NewIPDefragmenter()
			for _, frag := range tc.frags {
				_, _ = defragger.DefragIP(frag)
			}
		})
	}
}

// The fragment lengths must come from the header length in IHL, not from a
// fixed 20 bytes, or a datagram with IP options reassembles wrong.
func TestIpDefrag_IPv4FragmentsWithOptions(t *testing.T) {
	src := net.IP{10, 0, 0, 1}
	nop := layers.IPv4Option{OptionType: 1, OptionLength: 1}
	first := bytes.Repeat([]byte{0xaa}, 16)
	last := bytes.Repeat([]byte{0xbb}, 8)

	defragger := NewIPDefragmenter()
	if _, err := defragger.DefragIP(newIPv4Fragment(t, src, 9, 0, true, first, time.Time{}, nop, nop, nop, nop)); err != nil {
		t.Fatalf("unexpected error on the 1st fragment: %v", err)
	}
	pkt, err := defragger.DefragIP(newIPv4Fragment(t, src, 9, 2, false, last, time.Time{}, nop, nop, nop, nop))
	if err != nil {
		t.Fatalf("unexpected error on the 2nd fragment: %v", err)
	}
	if pkt == nil {
		t.Fatal("datagram with IP options not reassembled")
	}
	ip4 := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if want := append(append([]byte(nil), first...), last...); !bytes.Equal(ip4.Payload, want) {
		t.Errorf("reassembled payload = %x, want %x", ip4.Payload, want)
	}
}
