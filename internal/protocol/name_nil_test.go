package protocol

import "testing"

func TestNameNilReceiverSafe(t *testing.T) {
	var n *Name

	if got := n.String(); got != "." {
		t.Fatalf("nil Name String() = %q, want root name", got)
	}
	if !n.IsRoot() {
		t.Fatal("nil Name IsRoot() = false, want true")
	}
	if n.IsWildcard() {
		t.Fatal("nil Name IsWildcard() = true, want false")
	}
	if n.HasPrefix([]string{"www"}) {
		t.Fatal("nil Name HasPrefix(non-empty) = true, want false")
	}
	if n.HasSuffix([]string{"example"}) {
		t.Fatal("nil Name HasSuffix(non-empty) = true, want false")
	}
	if got := n.WireLength(); got != 1 {
		t.Fatalf("nil Name WireLength() = %d, want root wire length", got)
	}

	buf := make([]byte, 1)
	written, err := PackName(n, buf, 0, nil)
	if err != nil {
		t.Fatalf("PackName(nil) returned error: %v", err)
	}
	if written != 1 || buf[0] != 0 {
		t.Fatalf("PackName(nil) wrote n=%d buf=%v, want root wire name", written, buf)
	}
}
