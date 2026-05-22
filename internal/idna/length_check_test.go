package idna_test

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/idna"
)

// TestToASCII_ASCIIPath_RejectsOversizeLabel ensures the pure-ASCII
// fast path of ToASCII enforces the 63-byte label cap (RFC 1035
// §2.3.4 / RFC 5891 §4.4). Without the fix the function returned
// the oversized label unchanged.
func TestToASCII_ASCIIPath_RejectsOversizeLabel(t *testing.T) {
	label := strings.Repeat("a", 64)
	_, err := idna.ToASCII(label + ".example.com")
	if err == nil {
		t.Fatal("expected ErrLabelTooLong for 64-byte ASCII label")
	}
}

func TestToASCII_ASCIIPath_RejectsOversizeName(t *testing.T) {
	// Build > 255 byte ASCII domain
	var sb strings.Builder
	for i := 0; i < 50; i++ {
		sb.WriteString("abcdefghij.")
	}
	sb.WriteString("com")
	domain := sb.String()
	if len(domain) <= 255 {
		t.Fatalf("test setup: domain must exceed 255 bytes, got %d", len(domain))
	}
	if _, err := idna.ToASCII(domain); err == nil {
		t.Fatal("expected ErrNameTooLong for >255-byte ASCII domain")
	}
}
