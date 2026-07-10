package idna

import (
	"strings"
	"testing"
)

// TestDecodePunycode_NoOverflowPanic verifies that crafted punycode suffixes
// engineered to overflow the RFC 3492 accumulators (driving the insertion index
// negative) no longer panic with "slice bounds out of range" — they bail out
// and return the decoded prefix instead.
func TestDecodePunycode_NoOverflowPanic(t *testing.T) {
	inputs := []string{
		strings.Repeat("z", 300),         // max base-36 digit repeated
		strings.Repeat("9", 300),         // high digits
		"a-" + strings.Repeat("z", 200),  // with a basic prefix
		strings.Repeat("z9", 150),        // alternating
		strings.Repeat("zzzzzzzzzz", 40), // 400 max digits
		"xn--" + strings.Repeat("z", 128),
	}
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("decodePunycode(%q...) panicked: %v", in[:min(len(in), 12)], r)
				}
			}()
			_ = decodePunycode(in) // must not panic
		}()
	}
}
