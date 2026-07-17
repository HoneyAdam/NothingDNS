package idna

import "testing"

// Regression: isUnassigned was a placeholder returning false, so
// AllowUnassigned=false never rejected anything. It now consults the Go
// toolchain's Unicode tables (category Cn = absent from every table).
func TestIsUnassigned(t *testing.T) {
	assigned := []rune{'a', 'é', 'ü', '中', 'א', 'ع', '9', 0x00E9}
	for _, r := range assigned {
		if isUnassigned(r) {
			t.Errorf("isUnassigned(%U) = true, want false (assigned)", r)
		}
	}
	unassigned := []rune{
		0x0378,   // unassigned in the Greek block
		0x2FE0,   // unassigned range
		0xE01F0,  // beyond variation selectors supplement
		0x10FFFE, // plane-16 noncharacter (no category)
	}
	for _, r := range unassigned {
		if !isUnassigned(r) {
			t.Errorf("isUnassigned(%U) = false, want true", r)
		}
	}
	if !isUnassigned(-1) || !isUnassigned(0x110000) {
		t.Error("out-of-range runes must be treated as unassigned")
	}
}
