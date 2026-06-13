package idna

import "testing"

// RFC 3492 §7.1 sample vectors. These are regression tests for the adapt()
// bias-adaptation bug: the non-first branch divided delta by skew (38)
// instead of by 2 (RFC 3492 §6.1 "delta div 2"), corrupting every label
// with two or more encoded (non-basic) code points on both the encode and
// decode paths. Single-codepoint labels (e.g. "mnchen-3ya") were unaffected,
// which is why the pre-existing tests did not catch it.
//
// unicode strings are written with \u escapes to match the RFC's code-point
// listings exactly (the RFC samples use lowercase basic code points here).
var rfc3492Vectors = []struct {
	name    string
	unicode string
	puny    string
}{
	{
		// §7.1 (A) Arabic (Egyptian)
		name: "A_arabic_egyptian",
		unicode: "ليهمابتكل" +
			"موشعربي؟",
		puny: "egbpdaj6bu4bxfgehfvwxn",
	},
	{
		// §7.1 (B) Chinese (simplified)
		name:    "B_chinese_simplified",
		unicode: "他们为什么不说中文",
		puny:    "ihqwcrb4cv8a8dqg056pqjye",
	},
	{
		// §7.1 (L) Japanese 3<nen>B<gumi><kinpachi><sensei>, with the
		// basic code point "b" lowercase (punycode preserves basic
		// code-point case; the RFC sample uses "B"/"3B-...", this is the
		// lowercased equivalent produced by the IDNA mapping step).
		name:    "L_japanese_3nen_b_gumi",
		unicode: "3年b組金八先生",
		puny:    "3b-ww4c5e180e575a65lsy2b",
	},
	{
		// Simple single-delimiter case: münich (one basic-prefix label
		// with a single encoded code point plus a real '-' delimiter).
		name:    "simple_muenich",
		unicode: "münich",
		puny:    "mnich-kva",
	},
}

func TestEncodePunycode_RFC3492Vectors(t *testing.T) {
	for _, tt := range rfc3492Vectors {
		t.Run(tt.name, func(t *testing.T) {
			got := encodePunycode(tt.unicode)
			if got != tt.puny {
				t.Errorf("encodePunycode(%q) = %q, want %q", tt.unicode, got, tt.puny)
			}
		})
	}
}

func TestDecodePunycode_RFC3492Vectors(t *testing.T) {
	for _, tt := range rfc3492Vectors {
		t.Run(tt.name, func(t *testing.T) {
			got := decodePunycode(tt.puny)
			if got != tt.unicode {
				t.Errorf("decodePunycode(%q) = %q, want %q", tt.puny, got, tt.unicode)
			}
		})
	}
}

// Round-trip through the public ToASCII / ToUnicode entry points using the
// multi-codepoint Japanese sample (the case the adapt() bug broke).
func TestToASCIIToUnicode_RFC3492RoundTrip(t *testing.T) {
	tests := []struct {
		unicodeDomain string
		asciiDomain   string
	}{
		{"3年b組金八先生.example", "xn--3b-ww4c5e180e575a65lsy2b.example"},
		{"münich.example", "xn--mnich-kva.example"},
	}

	for _, tt := range tests {
		ascii, err := ToASCII(tt.unicodeDomain)
		if err != nil {
			t.Fatalf("ToASCII(%q) error: %v", tt.unicodeDomain, err)
		}
		if ascii != tt.asciiDomain {
			t.Errorf("ToASCII(%q) = %q, want %q", tt.unicodeDomain, ascii, tt.asciiDomain)
		}

		uni, err := ToUnicode(tt.asciiDomain)
		if err != nil {
			t.Fatalf("ToUnicode(%q) error: %v", tt.asciiDomain, err)
		}
		if uni != tt.unicodeDomain {
			t.Errorf("ToUnicode(%q) = %q, want %q", tt.asciiDomain, uni, tt.unicodeDomain)
		}
	}
}
