package zone

import (
	"testing"
)

func TestRadixTree_InsertAndFind(t *testing.T) {
	z1 := &Zone{Origin: "example.com."}
	z2 := &Zone{Origin: "example.org."}
	z3 := &Zone{Origin: "com."}
	z4 := &Zone{Origin: "org."}
	z5 := &Zone{Origin: "."} // root zone

	tree := NewRadixTree()
	tree.Insert("example.com.", z1)
	tree.Insert("example.org.", z2)
	tree.Insert("com.", z3)
	tree.Insert("org.", z4)
	tree.Insert(".", z5)

	tests := []struct {
		name     string
		qname    string
		expected *Zone
	}{
		{"exact www.example.com", "www.example.com.", z1},
		{"exact example.com", "example.com.", z1},
		{"exact example.org", "example.org.", z2},
		{"closest encloser www.example.com", "www.example.com.", z1},
		{"closest encloser mail.example.com", "mail.example.com.", z1},
		{"closest encloser api.example.org", "api.example.org.", z2},
		{"root zone", ".", z5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tree.Find(tt.qname)
			if got != tt.expected {
				if tt.expected == nil {
					t.Errorf("expected nil, got %v", got)
				} else {
					t.Errorf("expected %v, got %v", tt.expected.Origin, got.Origin)
				}
			}
		})
	}
}

func TestRadixTree_BuildAndFind(t *testing.T) {
	zones := map[string]*Zone{
		"example.com.": {Origin: "example.com."},
		"example.org.": {Origin: "example.org."},
		"com.":         {Origin: "com."},
	}

	tree := BuildRadixTree(zones)

	if got := tree.Find("www.example.com."); got == nil || got.Origin != "example.com." {
		t.Errorf("www.example.com.: expected example.com., got %v", got)
	}
	if got := tree.Find("example.com."); got == nil || got.Origin != "example.com." {
		t.Errorf("example.com.: expected example.com., got %v", got)
	}
	if got := tree.Find("foo.bar.example.org."); got == nil || got.Origin != "example.org." {
		t.Errorf("foo.bar.example.org.: expected example.org., got %v", got)
	}
}

func TestRadixTree_List(t *testing.T) {
	zones := map[string]*Zone{
		"example.com.":     {Origin: "example.com."},
		"sub.example.com.": {Origin: "sub.example.com."},
		".":                {Origin: "."},
	}

	tree := BuildRadixTree(zones)
	list := tree.List()
	if len(list) != len(zones) {
		t.Fatalf("List len = %d, want %d", len(list), len(zones))
	}
	for origin, want := range zones {
		if got := list[origin]; got != want {
			t.Fatalf("List()[%q] = %v, want %v", origin, got, want)
		}
	}

	var nilTree *RadixTree
	if got := nilTree.List(); len(got) != 0 {
		t.Fatalf("nil RadixTree List len = %d, want 0", len(got))
	}
}

func TestRadixTree_ZeroValueAndNilReceiverSafe(t *testing.T) {
	z := &Zone{Origin: "example.com."}

	var tree RadixTree
	tree.Insert("example.com.", z)
	if got := tree.Find("www.example.com."); got != z {
		t.Fatalf("zero-value RadixTree Find() = %v, want inserted zone", got)
	}
	if list := tree.List(); list["example.com."] != z {
		t.Fatalf("zero-value RadixTree List()[example.com.] = %v, want inserted zone", list["example.com."])
	}

	var nilTree *RadixTree
	nilTree.Insert("example.net.", &Zone{Origin: "example.net."})
	if got := nilTree.Find("example.net."); got != nil {
		t.Fatalf("nil RadixTree Find() = %v, want nil", got)
	}
}

func TestSplitDomainReversed(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"simple", "example.com.", []string{"com", "example"}},
		{"subdomain", "www.example.com.", []string{"com", "example", "www"}},
		{"three labels", "mail.google.com.", []string{"com", "google", "mail"}},
		{"single label", "localhost.", []string{"localhost"}},
		{"root", ".", []string{"."}},
		{"empty", "", []string{""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitDomainReversed(tt.input)
			if len(got) != len(tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, got)
				return
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("expected %v, got %v", tt.expected, got)
					return
				}
			}
		})
	}
}

// TestRadixTree_CaseInsensitive verifies RFC 1035 §2.3.3 case-insensitive
// matching: a zone inserted as "EXAMPLE.COM." must match queries in any case
// (e.g. "example.com.", "Example.Com.", "EXAMPLE.COM.") and vice versa.
func TestRadixTree_CaseInsensitive(t *testing.T) {
	tree := NewRadixTree()
	upper := &Zone{Origin: "EXAMPLE.COM."}
	tree.Insert("EXAMPLE.COM.", upper)

	cases := []string{
		"example.com.",
		"EXAMPLE.COM.",
		"Example.Com.",
		"www.example.com.",
		"WWW.EXAMPLE.COM.",
		"WwW.eXaMpLe.CoM.",
	}
	for _, q := range cases {
		if got := tree.Find(q); got != upper {
			t.Errorf("Find(%q) did not match zone inserted as EXAMPLE.COM. (got %v)", q, got)
		}
	}

	// Reverse: zone inserted lowercase must be matched by uppercase query.
	tree2 := NewRadixTree()
	lower := &Zone{Origin: "example.net."}
	tree2.Insert("example.net.", lower)
	if got := tree2.Find("HOST.EXAMPLE.NET."); got != lower {
		t.Errorf("Find(HOST.EXAMPLE.NET.) did not match zone inserted as example.net. (got %v)", got)
	}
}

func TestRadixTree_Empty(t *testing.T) {
	tree := NewRadixTree()
	if got := tree.Find("anything.com."); got != nil {
		t.Errorf("expected nil for empty tree, got %v", got)
	}
}

func TestRadixTree_BuildEmptyMap(t *testing.T) {
	tree := BuildRadixTree(nil)
	if tree == nil {
		t.Errorf("BuildRadixTree(nil) should return a valid tree")
	}
	if got := tree.Find("anything.com."); got != nil {
		t.Errorf("expected nil for empty tree, got %v", got)
	}
}
