package protocol

import (
	"errors"
	"fmt"
	"strings"
)

// Label compression constants.
const (
	// PointerMask is the mask to identify a compression pointer (0xC0 = 1100 0000).
	PointerMask = 0xC0
	// PointerOffsetMask is the mask to extract the offset from a pointer (0x3FFF).
	PointerOffsetMask = 0x3FFF
	// MaxLabelLength is the maximum length of a single label (63 bytes).
	MaxLabelLength = 63
	// MaxNameLength is the maximum length of a domain name (255 bytes).
	MaxNameLength = 255
	// MaxPointerDepth is the maximum number of pointer indirections to follow.
	// RFC 1035 allows 2-byte pointers, depth limit prevents compression attacks.
	MaxPointerDepth = 5
	// maxLabels is the maximum number of labels a name can contain.
	// With MaxNameLength=255 and min label=1 byte (1 len + 1 data), max ≈ 127.
	maxLabels = 127
)

// Common label errors.
var (
	ErrLabelTooLong    = errors.New("label too long")
	ErrNameTooLong     = errors.New("domain name too long")
	ErrInvalidLabel    = errors.New("invalid label")
	ErrInvalidPointer  = errors.New("invalid compression pointer")
	ErrPointerLoop     = errors.New("compression pointer loop detected")
	ErrPointerTooDeep  = errors.New("compression pointer depth exceeded")
	ErrInvalidWireData = errors.New("invalid wire format data")
)

// Name represents a DNS domain name as a sequence of labels.
type Name struct {
	// Labels contains the labels in normal order (e.g., ["www", "example", "com"]).
	// The root label (empty string) is implicit and not stored.
	Labels []string
	// FQDN indicates if the name is fully qualified (ends with root).
	FQDN bool
	// stringCache memoizes String() for request-path callers that repeatedly
	// stringify the same unpacked name. It must be cleared on every mutation or
	// pool reuse.
	stringCache string
}

// NewName creates a Name from a slice of labels.
func NewName(labels []string, fqdn bool) *Name {
	pooledLabels := acquireLabelSlice()
	pooledLabels = append(pooledLabels, labels...)
	name := acquireName()
	name.Labels = pooledLabels
	name.FQDN = fqdn
	return name
}

// Copy creates a deep copy of the Name.
func (n *Name) Copy() *Name {
	if n == nil {
		return nil
	}
	return NewName(n.LabelsSlice(), n.FQDN)
}

// CanonicalWire returns the canonical lowercase wire-format name.
func (n *Name) CanonicalWire() []byte {
	if n == nil {
		return []byte{0}
	}
	return CanonicalWireName(n.String())
}

// LabelsSlice returns a copy-compatible view of the labels.
// Compatibility helper during migration away from direct field-based cloning.
func (n *Name) LabelsSlice() []string {
	if n == nil {
		return nil
	}
	return n.Labels
}

// ForEachLabel iterates labels in left-to-right order.
func (n *Name) ForEachLabel(fn func(label string) bool) {
	if n == nil || fn == nil {
		return
	}
	for _, label := range n.Labels {
		if !fn(label) {
			return
		}
	}
}

// Release returns the Name and its label-slice backing storage to internal pools.
// After Release the Name must not be used again.
func (n *Name) Release() {
	if n == nil {
		return
	}
	if n.Labels != nil {
		releaseLabelSlice(n.Labels)
		n.Labels = nil
	}
	n.FQDN = false
	n.stringCache = ""
	namePool.Put(n)
}

// ParseName parses a domain name string into a Name struct.
func ParseName(s string) (*Name, error) {
	// Remove trailing dot if present
	fqdn := strings.HasSuffix(s, ".")
	if fqdn {
		s = s[:len(s)-1]
	}

	// Root domain
	if s == "" {
		name := acquireName()
		name.Labels = acquireLabelSlice()
		name.FQDN = fqdn
		return name, nil
	}

	// Split into labels
	labels := strings.Split(s, ".")

	if err := validateNameLabels(labels); err != nil {
		return nil, err
	}

	// Validate each label
	for i, label := range labels {
		if err := ValidateLabel(label); err != nil {
			return nil, fmt.Errorf("invalid label %d: %w", i, err)
		}
	}

	name := acquireName()
	name.Labels = labels
	name.FQDN = fqdn
	return name, nil
}

// String returns the domain name as a string.
func (n *Name) String() string {
	if n == nil {
		return "."
	}
	if n.stringCache != "" {
		return n.stringCache
	}
	if len(n.Labels) == 0 {
		if n.FQDN {
			n.stringCache = "."
			return n.stringCache
		}
		return ""
	}
	result := strings.Join(n.Labels, ".")
	if n.FQDN {
		result += "."
	}
	n.stringCache = result
	return result
}

// IsRoot returns true if this is the root domain.
func (n *Name) IsRoot() bool {
	if n == nil {
		return true
	}
	return len(n.Labels) == 0
}

// IsWildcard returns true if this is a wildcard name (starts with *).
func (n *Name) IsWildcard() bool {
	if n == nil {
		return false
	}
	return len(n.Labels) > 0 && n.Labels[0] == "*"
}

// HasPrefix returns true if the name has the given prefix labels.
func (n *Name) HasPrefix(prefix []string) bool {
	if n == nil {
		return len(prefix) == 0
	}
	if len(prefix) > len(n.Labels) {
		return false
	}
	for i, label := range prefix {
		if !strings.EqualFold(label, n.Labels[i]) {
			return false
		}
	}
	return true
}

// HasPrefixName returns true if the name has the given prefix name.
func (n *Name) HasPrefixName(prefix *Name) bool {
	if prefix == nil {
		return true
	}
	return n.HasPrefix(prefix.Labels)
}

// HasSuffix returns true if the name has the given suffix labels.
func (n *Name) HasSuffix(suffix []string) bool {
	if n == nil {
		return len(suffix) == 0
	}
	if len(suffix) > len(n.Labels) {
		return false
	}
	offset := len(n.Labels) - len(suffix)
	for i, label := range suffix {
		if !strings.EqualFold(label, n.Labels[offset+i]) {
			return false
		}
	}
	return true
}

// HasSuffixName returns true if the name has the given suffix name.
func (n *Name) HasSuffixName(suffix *Name) bool {
	if suffix == nil {
		return true
	}
	return n.HasSuffix(suffix.Labels)
}

// Equal returns true if the names are equal (case-insensitive).
func (n *Name) Equal(other *Name) bool {
	if n == nil || other == nil {
		return false
	}
	if len(n.Labels) != len(other.Labels) {
		return false
	}
	for i, label := range n.Labels {
		if !strings.EqualFold(label, other.Labels[i]) {
			return false
		}
	}
	return n.FQDN == other.FQDN
}

// WireLength returns the length of the name in wire format.
func (n *Name) WireLength() int {
	if n == nil {
		return 1
	}
	length := 0
	for _, label := range n.Labels {
		length += 1 + len(label) // length byte + label data
	}
	length++ // terminating zero
	return length
}

func validateNameLabels(labels []string) error {
	if len(labels) > maxLabels {
		return ErrNameTooLong
	}
	length := 1 // terminating root label
	for _, label := range labels {
		length += 1 + len(label)
		if length > MaxNameLength {
			return ErrNameTooLong
		}
	}
	return nil
}

// ValidateLabel validates a single label.
func ValidateLabel(label string) error {
	// Empty label (root) is valid
	if label == "" {
		return nil
	}

	// Check length
	if len(label) > MaxLabelLength {
		return ErrLabelTooLong
	}

	// Check characters
	for i, c := range label {
		if i == 0 || i == len(label)-1 {
			// First and last character cannot be hyphen
			if c == '-' {
				return ErrInvalidLabel
			}
		}
		// Allow letters, digits, hyphens, and underscores
		if !isValidLabelChar(c) {
			return ErrInvalidLabel
		}
	}

	return nil
}

// isValidLabelChar returns true if the character is valid in a DNS label.
func isValidLabelChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '*'
}

// PackName packs a domain name into wire format with optional compression.
// Returns the number of bytes written and any compression pointer offset.
func PackName(name *Name, buf []byte, offset int, compression map[string]int) (int, error) {
	if offset < 0 || offset >= len(buf) {
		return 0, ErrInvalidOffset
	}
	if name == nil {
		buf[offset] = 0
		return 1, nil
	}
	if err := validateNameLabels(name.Labels); err != nil {
		return 0, err
	}

	startOffset := offset
	originalOffset := offset

	if compression != nil && len(name.Labels) > 0 {
		// Build the full lowercase name once. Sub-suffixes are derived by
		// slicing this single string, avoiding repeated strings.Join calls.
		fullName := strings.ToLower(strings.Join(name.Labels, "."))

		// Pre-compute cumulative byte offsets for each suffix start position.
		// suffixStarts[i] is the byte index in fullName where label[i] begins.
		// For labels ["www","example","com"] → offsets [0, 4, 12].
		var suffixStarts [maxLabels]byte // stack-allocated; max 127 labels
		pos := 0
		for i, label := range name.Labels {
			suffixStarts[i] = byte(pos)
			pos += len(label) + 1 // +1 for dot separator
		}

		// Lookup phase: check all suffixes for an existing compression pointer.
		for i := 0; i < len(name.Labels); i++ {
			suffix := fullName[suffixStarts[i]:]
			if ptrOffset, ok := compression[suffix]; ok && ptrOffset < PointerOffsetMask {
				if offset+2 > len(buf) {
					return 0, ErrBufferTooSmall
				}
				pointer := uint16(PointerMask<<8) | uint16(ptrOffset)
				PutUint16(buf[offset:], pointer)
				return offset + 2 - originalOffset, nil
			}
		}

		// No match: write labels and store compression entries.
		for i, label := range name.Labels {
			compression[fullName[suffixStarts[i]:]] = offset

			labelLen := len(label)
			if labelLen > MaxLabelLength {
				return 0, ErrLabelTooLong
			}
			if offset+1+labelLen > len(buf) {
				return 0, ErrBufferTooSmall
			}

			buf[offset] = byte(labelLen)
			offset++
			for j := 0; j < labelLen; j++ {
				buf[offset] = toLower(label[j])
				offset++
			}
		}
	} else {
		// No compression — write labels directly.
		for _, label := range name.Labels {
			labelLen := len(label)
			if labelLen > MaxLabelLength {
				return 0, ErrLabelTooLong
			}
			if offset+1+labelLen > len(buf) {
				return 0, ErrBufferTooSmall
			}

			buf[offset] = byte(labelLen)
			offset++
			for j := 0; j < labelLen; j++ {
				buf[offset] = toLower(label[j])
				offset++
			}
		}
	}

	// Write terminating zero
	if offset >= len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = 0
	offset++

	// Check total name length
	if offset-startOffset > MaxNameLength {
		return 0, ErrNameTooLong
	}

	return offset - originalOffset, nil
}

// UnpackName unpacks a domain name from wire format.
// Returns the name and the number of bytes consumed from the current offset.
func UnpackName(buf []byte, offset int) (*Name, int, error) {
	if offset < 0 || offset >= len(buf) {
		return nil, 0, ErrInvalidOffset
	}

	var nameLen int
	startOffset := offset
	ptrDepth := 0
	ptrOffset := -1

	// Build one contiguous dotted-name byte slice and slice substrings out of the
	// final string, instead of allocating one string per label.
	var nameBuf [MaxNameLength]byte
	namePos := 0
	var labelStarts [maxLabels]int
	var labelEnds [maxLabels]int
	labelCount := 0

	for {
		// Check bounds
		if offset >= len(buf) {
			return nil, 0, ErrBufferTooSmall
		}

		// Check for compression pointer
		if buf[offset]&PointerMask == PointerMask {
			// Compression pointer
			if offset+2 > len(buf) {
				return nil, 0, ErrBufferTooSmall
			}

			pointer := int(Uint16(buf[offset:]) & PointerOffsetMask)

			// Validate pointer is within buffer bounds and points backward (RFC 1035)
			if pointer >= len(buf) {
				return nil, 0, ErrInvalidPointer
			}
			if pointer >= offset {
				return nil, 0, ErrInvalidPointer
			}

			// Check pointer chain depth to prevent infinite loops
			if ptrDepth >= MaxPointerDepth {
				return nil, 0, ErrPointerTooDeep
			}

			// Record the pointer offset for byte counting
			if ptrOffset == -1 {
				ptrOffset = offset + 2
			}

			// Follow the pointer
			offset = pointer
			ptrDepth++
			continue
		}

		// Regular label
		labelLen := int(buf[offset])

		// Check for root (empty label)
		if labelLen == 0 {
			offset++
			fullName := string(nameBuf[:namePos])
			labels := acquireLabelSlice()
			for i := 0; i < labelCount; i++ {
				labels = append(labels, fullName[labelStarts[i]:labelEnds[i]])
			}
			name := acquireName()
			name.Labels = labels
			name.FQDN = true
			name.stringCache = ""
			if ptrOffset > 0 {
				return name, ptrOffset - startOffset, nil
			}
			return name, offset - startOffset, nil
		}

		// Validate label length
		if labelLen > MaxLabelLength {
			return nil, 0, ErrLabelTooLong
		}

		// Check for buffer overflow
		if offset+1+labelLen > len(buf) {
			return nil, 0, ErrBufferTooSmall
		}

		// Check total name length
		nameLen += 1 + labelLen
		if nameLen > MaxNameLength {
			return nil, 0, ErrNameTooLong
		}
		if labelCount >= maxLabels {
			return nil, 0, ErrNameTooLong
		}

		if labelCount > 0 {
			nameBuf[namePos] = '.'
			namePos++
		}
		labelStarts[labelCount] = namePos
		copy(nameBuf[namePos:], buf[offset+1:offset+1+labelLen])
		namePos += labelLen
		labelEnds[labelCount] = namePos
		labelCount++

		offset += 1 + labelLen
	}
}

// toLower converts a byte to lowercase if it's an uppercase letter.
func toLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// CanonicalWireName converts a DNS name string to canonical lowercase wire
// format (RFC 4034 Section 6.2). Each label is prefixed with its length byte,
// and the name is terminated with a zero-length root label. The name is
// lowercased using ASCII-only rules (DNS names are ASCII).
func CanonicalWireName(name string) []byte {
	// Trim whitespace and trailing dot
	start := 0
	end := len(name)
	for start < end && (name[start] == ' ' || name[start] == '\t') {
		start++
	}
	for end > start && (name[end-1] == ' ' || name[end-1] == '\t') {
		end--
	}
	name = name[start:end]
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	if name == "" {
		return []byte{0}
	}

	// Count dots to estimate wire size
	dots := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			dots++
		}
	}

	// Pre-allocate: labels + length bytes + root zero
	wire := make([]byte, 0, len(name)+2-dots)
	labelStart := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			labelLen := i - labelStart
			if labelLen == 0 {
				labelStart = i + 1
				continue
			}
			wire = append(wire, byte(labelLen))
			for j := 0; j < labelLen; j++ {
				wire = append(wire, toLower(name[labelStart+j]))
			}
			labelStart = i + 1
		}
	}
	wire = append(wire, 0)
	return wire
}

// WireNameLength returns the length of a domain name at the given offset.
// This is useful for skipping over names without fully parsing them.
func WireNameLength(buf []byte, offset int) (int, error) {
	if offset < 0 || offset >= len(buf) {
		return 0, ErrInvalidOffset
	}

	startOffset := offset
	labelCount := 0
	nameLen := 1

	for {
		if offset >= len(buf) {
			return 0, ErrBufferTooSmall
		}

		// Check for compression pointer
		if buf[offset]&PointerMask == PointerMask {
			if offset+2 > len(buf) {
				return 0, ErrBufferTooSmall
			}
			// Pointer is always 2 bytes and terminates the name
			return offset + 2 - startOffset, nil
		}

		labelLen := int(buf[offset])
		if labelLen == 0 {
			// Root label
			return offset + 1 - startOffset, nil
		}

		if labelLen > MaxLabelLength {
			return 0, ErrLabelTooLong
		}
		if offset+1+labelLen > len(buf) {
			return 0, ErrBufferTooSmall
		}

		labelCount++
		if labelCount > maxLabels {
			return 0, ErrNameTooLong
		}
		nameLen += 1 + labelLen
		if nameLen > MaxNameLength {
			return 0, ErrNameTooLong
		}

		offset += 1 + labelLen
	}
}

// CompareNames compares two domain names for ordering.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
// Comparison is done label by label from the TLD (right to left).
func CompareNames(a, b *Name) int {
	var aLabels, bLabels []string
	if a != nil {
		aLabels = a.LabelsSlice()
	}
	if b != nil {
		bLabels = b.LabelsSlice()
	}

	// Compare from the rightmost label (TLD) to the leftmost
	i, j := len(aLabels)-1, len(bLabels)-1

	for i >= 0 && j >= 0 {
		cmp := strings.Compare(
			strings.ToLower(aLabels[i]),
			strings.ToLower(bLabels[j]),
		)
		if cmp != 0 {
			return cmp
		}
		i--
		j--
	}

	// One name is a subdomain of the other
	if i < 0 && j < 0 {
		return 0 // Equal
	}
	if i < 0 {
		return -1 // a is shorter
	}
	return 1 // b is shorter
}

// IsSubdomain returns true if child is a subdomain of parent.
func IsSubdomain(child, parent *Name) bool {
	if parent == nil {
		return true
	}
	return child.HasSuffixName(parent)
}
