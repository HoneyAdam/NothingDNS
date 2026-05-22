package geodns

// MMDB writer used by unit tests to produce binary fixtures that the
// real parser in mmdb.go can decode end-to-end. Generates IPv4-only
// databases with 24-bit records — the smallest, simplest variant of
// the format — which is sufficient to exercise tree-walk, data-section
// decode, and metadata parsing paths.

import (
	"encoding/binary"
	"fmt"
)

// mmdbRef references either a child node or a data record. The writer
// resolves refs to concrete tree-record values at build time, once the
// final node count is known.
type mmdbRef struct {
	isData bool
	idx    uint32 // node index (if !isData) or data-blob index (if isData)
}

// mmdbBuilder accumulates a tree section and a data section, then
// emits a complete MMDB byte stream including the 16-byte separator,
// metadata marker, and metadata map.
type mmdbBuilder struct {
	// nodes[i] = (left ref, right ref). Resolved at build time.
	nodes [][2]mmdbRef

	// dataBlobs[i] = encoded bytes for data record i.
	dataBlobs [][]byte
}

// addData encodes value into the data section and returns a ref that
// can be passed as a left/right child of a tree node.
func (b *mmdbBuilder) addData(value interface{}) (mmdbRef, error) {
	blob, err := mmdbEncode(value)
	if err != nil {
		return mmdbRef{}, err
	}
	idx := uint32(len(b.dataBlobs))
	b.dataBlobs = append(b.dataBlobs, blob)
	return mmdbRef{isData: true, idx: idx}, nil
}

// addNode appends a tree node with the given left/right children and
// returns a ref to it.
func (b *mmdbBuilder) addNode(left, right mmdbRef) mmdbRef {
	idx := uint32(len(b.nodes))
	b.nodes = append(b.nodes, [2]mmdbRef{left, right})
	return mmdbRef{isData: false, idx: idx}
}

// noData returns a ref that, when stored in a tree node, means "the
// IP has no data in this database" (record value == node_count).
func (b *mmdbBuilder) noData() mmdbRef {
	// Use a sentinel idx; resolved in build() below.
	return mmdbRef{isData: false, idx: 0xffffffff}
}

// build returns the full MMDB file bytes.
func (b *mmdbBuilder) build(ipVersion uint32) ([]byte, error) {
	nodeCount := uint32(len(b.nodes))
	recordSize := uint32(24)
	nodeByteSize := recordSize * 2 / 8 // = 6
	treeBytes := nodeCount * nodeByteSize

	// Compute the data-section offset of each data blob (relative to
	// data-section start).
	dataOffsets := make([]uint32, len(b.dataBlobs))
	off := uint32(0)
	for i, blob := range b.dataBlobs {
		dataOffsets[i] = off
		off += uint32(len(blob))
	}

	resolve := func(r mmdbRef) (uint32, error) {
		if r.idx == 0xffffffff {
			// "No data" sentinel.
			return nodeCount, nil
		}
		if r.isData {
			if r.idx >= uint32(len(dataOffsets)) {
				return 0, fmt.Errorf("mmdbBuilder: data ref %d out of range", r.idx)
			}
			// Tree pointer value = node_count + 16 + data_section_offset.
			return nodeCount + 16 + dataOffsets[r.idx], nil
		}
		if r.idx >= nodeCount {
			return 0, fmt.Errorf("mmdbBuilder: node ref %d out of range (nodeCount=%d)", r.idx, nodeCount)
		}
		return r.idx, nil
	}

	// Encode tree.
	tree := make([]byte, treeBytes)
	for i, n := range b.nodes {
		base := uint32(i) * nodeByteSize
		l, err := resolve(n[0])
		if err != nil {
			return nil, err
		}
		r, err := resolve(n[1])
		if err != nil {
			return nil, err
		}
		tree[base+0] = byte(l >> 16)
		tree[base+1] = byte(l >> 8)
		tree[base+2] = byte(l)
		tree[base+3] = byte(r >> 16)
		tree[base+4] = byte(r >> 8)
		tree[base+5] = byte(r)
	}

	// Concatenate data blobs.
	var data []byte
	for _, blob := range b.dataBlobs {
		data = append(data, blob...)
	}

	// Build metadata map.
	meta := map[string]interface{}{
		"node_count":                  uint64(nodeCount),
		"record_size":                 uint64(recordSize),
		"ip_version":                  uint64(ipVersion),
		"database_type":               "GeoLite2-Country-Test",
		"binary_format_major_version": uint64(2),
		"binary_format_minor_version": uint64(0),
		"build_epoch":                 uint64(1700000000),
		"languages":                   []interface{}{"en"},
		"description": map[string]interface{}{
			"en": "Test fixture built by mmdbBuilder",
		},
	}
	metaBytes, err := mmdbEncode(meta)
	if err != nil {
		return nil, fmt.Errorf("encode metadata: %w", err)
	}

	// Assemble file: tree | 16 zero bytes | data | marker | metadata.
	var out []byte
	out = append(out, tree...)
	out = append(out, make([]byte, 16)...) // separator
	out = append(out, data...)
	out = append(out, []byte(mmdbMetadataMarker)...)
	out = append(out, metaBytes...)
	return out, nil
}

// mmdbEncode produces the MMDB binary representation of value. Supports
// the subset of types the geodns tests need (no pointer compression;
// every value is encoded inline).
func mmdbEncode(v interface{}) ([]byte, error) {
	switch x := v.(type) {
	case string:
		return encodeBytes(mmdbTypeUTF8, []byte(x)), nil
	case []byte:
		return encodeBytes(mmdbTypeBytes, x), nil
	case bool:
		var sz int
		if x {
			sz = 1
		}
		return encodeControl(mmdbTypeBoolean, sz), nil
	case int32:
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, uint32(x))
		ctrl := encodeControl(mmdbTypeInt32, len(payload))
		return append(ctrl, payload...), nil
	case uint64:
		switch {
		case x <= 0xffff:
			return encodeUint(mmdbTypeUint16, x), nil
		case x <= 0xffffffff:
			return encodeUint(mmdbTypeUint32, x), nil
		default:
			return encodeUint(mmdbTypeUint64, x), nil
		}
	case []interface{}:
		ctrl := encodeControl(mmdbTypeArray, len(x))
		out := ctrl
		for _, item := range x {
			enc, err := mmdbEncode(item)
			if err != nil {
				return nil, err
			}
			out = append(out, enc...)
		}
		return out, nil
	case map[string]interface{}:
		ctrl := encodeControl(mmdbTypeMap, len(x))
		out := ctrl
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sortStrings(keys)
		for _, k := range keys {
			ke := encodeBytes(mmdbTypeUTF8, []byte(k))
			out = append(out, ke...)
			ve, err := mmdbEncode(x[k])
			if err != nil {
				return nil, err
			}
			out = append(out, ve...)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("mmdbEncode: unsupported type %T", v)
	}
}

// encodeControl emits the control byte, optional extended-type byte,
// and optional size-extension bytes for a typed value of typeCode and
// payload-length size. The wire order is:
//
//	[ctrl] [extended-type if typeCode>7] [size-ext if size>=29]
//
// matching the decoder's readControlByte parse order.
func encodeControl(typeCode, size int) []byte {
	var ctrl byte
	var extType []byte
	if typeCode <= 7 {
		ctrl = byte(typeCode << 5)
	} else {
		// Extended: top 3 bits = 0 (mmdbTypeExtended); one extra byte
		// holds (typeCode - 7).
		extType = []byte{byte(typeCode - 7)}
	}

	var sizeExt []byte
	switch {
	case size < 29:
		ctrl |= byte(size)
	case size < 285:
		ctrl |= 29
		sizeExt = []byte{byte(size - 29)}
	case size < 65821:
		ctrl |= 30
		s := size - 285
		sizeExt = []byte{byte(s >> 8), byte(s)}
	default:
		ctrl |= 31
		s := size - 65821
		sizeExt = []byte{byte(s >> 16), byte(s >> 8), byte(s)}
	}

	out := []byte{ctrl}
	out = append(out, extType...)
	out = append(out, sizeExt...)
	return out
}

func encodeBytes(typeCode int, payload []byte) []byte {
	ctrl := encodeControl(typeCode, len(payload))
	return append(ctrl, payload...)
}

// encodeUint emits a variable-length unsigned integer in the smallest
// representation. Leading zero bytes are stripped; v=0 becomes size-0.
func encodeUint(typeCode int, v uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	// Strip leading zeros.
	i := 0
	for i < len(buf) && buf[i] == 0 {
		i++
	}
	trimmed := buf[i:]
	ctrl := encodeControl(typeCode, len(trimmed))
	return append(ctrl, trimmed...)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
