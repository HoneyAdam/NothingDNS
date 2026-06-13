// Package idna implements Punycode encoding/decoding per RFC 3492.
package idna

import "strings"

// Punycode base and delimiter constants
const (
	base      = 36
	delimiter = '-'
	tmin      = 1
	tmax      = 26
	skew      = 38
	damp      = 700
	// initialBias is the starting bias for the first delta.
	initialBias = 72
	// initialN is the first code point for the encoded suffix.
	initialN = 128 // 0x80
)

// digitToChar converts a digit value to its character representation.
func digitToChar(digit int) rune {
	switch {
	case digit >= 0 && digit <= 25:
		return rune('a' + digit)
	case digit >= 26 && digit <= 35:
		return rune('0' + digit - 26)
	default:
		return rune('a') // Should not happen
	}
}

// charToDigit converts a character to its digit value.
func charToDigit(char rune) int {
	switch {
	case char >= 'a' && char <= 'z':
		return int(char - 'a')
	case char >= 'A' && char <= 'Z':
		return int(char - 'A')
	case char >= '0' && char <= '9':
		return int(char - '0' + 26)
	default:
		return -1
	}
}

// encodePunycode encodes a Unicode string to punycode.
func encodePunycode(src string) string {
	runes := []rune(src)

	var encoded strings.Builder
	basicCount := 0
	for _, r := range runes {
		if r < 0x80 {
			encoded.WriteRune(r)
			basicCount++
		}
	}

	if basicCount > 0 && basicCount < len(runes) {
		encoded.WriteRune(delimiter)
	}
	if basicCount < len(runes) {
		encoded.WriteString(encodeSuffix(runes, basicCount))
	}

	return encoded.String()
}

// encodeSuffix encodes non-basic code points using RFC 3492 Bootstring.
func encodeSuffix(src []rune, basicCount int) string {
	if len(src) == 0 {
		return ""
	}

	var out strings.Builder

	n := initialN
	delta := 0
	bias := initialBias
	h := basicCount
	b := basicCount

	if h == len(src) {
		return ""
	}

	for h < len(src) {
		m := int(^uint(0) >> 1)
		for _, r := range src {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}

		delta += (m - n) * (h + 1)
		n = m

		for _, r := range src {
			c := int(r)
			if c < n {
				delta++
			}
			if c == n {
				q := delta
				for k := base; ; k += base {
					t := k - bias
					if t < tmin {
						t = tmin
					}
					if t > tmax {
						t = tmax
					}

					if q < t {
						break
					}

					out.WriteRune(digitToChar(t + (q-t)%(base-t)))
					q = (q - t) / (base - t)
				}

				out.WriteRune(digitToChar(q))
				bias = adapt(delta, h+1, h == b)
				delta = 0
				h++
			}
		}

		delta++
		n++
	}

	return out.String()
}

// decodePunycode decodes a punycode string to Unicode per RFC 3492 §6.2.
//
// Format: an optional ASCII basic-code-point prefix, a single '-' delimiter,
// then the variable-part digits. If the input contains no '-', the entire
// string is the variable part (basic prefix is empty). The previous
// implementation short-circuited "no hyphen" → return as-is, which produced
// the original ASCII for every real-world punycode (e.g. "nxasmq6b" should
// decode to "Ü" / "ä"-bearing strings, not stay literal).
func decodePunycode(src string) string {
	if src == "" {
		return ""
	}

	// Locate the last delimiter (RFC 3492 §6.2 step "find last '-'"). If
	// there is none, the basic prefix is empty and the whole string is the
	// encoded suffix.
	prefix := ""
	encoded := src
	if lastHyphen := strings.LastIndex(src, string(delimiter)); lastHyphen >= 0 {
		prefix = src[:lastHyphen]
		encoded = src[lastHyphen+1:]
	}

	if encoded == "" {
		return prefix
	}

	// Decode the suffix
	var (
		n    int = initialN
		bias     = initialBias
		i        = 0
		out  []rune
	)

	// Initialize output with the prefix
	for _, r := range prefix {
		out = append(out, r)
	}

	for pos := 0; pos < len(encoded); pos++ {
		char := rune(encoded[pos])
		if char == delimiter {
			// End of encoded part
			break
		}

		oldI := i
		weight := 1

		for k := base; ; k += base {
			if pos >= len(encoded) {
				return string(out)
			}

			digit := charToDigit(char)
			if digit < 0 {
				return string(out)
			}

			i += digit * weight

			t := k - bias
			if t < tmin {
				t = tmin
			}
			if t > tmax {
				t = tmax
			}

			if digit < t {
				break
			}

			weight *= (base - t)
			pos++
			if pos < len(encoded) {
				char = rune(encoded[pos])
			}
		}

		bias = adapt(i-oldI, len(out)+1, oldI == 0)

		n += i / (len(out) + 1)
		i = i % (len(out) + 1)

		// Insert n at position i
		if i == 0 {
			out = append([]rune{rune(n)}, out...)
		} else if i >= len(out) {
			out = append(out, rune(n))
		} else {
			// Insert in the middle
			out = append(out[:i], append([]rune{rune(n)}, out[i:]...)...)
		}

		i++
	}

	return string(out)
}

// adapt adjusts the bias for delta arithmetic.
func adapt(delta, numPoints int, first bool) int {
	if first {
		delta = delta / damp
	} else {
		delta = delta / 2
	}

	if numPoints > 0 {
		delta += delta / numPoints
	}

	k := 0
	for delta > ((base-tmin)*tmax)/2 {
		delta = delta / (base - tmin)
		k += base
	}

	return k + ((base-tmin+1)*delta)/(delta+skew)
}
