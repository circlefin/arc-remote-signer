// Copyright (c) 2026, Circle Internet Group, Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kmsrecipient

import (
	"bytes"
	"errors"
)

// The BER-to-DER conversion is derived from mozilla-services/pkcs7 (MIT).
// This version adds strict bounds, trailing-data, nesting, and size checks.
const (
	maxBERDepth   = 32
	maxBERSize    = 1 << 20
	maxBERTagSize = 9
)

func berToDER(input []byte) ([]byte, error) {
	if len(input) == 0 || len(input) > maxBERSize {
		return nil, errors.New("invalid BER input size")
	}

	encoded, next, eoc, err := readBERObject(input, 0, 0)
	if err != nil {
		return nil, err
	}
	if eoc || next != len(input) {
		return nil, errors.New("invalid BER top-level object")
	}
	return encoded, nil
}

func readBERObject(input []byte, offset, depth int) ([]byte, int, bool, error) {
	if depth > maxBERDepth || offset < 0 || offset >= len(input) {
		return nil, 0, false, errors.New("invalid BER object boundary")
	}
	if len(input)-offset >= 2 && input[offset] == 0 && input[offset+1] == 0 {
		return nil, offset + 2, true, nil
	}

	tag, constructed, offset, err := readBERTag(input, offset)
	if err != nil {
		return nil, 0, false, err
	}

	length, indefinite, offset, err := readBERLength(input, offset)
	if err != nil {
		return nil, 0, false, err
	}
	if indefinite && !constructed {
		return nil, 0, false, errors.New("indefinite primitive BER object")
	}

	if !constructed {
		if length > len(input)-offset {
			return nil, 0, false, errors.New("truncated BER primitive")
		}
		content := input[offset : offset+length]
		return encodeDERObject(tag, content), offset + length, false, nil
	}

	return readBERConstructed(input, tag, offset, depth, length, indefinite)
}

// readBERTag parses a BER identifier, including any high-tag-number
// continuation octets, and reports whether the object is constructed.
func readBERTag(input []byte, offset int) (tag []byte, constructed bool, next int, err error) {
	tagStart := offset
	firstTagByte := input[offset]
	offset++
	if firstTagByte&0x1f == 0x1f {
		var err error
		offset, err = readBERHighTagEnd(input, tagStart, offset)
		if err != nil {
			return nil, false, 0, err
		}
	}
	return input[tagStart:offset], firstTagByte&0x20 != 0, offset, nil
}

func readBERHighTagEnd(input []byte, tagStart, offset int) (int, error) {
	var seen bool
	for {
		if offset >= len(input) {
			return 0, errors.New("truncated BER high tag")
		}
		b := input[offset]
		offset++
		if !seen && b == 0x80 {
			return 0, errors.New("invalid BER high tag")
		}
		seen = true
		if b&0x80 == 0 {
			return offset, nil
		}
		if offset-tagStart >= maxBERTagSize {
			return 0, errors.New("BER tag is too long")
		}
	}
}

// readBERConstructed reassembles the children of a constructed BER object
// into DER, handling both definite- and indefinite-length forms.
func readBERConstructed(input, tag []byte, offset, depth, length int, indefinite bool) ([]byte, int, bool, error) {
	contentEnd := len(input)
	if !indefinite {
		if length > len(input)-offset {
			return nil, 0, false, errors.New("truncated BER constructed object")
		}
		contentEnd = offset + length
	}

	var content bytes.Buffer
	for {
		child, childEnd, done, err := readBERConstructedChild(input, offset, depth, contentEnd, indefinite)
		if err != nil {
			return nil, 0, false, err
		}
		if done {
			offset = childEnd
			break
		}
		if content.Len()+len(child) > maxBERSize {
			return nil, 0, false, errors.New("BER output is too large")
		}
		_, _ = content.Write(child)
		offset = childEnd
	}

	return encodeDERObject(tag, content.Bytes()), offset, false, nil
}

func readBERConstructedChild(
	input []byte,
	offset, depth, contentEnd int,
	indefinite bool,
) (child []byte, next int, done bool, err error) {
	if indefinite {
		if offset >= len(input) {
			return nil, 0, false, errors.New("unterminated BER object")
		}
	} else if offset == contentEnd {
		return nil, offset, true, nil
	} else if offset > contentEnd {
		return nil, 0, false, errors.New("BER child exceeds parent")
	}

	child, next, eoc, err := readBERObject(input, offset, depth+1)
	if err != nil {
		return nil, 0, false, err
	}
	if eoc {
		if !indefinite {
			return nil, 0, false, errors.New("unexpected BER end-of-contents")
		}
		return nil, next, true, nil
	}
	if next <= offset {
		return nil, 0, false, errors.New("BER parser made no progress")
	}
	return child, next, false, nil
}

func readBERLength(input []byte, offset int) (length int, indefinite bool, next int, err error) {
	if offset >= len(input) {
		return 0, false, 0, errors.New("truncated BER length")
	}
	first := input[offset]
	offset++
	if first == 0x80 {
		return 0, true, offset, nil
	}
	if first&0x80 == 0 {
		return int(first), false, offset, nil
	}

	count := int(first & 0x7f)
	if count == 0 || count > 4 || count > len(input)-offset || input[offset] == 0 {
		return 0, false, 0, errors.New("invalid BER long length")
	}
	for i := 0; i < count; i++ {
		length = length<<8 | int(input[offset+i])
	}
	if length < 128 {
		return 0, false, 0, errors.New("non-minimal BER long length")
	}
	return length, false, offset + count, nil
}

func encodeDERObject(tag, content []byte) []byte {
	encoded := make([]byte, 0, len(tag)+5+len(content))
	encoded = append(encoded, tag...)
	encoded = appendDERLength(encoded, len(content))
	encoded = append(encoded, content...)
	return encoded
}

func appendDERLength(dst []byte, length int) []byte {
	if length < 128 {
		return append(dst, byte(length))
	}

	var encoded [8]byte
	i := len(encoded)
	for length > 0 {
		i--
		encoded[i] = byte(length)
		length >>= 8
	}
	dst = append(dst, 0x80|byte(len(encoded)-i))
	return append(dst, encoded[i:]...)
}
