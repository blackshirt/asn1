// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ASN.1 length handling routines.
//
// The standard of X.690 ITU dokument defines two length types - definite and indefinite.
// DER only uses the definite method.
// Therre are two forms of length octets: short (for lengths between 0 and 127),
// and long definite (for lengths between 0 and 2^1008 -1).
// Short form. One octet. Bit 8 has value "0" and bits 7-1 give the length.
// Long form. Two to 127 octets. Bit 8 of first octet has value "1" and bits 7-1 give
// the number of additional length octets. Second and following octets give the length, base 256, most significant digit first.
//
// This mpdule only support definite length, in short or long form. Its required for DER encoding
// the length octets should in definite length.

// calculate lenght of bytes needed to store n
fn calc_length(n int) int {
	mut i := n
	mut num := 1
	for i > 255 {
		num++
		i >>= 8
	}
	return num
}

// bytes part of the length
fn append_length(mut dst []u8, i int) []u8 {
	mut n := calc_length(i)

	for ; n > 0; n-- {
		dst << u8(i >> (n - 1) * 8)
	}

	return dst
}

// calculates length of length bytes
pub fn calc_length_of_length(value int) int {
	mut length := 1
	if value >= 128 {
		s := calc_length(value)
		// length += 1
		length += s
	}
	return length
}

// serialize_length encodes value to dst
pub fn serialize_length(mut dst []u8, value int) []u8 {
	// mut dst := []u8{}
	// long form
	if value >= 128 {
		length := calc_length(value)
		dst << 0x80 | u8(length)
		dst = append_length(mut dst, value)
	} else {
		// short form
		dst << u8(value)
	}

	return dst
}

// decode_length decodes bytes from positon `loc` and returns integer length value and
// next offset to read bytes data from.
pub fn decode_length(buf []u8, loc int) !(int, int) {
	mut pos := loc
	if pos >= buf.len {
		return error('truncated tag or length')
	}
	mut b := buf[pos]
	pos += 1
	mut length := 0
	if b & 0x80 == 0 {
		length = int(b & 0x7f)
	} else {
		num_bytes := b & 0x7f
		if num_bytes == 0 {
			return error('unsupported undefinite length')
		}

		for i := 0; i < num_bytes; i++ {
			if pos >= buf.len {
				return error('truncated tag or length')
			}
			b = buf[pos]
			pos += 1
			if length > (max_i32 >> 8) {
				return error('integer overflow')
			}
			length <<= 8
			length |= int(b)
			if length == 0 {
				return error('leading zeros')
			}
		}

		// do not allow values <0x80 to be encoded in long form
		if length < 0x80 {
			// dump(length)
			return error('dont needed in long form')
		}
	}
	return length, pos
}
