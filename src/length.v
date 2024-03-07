// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ASN.1 length handling routines.
//
// The standard of X.690 ITU document defines two length types - definite and indefinite.
// DER encoding only uses the definite length.
// There are two forms of definite length octets: short (for lengths value between 0 and 127),
// and long definite (for lengths value between 0 and 2^1008 -1).
// Short form. One octet. Bit 8 has value "0" and bits 7-1 give the length (length value from 0 to 127)
// Long form. Two to 127 octets. Bit 8 of first octet has value "1" and bits 7-1 give
// the number of additional length octets.
// Second and following octets give the length, base 256, most significant digit first.
//
// This module only support definite length, in short or long form. Its required for DER encoding
// the length octets should in definite length.

const max_definite_length = 4
// Length represent ASN.1 length
type Length = int

fn Length.from_int(v int) Length {
	return Length(v)
}

// bytes_needed tells how many bytes needed to represent this length
fn (v Length) bytes_needed() int {
	mut i := v
	mut num := 1
	for i > 255 {
		num++
		i >>= 8
	}
	return num
}

// pack_and_append packs v to bytes and apends it to `to`
fn (v Length) pack_and_append(mut to []u8) {
	mut n := v.bytes_needed()
	for ; n > 0; n-- {
		// pay attention to the brackets
		to << u8(v >> ((n - 1) * 8))
	}
}

// length calculates the length of bytes length
pub fn (v Length) length() int {
	mut len := 1
	if v >= 128 {
		n := v.bytes_needed()
		len += n
	}
	return len
}

// pack serializes Length v into bytes and append it into `to`
pub fn (v Length) pack_to_asn1(mut to []u8, mode EncodingMode) ! {
	match mode {
		.der {
			// Long form
			if v >= 128 {
				length := v.bytes_needed()

				// if the length overflow the limit, something bad happen
				// return error instead
				if length > asn1.max_definite_length {
					return error('something bad in your length')
				}
				to << 0x80 | u8(length)
				v.pack_and_append(mut to)
			} else {
				// short form
				to << u8(v)
			}
		}
		// Otherwise, its not supported
		else {
			return error('Unsupported')
		}
	}
}

// unpack_from_asn1 deserializes back of buffer into Length form, start from offset loc in the buf.
// Its return Length and next offset in the buffer buf to process on, and return error on fail.
pub fn Length.unpack_from_asn1(buf []u8, loc int, mode EncodingMode) !(Length, int) {
	match mode {
		.der {
			mut pos := loc
			if pos >= buf.len {
				return error('Length: truncated length')
			}
			mut b := buf[pos]
			pos += 1
			mut length := 0
			// check for the most bit is set or not
			if b & 0x80 == 0 {
				// for lengths between 0 and 127, the one-octet short form can be used.
				// The bit 7 of the length octet is set to 0, and the length is encoded
				// as an unsigned binary value in the octet's rightmost seven bits.
				length = int(b & 0x7f)
			} else {
				// Otherwise, its a Long definite form or undefinite form
				num_bytes := b & 0x7f
				if num_bytes == 0 {
					// TODO: add support for undefinite length
					return error('Length: unsupported undefinite length')
				}

				for i := 0; i < num_bytes; i++ {
					if pos >= buf.len {
						return error('Length: truncated length')
					}
					b = buf[pos]
					pos += 1
					// currently, we're only support limited length.
					// The length is in integer range
					if length >= max_int - 1 {
						return error('Length: integer overflow')
					}
					length <<= 8
					length |= int(b)
					if length == 0 {
						// TODO: leading zeros is allowed in Long form of BER encoding, but
						// not allowed in DER encoding
						return error('Length: leading zeros')
					}
				}

				// do not allow values < 0x80 to be encoded in long form
				if length < 0x80 {
					// TODO: allow in BER
					return error('Length: dont needed in long form')
				}
			}
			return Length(length), pos
		}
		// Others encoding mode currently is not yet supported
		else {
			return error('Unsupported encoding mode')
		}
	}
}