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

// max_definite_length_count is a limit tells how many bytes to represent this length.
// We're going to limi this to 6 bytes following when the length is in long-definite form.
const max_definite_length_count = 6
const max_definite_length_value = u64(0x0000_ffff_ffff_ffff)

// Length represent ASN.1 length value
type Length = u64

fn Length.from_i64(v i64) !Length {
	if v < 0 {
		return error('Length: supply with positive i64')
	}
	return Length(u64(v))
}

fn Length.from_u64(v u64) !Length {
	if v > asn1.max_definite_length_value {
		return error('Length: ${v} is bigger than allowed value')
	}
	return Length(v)
}

// bytes_len tells how many bytes needed to represent this length
fn (v Length) bytes_len() int {
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
	mut n := v.bytes_len()
	for ; n > 0; n-- {
		// pay attention to the brackets
		to << u8(v >> ((n - 1) * 8))
	}
}

// length calculates the length of bytes needed to store Length
// value in v includes one byte marker for definite length value >= 128
pub fn (v Length) length() int {
	n := if v < 128 { 1 } else { v.bytes_len() + 1 }
	return n
}

// pack_to_asn1 serializes Length v into bytes and append it into `to`
pub fn (v Length) pack_to_asn1(mut to []u8, mode EncodingMode) ! {
	match mode {
		.der {
			// Long form
			if v >= 128 {
				length := v.bytes_len()

				// if the length exceed the limit, something bad happen
				// return error instead
				if length > asn1.max_definite_length_count {
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
			return error('Unsupported mode')
		}
	}
}

// unpack_from_asn1 deserializes back of buffer into Length form, start from offset loc in the buf.
// Its return Length and next offset in the buffer buf to process on, and return error on fail.
pub fn Length.unpack_from_asn1(buf []u8, loc i64, mode EncodingMode) !(Length, i64) {
	match mode {
		.der {
			mut pos := loc
			if pos >= buf.len {
				return error('Length: truncated length')
			}
			mut b := buf[pos]
			pos += 1
			mut length := i64(0)
			// check for the most bit is set or not
			if b & 0x80 == 0 {
				// for lengths between 0 and 127, the one-octet short form can be used.
				// The bit 7 of the length octet is set to 0, and the length is encoded
				// as an unsigned binary value in the octet's rightmost seven bits.
				length = b & 0x7f
			} else {
				// Otherwise, its a Long definite form or undefinite form
				num_bytes := b & 0x7f
				if num_bytes == 0 {
					// TODO: add support for undefinite length
					return error('Length: unsupported undefinite length')
				}
				// we limit the bytes count for length definite form to `max_definite_length_count`
				if num_bytes > asn1.max_definite_length_count {
					return error('Length: count bytes exceed limit')
				}
				for i := 0; i < num_bytes; i++ {
					if pos >= buf.len {
						return error('Length: truncated length')
					}
					b = buf[pos]
					pos += 1
					// currently, we're only support limited length.
					// The length is in integer range
					if length > asn1.max_definite_length_value {
						return error('Length: length exceed limit value')
					}
					length <<= 8
					length |= b
					if length == 0 {
						// TODO: leading zeros is allowed in Long form of BER encoding, but
						// not allowed in DER encoding
						return error('Length: leading zeros')
					}
				}

				// do not allow values < 0x80 to be encoded in long form
				if length < u64(0x80) {
					// TODO: allow in BER
					return error('Length: dont needed in long form')
				}
			}
			ret := Length.from_i64(length)!
			return ret, pos
		}
		// Others encoding mode currently is not yet supported
		else {
			return error('Unsupported encoding mode')
		}
	}
}
