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
// the length octets should be in definite length.

// max_definite_length_count is a limit tells how many bytes to represent this length.
// We're going to limi this to 6 bytes following when the length is in long-definite form.
const max_definite_length_count = 126
const max_definite_length_value = max_i64

// Length represent ASN.1 length value
type Length = i64

// from_i64 creates Length from i64  value. Passing negative value (<0) for length
// is not make a sense, so just return error instead if it happen.
pub fn Length.from_i64(v i64) !Length {
	if v < 0 {
		return error('Length: supply with positive i64')
	}
	if v > asn1.max_definite_length_value {
		return error('Length: value provided exceed limit')
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

// packed_length calculates the length of bytes needed to store the Length value `v`
// includes one byte marker for long definite form of length value, for value >= 128
pub fn (v Length) packed_length(p Params) int {
	n := if v < 128 { 1 } else { v.bytes_len() + 1 }
	return n
}

// pack_to_asn1 serializes Length v into bytes and append it into `dst`. if p `Params` is provided,
// it would use p.mode of `EncodingMode` to drive packing operation operation would be done.
// By default the .der mode is only currently supported.
pub fn (v Length) pack_to_asn1(mut dst []u8, p Params) ! {
	// we currently only support .der and (stricter) .ber
	if p.mode != .der && p.mode != .ber {
		return error('Length: unsupported mode')
	}
	// TODO: add supports for undefinite form
	// Long form
	if v >= 128 {
		// First, we count how many bytes occupied by this length value.
		// if the count exceed the limit, we return error.
		count := v.bytes_len()
		if count > asn1.max_definite_length_count {
			return error('something bad in your length')
		}
		// In definite long form, msb bit of first byte is set into 1, and the remaining bits
		// of first byte tells exact count how many bytes following representing this length value.
		dst << 0x80 | u8(count)
		v.pack_and_append(mut dst)
	} else {
		// short form, already tells the length value.
		dst << u8(v)
	}
}

// unpack_from_asn1 deserializes back of buffer into Length form, start from offset loc in the buffer.
// Its return Length and next offset in the buffer src to process on, and return error on fail.
pub fn Length.unpack_from_asn1(src []u8, loc i64, p Params) !(Length, i64) {
	if src.len < 1 {
		return error('Length: truncated length')
	}
	// preliminary check
	if p.mode != .der && p.mode != .ber {
		return error('Length: unsupported mode')
	}
	if loc > src.len {
		return error('Length: invalid pos')
	}

	mut pos := loc
	mut b := src[pos]
	pos += 1
	mut length := i64(0)
	// check for the most bit is set or not
	if b & 0x80 == 0 {
		// for lengths between 0 and 127, the one-octet short form can be used.
		// The bit 7 of the length octet is set to 0, and the length is encoded
		// as an unsigned binary value in the octet's rightmost seven bits.
		length = b & 0x7f
	} else {
		if pos >= src.len {
			return error('truncated tag or length')
		}
		// Otherwise, its a Long definite form or undefinite form
		num_bytes := b & 0x7f
		if num_bytes == 0 {
			// TODO: add support for undefinite length
			return error('Length: unsupported undefinite length')
		}
		if num_bytes == 0x7f {
			return error('Length: 0x7f is for reserved use')
		}
		// we limit the bytes count for length definite form to `max_definite_length_count`
		// if num_bytes > asn1.max_definite_length_count {
		//	dump(num_bytes)
		//	return error('Length: count bytes exceed limit')
		//}
		for i := 0; i < num_bytes; i++ {
			if pos >= src.len {
				return error('Length: truncated length')
			}
			b = src[pos]
			pos += 1
			// currently, we're only support limited length.
			// The length is in i64 range
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
		if length < i64(0x80) {
			// TODO: allow in BER
			return error('Length: dont needed in long form')
		}
	}
	ret := Length.from_i64(length)!
	return ret, pos
}
