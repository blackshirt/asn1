// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ASN.1 length handling routines.
//
// The standard of X.690 ITU document defines two length types - definite and indefinite.
// In DER encoding only uses the definite length. The length field must be encoded in the minimum number of octets.
// There are two forms of definite length octets: short (for lengths value between 0 and 127),
// and long definite (for lengths value between 0 and 2^1008 -1).
// In short form contains one octet. Bit 8 has value "0" and bits 7-1 give the length (length value from 0 to 127)
// In long form, its required two or more octets, limited to 127 octets. Bit 8 of first octet has value "1" and bits 7-1 gives
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
fn Length.from_i64(v i64) !Length {
	if v < 0 {
		return error('Length: supply with positive i64')
	}
	if v > max_definite_length_value {
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

// to_bytes packs Length v into bytes and apends it into `dst` bytes.
fn (v Length) to_bytes(mut dst []u8) {
	mut n := v.bytes_len()
	for ; n > 0; n-- {
		// pay attention to the brackets
		dst << u8(v >> ((n - 1) * 8))
	}
}

// length_size gets length of length v in .der rule
fn (v Length) length_size() !int {
	ctx := Context{}
	n := v.length_size_with_context(ctx)!
	return n
}

// length_size_with_context calculates the length of bytes needed to store the Length value `v`
// includes one byte marker for long definite form of length value, for value >= 128
fn (v Length) length_size_with_context(ctx Context) !int {
	// we currently only support .der or (stricter) .ber
	if ctx.rule != .der && ctx.rule != .ber {
		return error('Length: unsupported rule')
	}
	n := if v < 128 { 1 } else { v.bytes_len() + 1 }
	return n
}

// encode serializes Length v into bytes in .der rule
fn (v Length) encode(mut dst []u8) ! {
	ctx := Context{}
	v.encode_with_context(mut dst, ctx)!
}

// encode_with_context serializes Length v into bytes and append it into `dst`. if p `Params` is provided,
// it would use ctx.rule of `Encodingrule` to drive how encode operation would be done.
// By default the .der rule is only currently supported.
fn (v Length) encode_with_context(mut dst []u8, ctx Context) ! {
	// we currently only support .der and (stricter) .ber
	if ctx.rule != .der && ctx.rule != .ber {
		return error('Length: unsupported rule')
	}
	// TODO: add supports for undefinite form
	// Long form
	if v >= 128 {
		// First, we count how many bytes occupied by this length value.
		// if the count exceed the limit, we return error.
		count := v.bytes_len()
		if count > max_definite_length_count {
			return error('something bad in your length')
		}
		// In definite long form, msb bit of first byte is set into 1, and the remaining bits
		// of first byte tells exact count how many bytes following representing this length value.
		dst << 0x80 | u8(count)
		v.to_bytes(mut dst)
	} else {
		// short form, already tells the length value.
		dst << u8(v)
	}
}

// decode read length from bytes src with default context or return error on fails.
fn Length.decode(src []u8) !(Length, i64) {
	ret, next := Length.decode_from_offset(src, 0)!
	return ret, next
}

// decode_from_offset read length from src bytes start from offset pos or return error on fails.
fn Length.decode_from_offset(src []u8, pos i64) !(Length, i64) {
	ctx := Context{}
	ret, next := Length.decode_with_context(src, pos, ctx)!
	return ret, next
}

// decode_with_context tries to decode and deserializes buffer in src into Length form, start from offset loc in the buffer.
// Its return Length and next offset in the buffer to process on, or return error on fails.
fn Length.decode_with_context(src []u8, loc i64, ctx Context) !(Length, i64) {
	if src.len < 1 {
		return error('Length: truncated length')
	}
	// preliminary check
	if ctx.rule != .der && ctx.rule != .ber {
		return error('Length: unsupported rule')
	}
	// consider b := src[loc] would lead to panic
	if loc >= src.len {
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
		if pos > src.len {
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
		//		return error('Length: count bytes exceed limit')
		// }
		for i := 0; i < num_bytes; i++ {
			if pos >= src.len {
				return error('Length: truncated length')
			}
			b = src[pos]
			pos += 1

			// currently, we're only support limited length.
			// The length is in i64 range
			if length > max_definite_length_value {
				return error('Length: length exceed limit value')
			}
			length <<= 8
			length |= b
			if length == 0 {
				// TODO: leading zeros is allowed in Long form of BER encoding, but
				// not allowed in DER encoding
				if ctx.rule == .der {
					return error('Length: leading zeros')
				}
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
