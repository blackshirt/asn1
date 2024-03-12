// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module primitive

import math.big
import asn1

// INTEGER.
//
// ASN.1 INTEGER type represented by `big.Integer`.
// The INTEGER type value can be a positive or negative number.
// There are no limits imposed on the magnitude of INTEGER values in the ASN.1 standard.
// Its handles number arbitrary length of number with support of `math.big` module.
// But, for sake of safety, we limit the INTEGER limit to follow allowed length in
// definite form of Length part, ie, 1008 bit, or 126 bytes
// The encoding of an integer number shall be primitive.

// Limit of length of INTEGER type, in bytes
// Known big RSA keys is 4096 bits, ie, 512 bytes
const max_integer_length = 2048

// This is hackish way to achieve the desired specific issues on 'big.Integer' null or zero handling.
// `big.Integer.zero_int` or `big.integer_from_int(0)` has set a empty bytes with signum = 0
// Its make an issue where der encoding treated '0' as single byte `0x00`
const zero_integer = big.Integer{
	digits: [u32(0)]
	signum: 1
}

// Universal class of arbitrary length type of ASN.1 INTEGER
struct Integer {
mut:
	tag   asn1.Tag = asn1.new_tag(.universal, false, 2)!
	value big.Integer
}

// equal do checking if n equal to m.
// ISSUE?: There are some issues when compared n == m directly,
// its fails even internally its a same, so we provide and use equality check
fn (n Integer) equal(m Integer) bool {
	nbytes, nsignum := n.value.bytes()
	mbytes, msignum := m.value.bytes()

	return n.tag == m.tag && nbytes == mbytes && nsignum == msignum
}

// from_string creates a new ASN.1 Integer from decimal string s.
fn Integer.from_string(s string) Integer {
	v := big.integer_from_string(s) or { panic(err) }
	if v == big.zero_int {
		return Integer{
			value: primitive.zero_integer
		}
	}

	return Integer{
		value: v
	}
}

// from_hex creates a new ASN.1 Integer from hex string in x
// where x is a valid hex string without `0x` prefix.
fn Integer.from_hex(x string) !Integer {
	s := big.integer_from_radix(x, 16)!
	if s == big.zero_int {
		return Integer{
			value: primitive.zero_integer
		}
	}
	return Integer{
		value: s
	}
}

// from_i64 creates new a ASN.1 Integer from i64 v
fn Integer.from_i64(v i64) Integer {
	// same issue as above
	if v == 0 {
		return Integer{
			value: primitive.zero_integer
		}
	}
	return Integer{
		value: big.integer_from_i64(v)
	}
}

// from_u64 creates new Integer from u64 v
fn Integer.from_u64(v u64) Integer {
	if v == 0 {
		return Integer{
			value: primitive.zero_integer
		}
	}
	return Integer{
		value: big.integer_from_u64(v)
	}
}

fn (v Integer) bytes() []u8 {
	if v.value == primitive.zero_integer {
		return [u8(0x00)]
	}
	bytes, _ := v.value.bytes()
	return bytes
}

// tag returns the tag of Universal class of this Integer type.
fn (v Integer) tag() asn1.Tag {
	return v.tag
}

fn (v Integer) bytes_len() int {
	if v.value == primitive.zero_integer {
		return 1
	}
	nbits := v.value.bit_len()
	if nbits % 8 == 0 {
		return nbits / 8
	}
	return nbits / 8 + 1
}

// pack_into_twoscomplement_form serialize Integer in two's-complement rules. The integer value contains
// the encoded integer if it is positive, or its two's complement if it is negative.
// If the integer is positive but the high order bit is set to 1, a leading 0x00 is added to the content
// to indicate that the number is not negative.
// If the number is negative after applying two's-complement rules, and the the most-significant-bit of the
// the high order bit of the bytes results isn't set, pad it with 0xff in order to keep the number negative.
fn (v Integer) pack_into_twoscomplement_form() !([]u8, int) {
	match v.value.signum {
		0 {
			return [u8(0x00)], 1
		}
		1 {
			mut b := v.bytes()
			// If the integer is positive but the high order bit is set to 1, a leading 0x00 is added
			// to the content to indicate that the number is not negative
			if b[0] & 0x80 > 0 {
				b.prepend(u8(0x00))
			}
			return b, b.len
		}
		-1 {
			// A negative number has to be converted to two's-complement form.
			// by invert the number and and then subtract it with big(1), or with other mean
			// Flip all of the bits in the value and then add one to the resulting value.
			// If the most-significant-bit isn't set then we'll need to pad the
			// beginning with 0xff in order to keep the number negative.
			negv := v.value.neg()
			negvminus1 := negv - big.one_int
			mut bytes, _ := negvminus1.bytes()
			for i, _ in bytes {
				bytes[i] ^= 0xff
			}
			if bytes.len == 0 || bytes[0] & 0x80 == 0 {
				bytes.prepend(u8(0xff))
			}
			return bytes, bytes.len
		}
		else {
			return error('should unreachable')
		}
	}
}

// unpack_from_twoscomplement_bytes parses the bytes in b into the Integer
// value in the big-endian two's complement way. If b[0]&80 != 0, the number
// is negative. If b is empty, the result will be zero_integer.
fn Integer.unpack_from_twoscomplement_bytes(b []u8) !Integer {
	// FIXME: should we return error instead ?
	if b.len == 0 {
		return error('Integer: null bytes')
	}
	mut num := big.integer_from_bytes(b)
	// negative number
	if b.len > 0 && b[0] & 0x80 > 0 {
		sub := big.one_int.left_shift(u32(b.len) * 8)
		num -= sub
	}

	return Integer{
		value: num
	}

	/*
	if b.len > 0 && b[0] & 0x80 == 0x80 {
		// This is a negative number.
		mut notbytes := []u8{len: b.len}
		for i, _ in notbytes {
			notbytes[i] = ~b[i]
		}
		mut ret := big.integer_from_bytes(notbytes)
		ret += big.one_int
		ret = ret.neg()
		return Integer{
			value: ret
		}
	}
	*/
}

// Integer.unpack_and_validate deserializes bytes in b into Integer
// in two's complement way and perform validation on this bytes to
// meet der requirement.
fn Integer.unpack_and_validate(b []u8) !Integer {
	if !valid_bytes(b, true) {
		return error('Integer: check return false')
	}
	ret := Integer.unpack_from_twoscomplement_bytes(b)!
	return ret
}

fn (v Integer) packed_length() !int {
	mut n := 0
	n += v.tag().tag_length()

	x := asn1.Length.from_i64(v.bytes_len())!
	n += x.length()
	n += v.bytes_len()

	return n
}

// pack_to_asn1 packs and serializes Integer v into ASN 1 serialized bytes into `to`.
// Its accepts encoding mode params, where its currently only suppport `.der` DER mode.
// If `to.len != 0`, it act as append semantic, otherwise the `to` bytes stores the result.
fn (v Integer) pack_to_asn1(mut to []u8, mode asn1.EncodingMode, p asn1.Params) ! {
	match mode {
		.der {
			v.tag().pack_to_asn1(mut to, .der, p)!
			bytes, n := v.pack_into_twoscomplement_form()!
			length := asn1.Length.from_i64(n)!
			length.pack_to_asn1(mut to, .der, p)!
			to << bytes
		}
		else {
			return error('unsupported mode')
		}
	}
}

// unpack_from_asn1 deserializes bytes b into ASN.1 Integer.
// Its accepts two params:
// `loc` params, the location (offset) sithin bytes b where the unpack
// process start form, if not sure set to 0.
// `mode` params, the encoding mode to drive unpack operation.
// see `EncodingMode` for availables values. Currently only support`.der`.
fn Integer.unpack_from_asn1(b []u8, loc i64, mode asn1.EncodingMode, p asn1.Params) !(Integer, i64) {
	match mode {
		.der {
			tag, pos := asn1.Tag.unpack_from_asn1(b, loc, .der, p)!
			if tag.class() != .universal || tag.is_compound() || tag.tag_number() != 2 {
				return error('Integer: bad tag of universal class type')
			}
			// read the length part from current position pos
			len, idx := asn1.Length.unpack_from_asn1(b, pos, .der, p)!
			if len == 0 {
				return error("Integer: len==0")
			}
			if idx+len > b.len {
				return error("Integer: truncated input")
			}
			// read the bytes part from current position idx to the length part
			bytes := unsafe { b[idx..idx + len] }
			// buf := trim_bytes(bytes)!
			ret := Integer.unpack_and_validate(bytes)!
			return ret, idx + len
		}
		else {
			return error('unsupported mode')
		}
	}
}

// valid_bytes validates bytes meets some requirement for DER encoding.
fn valid_bytes(src []u8, signed bool) bool {
	// Requirement for der encoding
	// The contents octets shall consist of one or more octets.
	if src.len == 0 {
		return false
	}

	// check for minimaly encoded
	// If the contents octets of an integer value encoding consist of more
	// than one octet, then the bits of the first octet and bit 8 of
	// the second octets shall not all be ones; and shall not all be zero.
	if src.len > 1 && ((src[0] == 0 && src[1] & 0x80 == 0)
		|| (src[0] == 0xff && src[1] & 0x80 == 0x80)) {
		return false
	}

	// reject negative for unsigned type
	if !signed && src[0] & 0x80 == 0x80 {
		return false
	}
	return true
}

fn is_highest_bit_set(b []u8) bool {
	if b.len > 0 {
		return b[0] & 0x80 == 0
	}
	return false
}

fn trim_bytes(b []u8) ![]u8 {
	if b.len == 0 {
		return error('bad b')
	}
	// TODO: removes prepended bytes when its meet criteria
	// positive value but its prepended with 0x00
	if b.len > 1 && b[0] == 0x00 && b[1] & 0x80 > 0 {
		bytes := b[1..]
		return bytes
	}
	// TODO: how with multiples 0xff
	if b.len > 1 && b[0] == 0xff && b[1] & 0x80 == 0 {
		bytes := b[1..]
		return bytes
	}
	return b
}
