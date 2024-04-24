// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

import math.big

// ASN.1 INTEGER.
//
// The INTEGER type value can be a positive or negative number.
// There are no limits imposed on the magnitude of INTEGER values in the ASN.1 standard.
// Its handles number arbitrary length of number with support of `math.big` module.
// But, for sake of safety, we limit the INTEGER limit to follow allowed length in
// definite form of Length part, ie, 1008 bit, or 126 bytes
// The encoding of an integer number shall be primitive.

// Limit of length of INTEGER type, in bytes
// Known big RSA keys is 4096 bits, ie, 512 bytes
const max_integer_length = 2048

// Integer represent Universal class of arbitrary length type of ASN.1 INTEGER
// The encoding of an integer value shall be primitive.
// If the contents octets of an integer value encoding consist of more than one octet,
// then the bits of the first octet and bit 8 of the second octet:
// 	a) shall not all be ones; and
// 	b) shall not all be zero.
// NOTE – These rules ensure that an integer value is always encoded in the smallest possible number of octets
pub struct Integer {
mut:
	tag Tag = Tag{.universal, false, int(TagType.integer)}
	// underlying integer value with support from i64 and big.Integer
	value IntValue
}

// from_i64 creates new a ASN.1 Integer from i64 v
pub fn Integer.from_i64(v i64) Integer {
	return Integer{
		value: IntValue(v)
	}
}

// from_int creates a new ASN.1 Integer from int v
pub fn Integer.from_int(v int) Integer {
	return Integer{
		value: IntValue(i64(v))
	}
}

// from_bigint creates a new ASN.1 Integer from big.Integer b
pub fn Integer.from_bigint(b big.Integer) Integer {
	return Integer{
		value: IntValue(b)
	}
}

// from_string creates a new ASN.1 Integer from decimal string s.
// If your string value is below max_i64, use from_i64 instead
pub fn Integer.from_string(s string) !Integer {
	v := big.integer_from_string(s)!
	return Integer{
		value: IntValue(v)
	}
}

// from_hex creates a new ASN.1 Integer from hex string in x
// where x is a valid hex string without `0x` prefix.
// If your string value is below max_i64, use from_i64 instead
pub fn Integer.from_hex(x string) !Integer {
	s := big.integer_from_radix(x, 16)!
	return Integer{
		value: IntValue(s)
	}
}

// from_bytes creates a new ASN.1 Integer from bytes array in b.
// Its try to parse bytes as in two's complement form. see `unpack_from_twoscomplement_bytes`
pub fn Integer.from_bytes(b []u8, p Params) !Integer {
	return Integer.unpack_from_twoscomplement_bytes(b, p)!
}

// bytes return underlying bytes array
pub fn (v Integer) bytes() []u8 {
	return v.value.bytes()
}

// bytes_len returns underlying bytes length
fn (v Integer) bytes_len() int {
	b := v.value.bytes()
	return b.len
}

// equal do checking if n equal to m.
// ISSUE?: There are some issues when compared n == m directly,
// its fails even internally its a same, so we provide and use equality check
pub fn (n Integer) equal(m Integer) bool {
	nbytes := n.bytes()
	mbytes := m.bytes()
	// todo: check sign equality
	return n.tag == m.tag && nbytes == mbytes
}

// pack_into_twoscomplement_form serialize Integer in two's-complement rules.
// 	- 	The integer value contains the encoded integer if it is positive, or its two's complement if it is negative.
// 	- 	If the integer is positive but the high order bit is set to 1, a leading 0x00 is added to the content
// 		to indicate that the number is not negative.
// 	-	If the number is negative after applying two's-complement rules, and the the most-significant-bit of the
// 		the high order bit of the bytes results isn't set, pad it with 0xff in order to keep the number negative.
fn (v Integer) pack_into_twoscomplement_form(p Params) !([]u8, int) {
	match v.value {
		i64 {
			val := v.value as i64
			mut bytes := i64_to_bytes(val)
			return bytes, bytes.len
		}
		big.Integer {
			match v.value.signum {
				0 {
					return [u8(0x00)], 1
				}
				1 {
					mut b := v.bytes()
					// handle the zero issues
					if b.len == 0 {
						return [u8(0x00)], 1
					}
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
	}
}

// Integer.unpack_and_validate deserializes bytes in b into Integer
// in two's complement way and perform validation on this bytes to
// meet der requirement.
fn Integer.unpack_and_validate(b []u8, p Params) !Integer {
	if !valid_bytes(b, true) {
		return error('Integer: check return false')
	}
	ret := Integer.unpack_from_twoscomplement_bytes(b, p)!
	return ret
}

// unpack_from_twoscomplement_bytes parses the bytes in b into the Integer
// value in the big-endian two's complement way. If b[0]&80 != 0, the number
// is negative. If b is empty it would be error.
fn Integer.unpack_from_twoscomplement_bytes(b []u8, p Params) !Integer {
	// FIXME: should we return error instead ?
	if b.len == 0 {
		return error('Integer: null bytes')
	}
	if b.len > 8 {
		mut num := big.integer_from_bytes(b)
		// negative number
		if b.len > 0 && b[0] & 0x80 > 0 {
			sub := big.one_int.left_shift(u32(b.len) * 8)
			num -= sub
		}

		return Integer{
			value: IntValue(num)
		}
	}
	// use i64
	val := read_i64(b)!
	res := Integer.from_i64(val)
	return res
}

pub fn (v Integer) packed_length(p Params) int {
	mut n := 0
	n += v.tag().packed_length(p)

	len := Length.from_i64(v.bytes_len()) or { panic(err) }
	n += len.packed_length(p)
	n += v.bytes_len()

	return n
}

pub fn (v Integer) tag() Tag {
	return v.tag
}

// as_bigint casts Integer value to big.Integer or error on fails.
pub fn (v Integer) as_bigint() !big.Integer {
	if v.value is big.Integer {
		val := v.value as big.Integer
		return val
	}
	return error('not hold big.Integer type')
}

// as_i64 casts Integer value to i64 value or error on fails.
pub fn (v Integer) as_i64() !i64 {
	if v.value is i64 {
		val := v.value as i64
		return val
	}
	return error('not hold i64 type')
}

pub fn (v Integer) payload(p Params) ![]u8 {
	bytes, _ := v.pack_into_twoscomplement_form(p)!
	return bytes
}

pub fn (v Integer) length(p Params) int {
	return v.bytes_len()
}

// encode serializes and encodes Integer v into bytes and appended into `dst`.
// Its accepts encoding mode params, where its currently only suppport `.der` DER mode.
// If `dst.len != 0`, it act as append semantic, otherwise the `dst` bytes stores the result.
pub fn (v Integer) encode(mut dst []u8, p Params) ! {
	if p.mode != .der && p.mode != .ber {
		return error('Integer: unsupported mode')
	}

	v.tag().encode(mut dst, p)!
	bytes, n := v.pack_into_twoscomplement_form(p)!
	length := Length.from_i64(n)!
	length.encode(mut dst, p)!
	dst << bytes
}

// decode deserializes and decodes bytes src back into ASN.1 Integer.
// Its accepts `loc` params, the location (offset) within bytes src where the unpack
// process start form, if not sure set to 0 and optional mode in `Params` to drive unpacking.
// see `EncodingMode` for availables values. Currently only support`.der`.
pub fn Integer.decode(src []u8, loc i64, p Params) !(Integer, i64) {
	if src.len < 3 {
		return error('IA5String: bad ia5string bytes length')
	}
	raw, next := RawElement.decode(src, loc, p)!
	if raw.tag.class() != .universal || raw.tag.is_constructed()
		|| raw.tag.tag_number() != int(TagType.integer) {
		return error('Integer: bad tag of universal class type')
	}
	if raw.payload.len == 0 {
		return error('Integer: len==0')
	}

	bytes := raw.payload
	// buf := trim_bytes(bytes)!
	ret := Integer.from_bytes(bytes, p)!
	return ret, next
}

// IntValue represents arbitrary integer value, currently we support
// through primitive 164 type for integer value below < max_i64, and
// use `big.Integer` for support arbitrary length of integer values.
type IntValue = big.Integer | i64

fn (v IntValue) str() string {
	match v {
		i64 {
			val := v as i64
			return val.str()
		}
		big.Integer {
			val := v as big.Integer
			return val.str()
		}
	}
}

// bytes get the bytes representation from underlying IntValue
fn (v IntValue) bytes() []u8 {
	match v {
		i64 {
			return i64_to_bytes(v)
		}
		big.Integer {
			// if v == big.zero_int or similar big.Integer values that produces empty bytes,
			// returns v.bytes() directly can lead to undesired behavior thats doesn't aligned with
			// ASN.1 INTEGER requirement. See the discussion on the discord about the issues
			// at https://discord.com/channels/592103645835821068/592294828432424960/1230460279733620777
			// so, we do some hack to get the correct value
			// TODO: find the correct way to tackle this
			if v == big.zero_int {
				return [u8(0x00)]
			}
			// todo: proper check of 0 bytes length
			if v.bit_len() == 0 {
				return [u8(0x00)]
			}
			// otherwise, we use v.bytes() directly
			b, _ := v.bytes()
			return b
		}
	}
}

// Utility function

// valid_bytes validates bytes meets some requirement for BER/DER encoding.
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

fn is_highest_bit_set(src []u8) bool {
	if src.len > 0 {
		return src[0] & 0x80 == 0
	}
	return false
}

fn trim_bytes(src []u8) ![]u8 {
	if src.len == 0 {
		return error('bad src')
	}
	// TODO: removes prepended bytes when its meet criteria
	// positive value but its prepended with 0x00
	if src.len > 1 && src[0] == 0x00 && src[1] & 0x80 > 0 {
		bytes := src[1..]
		return bytes
	}
	// TODO: how to do with multiples 0xff
	if src.len > 1 && src[0] == 0xff && src[1] & 0x80 == 0 {
		bytes := src[1..]
		return bytes
	}
	return src
}

// length_i64 gets bytes length needed to reperesent this i64 value
fn length_i64(val i64) int {
	mut i := val
	mut n := 1

	for i > 127 {
		n++
		i >>= 8
	}

	for i < -128 {
		n++
		i >>= 8
	}

	return n
}

// i64_to_bytes transforms i64 value into bytes representation
fn i64_to_bytes(i i64) []u8 {
	mut n := length_i64(i)
	mut dst := []u8{len: n}
	for j := 0; j < n; j++ {
		dst[j] = u8(i >> u32((n - 1 - j) * 8))
	}
	return dst
}

// read_i64 read src as signed i64
fn read_i64(src []u8) !i64 {
	if !valid_bytes(src, true) {
		return error('i64 check return false')
	}
	mut ret := i64(0)

	if src.len > 8 {
		return error('too large integer')
	}
	for i := 0; i < src.len; i++ {
		ret <<= 8
		ret |= i64(src[i])
	}

	ret <<= 64 - u8(src.len) * 8
	ret >>= 64 - u8(src.len) * 8

	// try to serialize back, and check its matching original one
	// and gives a warning when its not match.

	dst := i64_to_bytes(ret)
	if dst != src {
		eprintln('maybe integer bytes not in shortest form')
	}

	return ret
}

// i32 handling
//
// read_i32 read from bytes
fn read_i32(src []u8) !int {
	if !valid_bytes(src, true) {
		return error('i32 check return false')
	}

	ret := read_i64(src)!
	if ret != i64(int(ret)) {
		return error('integer too large')
	}

	return int(ret)
}

fn length_i32(v i32) int {
	return length_i64(i64(v))
}

fn i32_to_bytes(v i32) []u8 {
	return i64_to_bytes(i64(v))
}
