// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

import math.big

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
pub struct Integer {
	tag   Tag = Tag{.universal, false, int(TagType.integer)}
	value big.Integer
}

pub fn Integer.from_bigint(b big.Integer) !Integer {
	if b == big.zero_int {
		return Integer{
			value: asn1.zero_integer
		}
	}
	return Integer{
		value: b
	}
}

// from_string creates a new ASN.1 Integer from decimal string s.
pub fn Integer.from_string(s string) Integer {
	v := big.integer_from_string(s) or { panic(err) }
	if v == big.zero_int {
		return Integer{
			value: asn1.zero_integer
		}
	}

	return Integer{
		value: v
	}
}

pub fn Integer.from_bytes(b []u8) !Integer {
	return Integer.unpack_from_twoscomplement_bytes(b)!
}

// from_hex creates a new ASN.1 Integer from hex string in x
// where x is a valid hex string without `0x` prefix.
pub fn Integer.from_hex(x string) !Integer {
	s := big.integer_from_radix(x, 16)!
	if s == big.zero_int {
		return Integer{
			value: asn1.zero_integer
		}
	}
	return Integer{
		value: s
	}
}

// from_i64 creates new a ASN.1 Integer from i64 v
pub fn Integer.from_i64(v i64) Integer {
	// same issue as above
	if v == 0 {
		return Integer{
			value: asn1.zero_integer
		}
	}
	return Integer{
		value: big.integer_from_i64(v)
	}
}

// from_u64 creates new Integer from u64 v
pub fn Integer.from_u64(v u64) Integer {
	if v == 0 {
		return Integer{
			value: asn1.zero_integer
		}
	}
	return Integer{
		value: big.integer_from_u64(v)
	}
}

// equal do checking if n equal to m.
// ISSUE?: There are some issues when compared n == m directly,
// its fails even internally its a same, so we provide and use equality check
pub fn (n Integer) equal(m Integer) bool {
	nbytes, nsignum := n.value.bytes()
	mbytes, msignum := m.value.bytes()

	return n.tag == m.tag && nbytes == mbytes && nsignum == msignum
}

fn (v Integer) bytes() []u8 {
	if v.value == asn1.zero_integer {
		return [u8(0x00)]
	}
	bytes, _ := v.value.bytes()
	return bytes
}

fn (v Integer) bytes_len() int {
	if v.value == asn1.zero_integer {
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

pub fn (v Integer) value() big.Integer {
	return v.value
}

pub fn (v Integer) payload(p Params) ![]u8 {
	bytes, _ := v.pack_into_twoscomplement_form()!
	return bytes
}

pub fn (v Integer) length(p Params) int {
	return v.bytes_len()
}

// pack_to_asn1 packs and serializes Integer v into ASN 1 serialized bytes into `dst`.
// Its accepts encoding mode params, where its currently only suppport `.der` DER mode.
// If `dst.len != 0`, it act as append semantic, otherwise the `dst` bytes stores the result.
pub fn (v Integer) encode(mut dst []u8, p Params) ! {
	if p.mode != .der && p.mode != .ber {
		return error('Integer: unsupported mode')
	}

	v.tag().encode(mut dst, p)!
	bytes, n := v.pack_into_twoscomplement_form()!
	length := Length.from_i64(n)!
	length.encode(mut dst, p)!
	dst << bytes
}

// unpack_from_asn1 deserializes bytes src into ASN.1 Integer.
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
	ret := Integer.unpack_and_validate(bytes)!
	return ret, next
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
	// TODO: how with multiples 0xff
	if src.len > 1 && src[0] == 0xff && src[1] & 0x80 == 0 {
		bytes := src[1..]
		return bytes
	}
	return src
}

// INT64
pub struct Int64 {
	tag   Tag = Tag{.universal, false, int(TagType.integer)}
	value i64
}

pub fn Int64.from_i64(v i64) Int64 {
	return Int64{
		value: v
	}
}

pub fn Int64.from_bytes(src []u8) !Int64 {
	val := read_i64(src)!
	return Int64.from_i64(val)
}

pub fn (v Int64) tag() Tag {
	return v.tag
}

pub fn (v Int64) value() i64 {
	return i64(v.value)
}

pub fn (v Int64) payload(p Params) ![]u8 {
	mut n := length_i64(v.value)
	mut dst := []u8{len: n}
	i64_to_bytes(mut dst, v.value)
	return dst
}

pub fn (v Int64) length(p Params) int {
	return length_i64(v.value)
}

pub fn (v Int64) packed_length(p Params) int {
	mut n := 0
	n += v.tag().packed_length(p)
	len := v.length(p)
	vlen := Length.from_i64(len) or { panic(err) }
	n += vlen.packed_length(p)
	n += len

	return n
}

pub fn (v Int64) encode(mut dst []u8, p Params) ! {
	v.tag().encode(mut dst, p)!
	payload := v.payload(p)!
	len := Length.from_i64(payload.len)!
	len.encode(mut dst, p)!
	dst << payload
}

pub fn Int64.decode(src []u8, loc i64, p Params) !(Int64, i64) {
	if src.len < 3 {
		return error('Int64: bytes underflow')
	}
	raw, next := RawElement.decode(src, loc, p)!
	if raw.payload.len == 0 {
		return error('Int64: len==0')
	}

	bytes := raw.payload
	val := read_i64(bytes)!

	return Int64.from_i64(val), next
}

// Utility function
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

fn i64_to_bytes(mut dst []u8, i i64) {
	mut n := length_i64(i)

	for j := 0; j < n; j++ {
		dst[j] = u8(i >> u32((n - 1 - j) * 8))
	}
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

	a := Int64.from_i64(ret)
	mut n := length_i64(a.value)
	mut dst := []u8{len: n}
	i64_to_bytes(mut dst, a.value)
	if dst != src {
		eprintln('maybe integer bytes not in shortest form')
	}

	return ret
}

// i32 handling
//
// read_i32 readt  from bytes
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
