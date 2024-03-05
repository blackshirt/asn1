// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

import math.big

// INTEGER.
//
// ASN.1 Integer represented by `big.Integer`.
// Its handles number arbitrary length of number with support of `math.big` module.
// The encoding of an integer value shall be primitive.

// Universal class of arbitrary length type of ASN.1 integer
type Integer = big.Integer

fn Integer.from_int(v int) Integer {
	return big.integer_from_int(v)
}

fn Integer.from_int64(v i64) Integer {
	return big.integer_from_i64(v)
}

fn Integer.from_u64(v u64) Integer {
	return big.integer_from_u64(v)
}

// tag returns the tag of Universal class of this Integer type.
fn (v Integer) tag() Tag {
	return new_tag(.universal, false, 2)
}
	
fn (v Integer) bytes_needed() int {
	nbits := v.bit_len()
	if nbits % 8 == 0 { return nbits/8 }
	return nbits/8 + 1
}

fn (v Integer) packed_length() !int {
	mut n := 0
	n += v.tag().tag_length()
	x := Length(v.bytes_needed())
	n += x.length()
	n += v.bytes_needed()

	return n
}

fn (v Integer) pack_to_asn1(mut to []u8, mode EncodingMode) ! {
	match mode {
		.der {
			v.tag().pack(mut to)
			length := Length(v.bytes_needed())
			length.pack(mut to)

			to << v.bytes
		}
		else {
			return error("unsupported mode")
		}
	}
}

fn Integer.unpack_from_asn1(b []u8, loc int, mode EncodingMode) !(Integer, int) {
	match mode {
		.der {
			tag, pos := Tag.unpack(b, loc)!
			if tag != new_tag(.universal, false, 2) {
					return error("Integer: bad tag of universal class type")
			}
			// read the length part from current position pos 
			len, idx := Length.unpack(b, pos)!
			// read the bytes part from current position idx to the length part 
			bytes := unsafe { b[idx..idx+len]}
			ret := read_bigint(bytes)!
			return Integer(ret)
		}
		else {
			return error("unsupported mode")
		}
	}
	
}

// read big.Integer from src bytes 
fn read_bigint(src []u8) !big.Integer {
	if !valid_integer(src, true) {
		return error('big integer check return false')
	}

	if src.len > 0 && src[0] & 0x80 == 0x80 {
		// This is negative number, do two complements rule
		// FIXME: or we can use `big.integer_from_bytes(bytes, signum: -1)` ?
		mut notbytes := []u8{len: src.len}
		for i, _ in notbytes {
			notbytes[i] = ~src[i]
		}
		mut ret := big.integer_from_bytes(notbytes)
		ret += big.one_int
		ret = ret.neg()
		return ret
	}
	s := big.integer_from_bytes(src)
	return s
}

fn valid_integer(src []u8, signed bool) bool {
	if src.len == 0 {
		return false
	}

	// check for minimaly encoded
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

// new_integer creates asn.1 serializable integer object. Its supports
// arbitrary integer value, with support from `math.big` module for
// integer bigger than 64 bit number.
pub fn new_integer(val AsnInteger) Encoder {
	match val {
		int {
			res := val as int
			return AsnInteger(res)
		}
		i64 {
			res := val as i64
			return AsnInteger(res)
		}
		big.Integer {
			res := val as big.Integer
			return AsnInteger(res)
		}
	}
}

// new_integer_from_bytes decodes integer from bytes array
fn new_integer_from_bytes(src []u8) !Encoder {
	x := src.len
	if x <= 4 {
		ret := read_i32(src)!
		return AsnInteger(ret)
	}
	if x <= 8 {
		ret := read_i64(src)!
		return AsnInteger(ret)
	}

	ret := read_bigint(src)!
	return AsnInteger(ret)
}

pub fn (n AsnInteger) tag() Tag {
	return new_tag(.universal, false, int(TagType.integer))
}

pub fn (n AsnInteger) length() int {
	match n {
		int {
			v := n as int
			l := length_i64(v)
			return l
		}
		i64 {
			v := n as i64
			l := length_i64(v)
			return l
		}
		big.Integer {
			v := n as big.Integer
			l, _ := v.bytes()
			return l.len
		}
	}
}

pub fn (n AsnInteger) size() int {
	mut size := 0
	tag := n.tag()
	t := calc_tag_length(tag)
	size += t

	lol := calc_length_of_length(n.length())
	size += int(lol)

	size += n.length()

	return size
}

pub fn (n AsnInteger) encode() ![]u8 {
	match n {
		int {
			val := n as int
			res := serialize_i32(val)!
			return res
		}
		i64 {
			val := n as i64
			res := serialize_i64(val)!
			return res
		}
		big.Integer {
			val := n as big.Integer
			res := serialize_bigint(val)!
			return res
		}
	}
}

fn (n AsnInteger) str() string {
	match n {
		int {
			val := n as int
			return 'INTEGER ${val}'
		}
		i64 {
			val := n as i64
			return 'INTEGER(64) ${val}'
		}
		big.Integer {
			val := n as big.Integer
			return 'INTEGER(BIG) ${val}'
		}
	}
}


// i64 handling

// serialize i64
fn serialize_i64(s i64) ![]u8 {
	t := new_tag(.universal, false, int(TagType.integer))
	mut out := []u8{}

	serialize_tag(mut out, t)

	n := length_i64(s)
	mut src := []u8{len: n}

	i64_to_bytes(mut src, s)
	serialize_length(mut out, src.len)
	out << src
	return out
}

fn decode_i64(src []u8) !(Tag, i64) {
	if src.len < 2 {
		return error('decode: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.integer) {
		return error('bad tag')
	}
	if pos > src.len {
		return error('truncated input')
	}

	// mut length := 0
	length, next := decode_length(src, pos)!

	if next > src.len {
		return error('truncated input')
	}
	out := read_bytes(src, next, length)!

	val := read_i64(out)!

	return tag, val
}

// read_i64 read src as signed i64
fn read_i64(src []u8) !i64 {
	if !valid_integer(src, true) {
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
	$if debug {
		a := new_integer(ret)
		c := a.contents()!
		if c != src {
			eprintln('maybe integer bytes not in shortest form')
		}
	}
	return ret
}

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
		dst[j] = u8(i >> u32(n - 1 - j) * 8)
	}
}

// i32 handling
//
// read_i32 readt  from bytes
fn read_i32(src []u8) !int {
	if !valid_integer(src, true) {
		return error('i32 check return false')
	}

	ret := read_i64(src)!
	if ret != i64(int(ret)) {
		return error('integer too large')
	}

	return int(ret)
}

fn serialize_i32(s i32) ![]u8 {
	out := serialize_i64(i64(s))!
	return out
}

fn decode_i32(src []u8) !(Tag, i32) {
	if src.len < 2 {
		return error('decode: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.integer) {
		return error('bad tag')
	}
	if pos > src.len {
		return error('truncated input')
	}
	length, next := decode_length(src, pos)!

	if next > src.len {
		return error('truncated input')
	}
	out := read_bytes(src, next, length)!
	val := read_i32(out)!

	return tag, val
}

// big.Integer handling

fn serialize_bigint(b big.Integer) ![]u8 {
	tag := new_tag(.universal, false, int(TagType.integer))
	mut out := []u8{}

	serialize_tag(mut out, tag)

	bs, _ := b.bytes()
	serialize_length(mut out, bs.len)
	out << bs

	return out
}

fn decode_bigint(src []u8) !(Tag, big.Integer) {
	if src.len < 2 {
		return error('decode: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.integer) {
		return error('bad tag')
	}
	if pos > src.len {
		return error('truncated input')
	}
	length, next := decode_length(src, pos)!

	if next > src.len {
		return error('truncated input')
	}
	out := read_bytes(src, next, length)!
	val := read_bigint(out)!

	return tag, val
}
