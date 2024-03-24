// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ENUMERATED.
// Enumerated type treated as ordinary integer, only differs on tag value.
// The encoding of an enumerated value shall be that of the integer value with which it is associated.
// NOTE: It is primitive.
pub struct Enumerated {
	tag   Tag = Tag{.universal, false, int(TagType.enumerated)}
	value int
}

pub fn Enumerated.from_int(val int) Enumerated {
	return Enumerated{
		value: val
	}
}

pub fn Enumerated.from_bytes(b []u8) !Enumerated {
	return Enumerated.unpack(b)!
}

pub fn (e Enumerated) tag() Tag {
	return e.tag
}

pub fn (e Enumerated) payload(p Params) ![]u8 {
	return e.pack()!
}

pub fn (e Enumerated) length(p Params) int {
	return e.enumerated_len()
}

pub fn (e Enumerated) packed_length(p Params) !int {
	mut n := 0
	n += e.tag().packed_length(p)
	len := Length.from_i64(e.value)!
	n += len.packed_length(p)
	n += e.enumerated_len()
	return n
}

pub fn (e Enumerated) encode(mut dst []u8, p Params) ! {
	if p.mode != .der && p.mode != .ber {
		return error('Integer: unsupported mode')
	}
	e.tag().encode(mut dst, p)!
	bytes := e.pack()!
	length := Length.from_i64(bytes.len)!
	length.encode(mut dst, p)!
	dst << bytes
}

pub fn Enumerated.decode(src []u8, loc i64, p Params) !(Enumerated, i64) {
	// integer minimaly should length 1 for 0 value
	if src.len < 3 {
		return error('Enumerated: bytes underflow')
	}
	raw, next := RawElement.decode(src, loc, p)!
	if raw.tag.class() != .universal || raw.tag.is_constructed()
		|| raw.tag.tag_number() != int(TagType.enumerated) {
		return error('Enumerated: bad tag of universal class type')
	}
	ret := Enumerated.unpack(raw.payload)!
	return ret, next
}

fn Enumerated.unpack(src []u8) !Enumerated {
	if !valid_bytes(src, true) {
		return error('Enumerated: failed check')
	}
	mut ret := i64(0)
	for i := 0; i < src.len; i++ {
		ret <<= 8
		ret |= i64(src[i])
	}

	ret <<= 64 - u8(src.len) * 8
	ret >>= 64 - u8(src.len) * 8

	if ret != i64(int(ret)) {
		return error('integer too large')
	}
	return Enumerated{
		value: int(ret)
	}
}

fn (e Enumerated) pack() ![]u8 {
	mut n := e.enumerated_len()
	mut dst := []u8{len: n}

	for j := 0; j < n; j++ {
		dst[j] = u8(e.value >> u32(n - 1 - j) * 8)
	}
	return dst
}

fn (e Enumerated) enumerated_len() int {
	mut i := e.value
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
