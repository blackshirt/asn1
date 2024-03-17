// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ENUMERATED.
// Enumerated type treated as ordinary integer, only differs on tag value.
// The encoding of an enumerated value shall be that of the integer value with which it is associated.
// NOTE: It is primitive.
struct Enumerated {
	value int
mut:
	tag Tag = Tag{.universal, false, int(TagType.enumerated)}
}

fn Enumerated.from_int(val int) Enumerated {
	return Enumerated{
		value: val
	}
}

fn (e Enumerated) tag() Tag {
	return e.tag
}

fn (e Enumerated) packed_length() !int {
	mut n := 0
	n += e.tag().packed_length()
	len := Length.from_i64(e.value)!
	n += len.packed_length()
	n += e.enumerated_len()
	return n
}

fn (e Enumerated) pack_to_asn1(mut dst []u8, p Params) ! {
	e.tag().pack_to_asn1(mut dst, mode, p)!
	bytes := e.pack()!
	length := Length.from_i64(bytes.len)!
	length.pack_to_asn1(mut dst, mode, p)!
	dst << bytes
}

fn Enumerated.unpack_from_asn1(src []u8, loc i64, p Params) !(Enumerated, i64) {
	if src.len < 3 {
		return error('Enumerated: bad src')
	}
	if p.mode != .der && p.mode != .ber {
		return error('Enumerated: unsupported mode')
	}
	if loc > src.len {
		return error('Enumerated: bad position offset')
	}

	tag, pos := Tag.unpack_from_asn1(src, loc, p)!
	if tag.class() != .universal || tag.is_compound() || tag.tag_number() != int(TagType.enumerated) {
		return error('Enumerated: bad tag of universal class type')
	}
	// read the length part from current position pos
	len, idx := Length.unpack_from_asn1(src, pos, p)!
	if len == 0 {
		return error('Enumerated: len==0')
	}
	if idx + len > src.len || idx + len > src.len {
		return error('Enumerated: truncated input')
	}
	// read the bytes part from current position idx to the length part
	bytes := unsafe { src[idx..idx + len] }
	// buf := trim_bytes(bytes)!
	ret := Enumerated.unpack(bytes)!
	return ret, idx + len
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
