// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

import bitfield

// BITSTRING
//
pub struct BitString {
	data    []u8
	padbits u8
}

pub fn new_bitstring(s string) !BitString {
	return new_bitstring_with_pad(s.bytes(), 0x00)
}

pub fn new_bitstring_from_bytes(src []u8) !BitString {
	bs := read_bitstring(src)!
	return bs
}

fn (bts BitString) as_bits_string() string {
	mut buf := []u8{}
	write_bitstring(mut buf, bts)
	bits := bitfield.from_bytes(buf)
	return bits.str()
}

fn new_bitstring_with_pad(src []u8, pad u8) !Encoder {
	if pad > 7 || (src.len == 0 && pad != 0) {
		return error('bad pad bits or zero length')
	}
	if pad > 0 && (src[src.len - 1]) & ((1 << pad) - 1) != 0 {
		return error('bad args')
	}

	return BitString{
		data: src
		padbits: pad
	}
}

pub fn (bs BitString) tag() Tag {
	return new_tag(.universal, false, int(TagType.bitstring))
}

pub fn (bs BitString) length() int {
	return length_bitstring(bs)
}

pub fn (bs BitString) size() int {
	mut size := 0
	tag := bs.tag()
	t := calc_tag_length(tag)
	size += t

	l := calc_length_of_length(bs.length())
	size += int(l)

	size += bs.length()

	return size
}

pub fn (bs BitString) encode() ![]u8 {
	return serialize_bitstring(bs)
}

pub fn BitString.decode(src []u8) !BitString {
	_, v := decode_bitstring(src)!
	return v
}

fn length_bitstring(b BitString) int {
	return b.data.len + 1
}

fn (b BitString) bytes() []u8 {
	return b.data
}

fn (b BitString) pad_bits() u8 {
	return b.padbits
}

fn (b BitString) bit_length() int {
	return (b.data.len - 1) * 8 - b.padbits
}

fn (b BitString) has_bit_set(n u32) bool {
	idx := n / 8
	v := 1 << (7 - (n & 0x07))
	if b.data.len < (idx + 1) {
		return false
	}
	return b.data[idx] & v != 0
}

fn read_bitstring(src []u8) !BitString {
	if src.len == 0 {
		return error('zero length bit string')
	}

	// bst := new_bst(src[1..], src[0])!
	bst := new_bitstring_with_pad(src[1..], src[0])!

	// check its held BitString type
	if bst is BitString {
		// WARNING: without unsafe *bst block, this error happens,
		// fn `asn1.read_bitstring` expects you to return a non reference type `!asn1.BitString`,
		// but you are returning `&asn1.BitString` instead
		return unsafe { *bst }
	}

	return error('Not held BitString type')
}

fn write_bitstring(mut dst []u8, b BitString) {
	dst << b.pad_bits()
	dst << b.bytes()
}

fn serialize_bitstring(b BitString) ![]u8 {
	tag := new_tag(.universal, false, int(TagType.bitstring))
	mut out := []u8{}

	serialize_tag(mut out, tag)
	n := length_bitstring(b)
	serialize_length(mut out, n)

	write_bitstring(mut out, b)

	return out
}

fn decode_bitstring(src []u8) !(Tag, BitString) {
	if src.len < 2 {
		return error('decode: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.bitstring) {
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

	str := read_bitstring(out)!

	return tag, str
}
