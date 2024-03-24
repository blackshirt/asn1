// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// BITSTRING
//
pub struct BitString {
	tag  Tag = Tag{.universal, false, int(TagType.bitstring)}
	data []u8
	pad  u8
}

// from_string creates new BitString from sring s
pub fn BitString.from_string(s string) !BitString {
	return BitString.from_bytes(s.bytes())
}

pub fn BitString.from_bytes(src []u8) !BitString {
	return BitString.new_with_pad(src, u8(0x00))
}

fn BitString.new_with_pad(src []u8, pad u8) !BitString {
	if pad > 7 || (src.len == 0 && pad != 0) {
		return error('BitString: bad pad bits or zero length')
	}
	if pad > 0 && (src[src.len - 1]) & ((1 << pad) - 1) != 0 {
		return error('BitString: bad args')
	}
	return BitString{
		data: src
		pad: pad
	}
}

fn (bs BitString) bytes_len() int {
	return bs.data.len + 1
}

pub fn (b BitString) tag() Tag {
	return b.tag
}

pub fn (bs BitString) payload(p Params) ![]u8 {
	mut out := []u8{}
	out << bs.pad
	out << bs.data
	return out
}

pub fn (bs BitString) length(p Params) int {
	return bs.bytes_len()
}

pub fn (bs BitString) packed_length(p Params) int {
	mut n := 0

	n += bs.tag().packed_length(p)
	len := bs.length(p)
	bslen := Length.from_i64(len) or { panic(err) }
	n += bslen.packed_length(p)
	n += len

	return n
}

pub fn (bs BitString) encode(mut dst []u8, p Params) ! {
	// we currently only support .der and (stricter) .ber
	if p.mode != .der && p.mode != .ber {
		return error('BitString: unsupported mode')
	}

	bs.tag().encode(mut dst, p)!
	length := Length.from_i64(bs.bytes_len())!
	length.encode(mut dst, p)!

	// write pad bit and data
	dst << bs.pad
	dst << bs.data
}

pub fn BitString.decode(src []u8, loc i64, p Params) !(BitString, i64) {
	raw, next := RawElement.decode(src, loc, p)!

	if raw.tag.class() != .universal || raw.tag.is_constructed()
		|| raw.tag.tag_number() != int(TagType.bitstring) {
		return error('BitString: bad tag check')
	}

	// check for length and required bytes
	if raw.length(p) == 0 {
		return error('BitString: zero length bit string')
	}

	bs := BitString.new_with_pad(raw.payload[1..], raw.payload[0])!
	return bs, next
}
