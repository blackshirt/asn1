// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// BITSTRING
//
struct BitString {
	data []u8
	pad  u8
mut:
	tag Tag = new_tag(.universal, false, int(TagType.bitstring))!
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

fn (b BitString) tag() Tag {
	return b.tag
}

fn (bs BitString) payload(p Params) ![]u8 {
	mut out := []u8{}
	out << bs.pad
	out << bs.data
	return out
}

fn (bs BitString) payload_length() int {
	return bs.bytes_len()
}

fn (bs BitString) packed_length(p Params) int {
	mut n := 0

	n += bs.tag().packed_length(p)
	len := bs.payload_length()
	bslen := Length.from_i64(len) or { panic(err) }
	n += bslen.packed_length(p)
	n += len

	return n
}

fn (bs BitString) pack_to_asn1(mut dst []u8, p Params) ! {
	// we currently only support .der and (stricter) .ber
	if p.mode != .der && p.mode != .ber {
		return error('BitString: unsupported mode')
	}

	bs.tag().pack_to_asn1(mut dst, p)!
	length := Length.from_i64(bs.bytes_len())!
	length.pack_to_asn1(mut dst, p)!

	// write pad bit and data
	dst << bs.pad
	dst << bs.data
}

fn BitString.unpack_from_asn1(src []u8, loc i64, p Params) !(BitString, i64) {
	if src.len < 2 {
		return error('BitString: b.len underflow')
	}
	// we currently only support .der and (stricter) .ber
	if p.mode != .der && p.mode != .ber {
		return error('BitString: unsupported mode')
	}
	if loc > src.len {
		return error('BitString: bad position offset')
	}

	// TODO: support for other encoding mode
	tag, pos := Tag.unpack_from_asn1(src, loc, p)!
	if tag.class() != .universal || tag.is_constructed()
		|| tag.tag_number() != int(TagType.bitstring) {
		return error('BitString: bad tag check')
	}
	len, idx := Length.unpack_from_asn1(src, pos, p)!
	// check for length and required bytes
	if len == 0 {
		return error('BitString: zero length bit string')
	}
	if idx > src.len || idx + len > src.len {
		return error('BitString: truncated bytes')
	}
	// todo: check length
	bytes := unsafe { src[idx..idx + len] }

	bs := BitString.new_with_pad(bytes[1..], bytes[0])!
	return bs, idx + len
}
