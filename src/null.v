// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ASN.1 NULL TYPE
pub struct Null {
	tag Tag = Tag{.universal, false, int(TagType.null)}
}

pub fn Null.new() Null {
	return Null{}
}

pub fn Null.from_bytes(b []u8) !Null {
	if b.len != 0 {
		return error('Null: bad bytes')
	}
	return Null{}
}

pub fn (n Null) tag() Tag {
	return n.tag
}

pub fn (n Null) length(p Params) int {
	return 0
}

pub fn (n Null) payload(p Params) ![]u8 {
	return []u8{}
}

pub fn (n Null) packed_length(p Params) int {
	return 2
}

pub fn (n Null) encode(mut dst []u8, p Params) ! {
	if p.mode != .der && p.mode != .ber {
		return error('Integer: unsupported mode')
	}

	n.tag().encode(mut dst, p)!
	// the length is 0
	dst << [u8(0x00)]
}

fn Null.decode(src []u8, loc i64, p Params) !(Null, i64) {
	tlv, next := Tlv.read(src, loc, p)!
	if tlv.tag.class() != .universal || tlv.tag.is_constructed()
		|| tlv.tag.tag_number() != int(TagType.null) {
		return error('Null: bad tag=${tlv.tag}')
	}
	if tlv.length != 0 {
		return error('Null: len != 0')
	}
	return Null.new(), next
}

pub fn (n Null) str() string {
	return 'NULL'
}
