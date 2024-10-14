// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

const default_null_tag = Tag{.universal, false, int(TagType.null)}

// ASN.1 NULL TYPE
pub struct Null {}

pub fn Null.new() Null {
	return Null{}
}

pub fn (n Null) tag() Tag {
	return default_null_tag
}

// payload tells the payload of the Null type, its should empty bytes.
pub fn (n Null) payload() ![]u8 {
	return []u8{}
}

fn (n Null) str() string {
	return 'NULL'
}

// Null.parse read Null from ongoing parser
pub fn Null.parse(mut p Parser) !Null {
	null, next := Null.decode(p.data)!
	rest := if next >= p.data.len { []u8{} } else { unsafe { p.data[next..] } }
	p.data = rest
	return null
}

// Null.decode read Null from bytes
pub fn Null.decode(bytes []u8) !(Null, i64) {
	tag, length_pos := Tag.decode(bytes)!
	if !tag.equal(default_null_tag) {
		return error('Null: get unexpected tag')
	}
	length, content_pos := Length.decode_from_offset(bytes, length_pos)!
	if length != 0 {
		return error('Null with non-null length')
	}
	next := content_pos + length
	return Null{}, next
}

fn Null.from_bytes(b []u8) !Null {
	return Null.from_bytes_with_rule(b, .der)!
}

fn Null.from_bytes_with_rule(b []u8, rule EncodingRule) !Null {
	if b.len != 0 {
		return error('Null: bad non-null bytes')
	}
	return Null{}
}
