// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// The default tag of ASN.1 NULL type with tag number 5.
const default_null_tag = Tag{.universal, false, int(TagType.null)}

// ASN.1 NULL TYPE
// The ASN.1 NULL type is a placeholder used when there is no value.
// It's a simple, non-string type with the UNIVERSAL TAG number 5.
// The NULL type can be used in situations where the presence of a type is important, but no concrete value is needed.
pub struct Null {}

// `Null.new` creates a Null
pub fn Null.new() Null {
	return Null{}
}

// tag is the tag of Null type.
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

// `Null.parse` tries to read into Null type from ongoing parser.
pub fn Null.parse(mut p Parser) !Null {
	tag := p.read_tag()!
	if !tag.equal(default_null_tag) {
		return error('Get unexpected null tag')
	}
	length := p.read_length()!
	if length != 0 {
		return error('Get unexpected non-null length for Null type')
	}
	null := Null.new()

	return null
}

// Null.decode read Null from bytes.
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
