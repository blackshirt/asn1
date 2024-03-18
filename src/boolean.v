// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ASN.1 BOOLEAN
//
// A Boolean value can take true or false.
// ASN.1 DER encoding restricts encoding of boolean true value to 0xff
// and otherwise, encodes to zero (0x00) for false value.
// The encoding of a boolean value shall be primitive. The contents octets shall consist of a single octet.
type Boolean = bool

const (
	allowed_boolean_value = [u8(0x00), 0xff]
)

pub fn new_boolean(value bool) Encoder {
	return Boolean(value)
}

fn new_boolean_from_bytes(src []u8) !Encoder {
	ret := decode_boolean(src)!
	return ret
}

fn validate_boolean(content []u8) bool {
	return content.len == 1 && content[0] in asn1.allowed_boolean_value
}

// read_boolean read boolean content without tag and length parts
fn read_boolean(content []u8) !Encoder {
	if !validate_boolean(content) {
		return error('bad boolean content')
	}
	val := if content[0] == u8(0xff) { true } else { false }

	return Boolean(val)
}

fn validate_boolean_contents(src []u8) bool {
	if src.len != 3 || src[0] != 0x01 || src[1] != 0x01 || (src[2] != 0x00 && src[2] != 0xff) {
		return false
	}
	return true
}

// decode_boolean checks whether bytes arrays was ASN.1 boolean.
fn decode_boolean(src []u8) !Encoder {
	if !validate_boolean_contents(src) {
		return error('bad boolean contents argument')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.boolean) {
		return error('tag.number=${tag.number} is not boolean type (${TagType.boolean})')
	}
	length, idx := decode_length(src, pos)!
	if length != 1 {
		return error('boolean length ${length} != 1')
	}
	contents := read_bytes(src, idx, length)!
	ret := read_boolean(contents)!

	return ret
}

pub fn (b Boolean) tag() Tag {
	t := new_tag(.universal, false, int(TagType.boolean))
	return t
}

pub fn (b Boolean) length() int {
	return 1
}

pub fn (b Boolean) size() int {
	mut size := 0
	tag := b.tag()
	t := calc_tag_length(tag)
	size += t

	l := calc_length_of_length(b.length())
	size += int(l)

	size += b.length()

	return size
}

pub fn (b Boolean) encode() ![]u8 {
	res := encode_boolean(b)
	return res
}

pub fn Boolean.decode(src []u8) !Boolean {
	if !validate_boolean_contents(src) {
		return error('bad boolean contents argument')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.boolean) {
		return error('tag.number=${tag.number} is not boolean type (${TagType.boolean})')
	}
	length, idx := decode_length(src, pos)!
	if length != 1 {
		return error('boolean length ${length} != 1')
	}
	contents := read_bytes(src, idx, length)!
	ret := read_boolean(contents)!

	return ret
}

fn encode_boolean(val bool) []u8 {
	mut b := u8(0)
	mut dst := []u8{}
	match val {
		false { b = u8(0x00) }
		true { b = u8(0xff) }
	}
	t := new_tag(.universal, false, int(TagType.boolean))
	serialize_tag(mut dst, t)
	serialize_length(mut dst, 1)
	dst << b
	return dst
}
