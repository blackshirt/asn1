// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// BOOLEAN
// A Boolean value can take true or false.
// ASN.1 DER encoding restricts encoding of boolean true value to 0xff
// and otherwise, encodes to zero (0x00) for false value.
// The encoding of a boolean value shall be primitive. The contents octets shall consist of a single octet.
struct AsnBoolean {
	value bool
}

const (
	allowed_boolean_value = [u8(0x00), 0xff]
)

pub fn new_boolean(value bool) Encoder {
	return AsnBoolean{value}
}

fn new_boolean_from_bytes(src []u8) !Encoder {
	ret := decode_boolean(src)!
	return ret
}

// read_boolean read boolean contents without tag and length parts
fn read_boolean(contents []u8) !Encoder {
	if contents.len != 1 {
		return error('bad len of boolean bytes')
	}
	if contents[0] !in asn1.allowed_boolean_value {
		return error('bad bool bytes')
	}
	val := if contents[0] == u8(0xff) { true } else { false }

	return AsnBoolean{val}
}

// decode_boolean checks whether bytes arrays was ASN.1 boolean.
fn decode_boolean(src []u8) !Encoder {
	if src.len < 3 || src[0] != 0x01 || src[1] != 0x01 || (src[2] != 0x00 && src[2] != 0xff) {
		return error('boolean: invalid args of src')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.boolean) {
		return error('tag.number=${tag.number} is not boolean type (${TagType.boolean})')
	}
	length, idx := decode_length(src, pos)!

	contents := read_bytes(src, idx, length)!
	ret := read_boolean(contents)!

	return ret
}

fn (b AsnBoolean) tag() Tag {
	t := new_tag(.universal, false, int(TagType.boolean))
	return t
}

fn (b AsnBoolean) length() int {
	return 1
}

fn (b AsnBoolean) size() int {
	mut size := 0
	tag := b.tag()
	t := calc_tag_length(tag)
	size += t

	l := calc_length_of_length(b.length())
	size += int(l)

	size += b.length()

	return size
}

fn (b AsnBoolean) encode() ![]u8 {
	res := encode_boolean(b.value)
	return res
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
