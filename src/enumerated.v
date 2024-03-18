// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ENUMERATED.
// Enumerated type treated as ordinary integer, only differs on tag value.
// The encoding of an enumerated value shall be that of the integer value with which it is associated.
// NOTE: It is primitive.
pub type Enumerated = int

pub fn new_enumerated(val int) Encoder {
	return Enumerated(val)
}

pub fn (en Enumerated) tag() Tag {
	return new_tag(.universal, false, int(TagType.enumerated))
}

pub fn (en Enumerated) length() int {
	v := length_i64(en)
	return v
}

pub fn (en Enumerated) size() int {
	mut size := 0
	tag := en.tag()
	t := calc_tag_length(tag)
	size += t

	l := calc_length_of_length(en.length())
	size += int(l)

	size += en.length()

	return size
}

pub fn (en Enumerated) encode() ![]u8 {
	res := serialize_i32(en)!
	return res
}

pub fn Enumerated.decode(src []u8) !Enumerated {
	if src.len < 2 {
		return error('bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.enumerated) {
		return error('bad tag')
	}
	if pos > src.len {
		return error('truncated input')
	}
	length, next := decode_length(src, pos)!

	if next > src.len {
		return error('truncated input')
	}
	out := read_bytes(src, next, length)!
	val := read_i32(out)!

	return Enumerated(val)
}