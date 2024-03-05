// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// IA5String handling routine
// Standard ASCII characters
type IA5String = string

pub fn new_ia5string(s string) !Encoder {
	if !is_ia5string(s) {
		return error('bad ascii string')
	}
	return IA5String(s)
}

pub fn (a5 IA5String) tag() Tag {
	return new_tag(.universal, false, int(TagType.ia5string))
}

pub fn (a5 IA5String) length() int {
	return a5.len
}

pub fn (a5 IA5String) size() int {
	mut size := 0
	tag := a5.tag()
	t := calc_tag_length(tag)
	size += t

	lol := calc_length_of_length(a5.length())
	size += int(lol)

	size += a5.length()

	return size
}

pub fn (a5 IA5String) encode() ![]u8 {
	return serialize_ia5string(a5)
}

fn (a5 IA5String) str() string {
	return 'IA5STRING ${string(a5)}'
}

fn is_ia5string(c string) bool {
	return c.is_ascii()
}

fn serialize_ia5string(s string) ![]u8 {
	if !is_ia5string(s) {
		return error('contains invalid char')
	}

	t := new_tag(.universal, false, int(TagType.ia5string))
	mut out := []u8{}

	serialize_tag(mut out, t)
	p := s.bytes()
	serialize_length(mut out, p.len)
	out << p
	return out
}

fn decode_ia5string(src []u8) !(Tag, string) {
	if src.len < 2 {
		return error('decode numeric: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.ia5string) {
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

	if !is_ia5string(out.bytestr()) {
		return error('contains invalid char')
	}
	return tag, out.bytestr()
}
