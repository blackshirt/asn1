// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

import encoding.utf8

// UTF8String
// UTF8 unicode charset
//
type UTF8String = string

fn new_utf8string(s string) !Encoder {
	if !utf8.validate_str(s) {
		return error('invalid UTF-8 string')
	}
	return UTF8String(s)
}

fn (ut UTF8String) tag() Tag {
	return new_tag(.universal, false, int(TagType.utf8string))
}

fn (ut UTF8String) length() int {
	return ut.len
}

fn (ut UTF8String) size() int {
	mut size := 0
	tag := ut.tag()
	t := calc_tag_length(tag)
	size += t

	lol := calc_length_of_length(ut.length())
	size += int(lol)

	size += ut.length()

	return size
}

fn (ut UTF8String) encode() ![]u8 {
	return serialize_utf8string(ut)
}

fn serialize_utf8string(s string) ![]u8 {
	if !utf8.validate_str(s) {
		return error('invalid UTF-8 string')
	}
	t := new_tag(.universal, false, int(TagType.utf8string))
	mut out := []u8{}

	serialize_tag(mut out, t)
	p := s.bytes()
	serialize_length(mut out, p.len)
	out << p
	return out
}

fn read_utf8string(contents []u8) !UTF8String {
	out := contents.bytestr()
	if !utf8.validate_str(out) {
		return error('invalid UTF-8 string')
	}
	return UTF8String(out)
}

fn decode_utf8string(src []u8) !(Tag, string) {
	if src.len < 2 {
		return error('decode numeric: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.utf8string) {
		return error('bad tag')
	}
	if pos > src.len {
		return error('truncated input')
	}

	length, next := decode_length(src, pos)!

	if next > src.len {
		return error('truncated input')
	}
	contents := read_bytes(src, next, length)!
	out := read_utf8string(contents)!

	return tag, out
}
