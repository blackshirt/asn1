// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// VisibleString
//
type VisibleString = string

fn new_visiblestring(s string) !Encoder {
	if !is_visiblestring(s.bytes()) {
		return error('bad visible char')
	}
	return VisibleString(s)
}

fn (vs VisibleString) tag() Tag {
	return new_tag(.universal, false, int(TagType.visiblestring))
}

fn (vs VisibleString) length() int {
	return vs.len
}

fn (vs VisibleString) size() int {
	mut size := 0
	tag := vs.tag()
	t := calc_tag_length(tag)
	size += t

	l := calc_length_of_length(vs.length())
	size += int(l)

	size += vs.length()

	return size
}

fn (vs VisibleString) encode() ![]u8 {
	return serialize_visiblestring(vs)
}

fn is_ctrl_char(c u8) bool {
	return (c >= 0 && c <= 0x1f) || c == 0x7f
}

fn is_visiblestring(src []u8) bool {
	for c in src {
		if is_ctrl_char(c) {
			return false
		}
	}
	return true
}

fn serialize_visiblestring(s string) ![]u8 {
	p := s.bytes()
	if !is_visiblestring(p) {
		return error('contains invalid (control) char')
	}

	t := new_tag(.universal, false, int(TagType.visiblestring))
	mut out := []u8{}

	serialize_tag(mut out, t)
	serialize_length(mut out, p.len)
	out << p
	return out
}

fn decode_visiblestring(src []u8) !(Tag, string) {
	if src.len < 2 {
		return error('decode numeric: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.visiblestring) {
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
	out := src[next..next + length]

	if !is_visiblestring(out) {
		return error('invalid UTF-8 string')
	}

	return tag, out.bytestr()
}
