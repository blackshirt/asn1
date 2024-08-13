<<<<<<< HEAD
module asn1

// ASN.1 GENERALSTRING Handling
// It may contain any characters from a "G" and "C" set of any standardized character sets.
// A "G" set contains some specified set of graphic (i.e., printable) characters,
// while a "C" set contains a group of control characters.
// For example, the "G" set in the ASCII character set consists of the characters with ASCII numbers 33 through 126,
// while the "C" set is those characters with ASCII numbers 0 through 31.
// For historical reasons, the characters SPACE (number 32) and DELETE (number 127)
// are not considered to be in either the C set or the G set, but instead stand on their own
// We only treated GeneralString as an us-ascii charset
pub struct GeneralString {
	value string
	tag   Tag = Tag{.universal, false, int(TagType.generalstring)}
}

// TODO: proper check GeneralString validation
// from_string creates GeneralString from string s
pub fn GeneralString.from_string(s string) !GeneralString {
	if !s.is_ascii() {
		return error('GeneralString: contains non-ascii chars')
	}
	return GeneralString{
		value: s
	}
}

// from_bytes creates GeneralString from bytes b
pub fn GeneralString.from_bytes(b []u8) !GeneralString {
	if b.any(it < u8(` `) || it > u8(`~`)) {
		return error('GeneralString: bytes contains non-ascii chars')
	}
	return GeneralString{
		value: b.bytestr()
	}
}

pub fn (g GeneralString) tag() Tag {
	return g.tag
}

pub fn (g GeneralString) value() string {
	return g.value
}

pub fn (g GeneralString) payload(p Params) ![]u8 {
	if !g.value.is_ascii() {
		return error('GeneralString: contains non-ascii chars')
	}
	return g.value.bytes()
}

pub fn (g GeneralString) length(p Params) !int {
	return g.value.bytes().len
}

pub fn (g GeneralString) packed_length(p Params) !int {
	mut n := 0

	n += g.tag.packed_length(p)!
	len := Length.from_i64(g.value.bytes().len)!
	n += len.packed_length(p)!
	n += g.value.bytes().len

	return n
}

pub fn (g GeneralString) encode(mut dst []u8, p Params) ! {
	if !g.value.is_ascii() {
		return error('GeneralString: contains non-ascii char')
	}
	if p.mode != .der && p.mode != .ber {
		return error('GeneralString: unsupported mode')
	}

	g.tag.encode(mut dst, p)!
	bytes := g.value.bytes()
	length := Length.from_i64(bytes.len)!
	length.encode(mut dst, p)!
	dst << bytes
}

pub fn GeneralString.decode(src []u8, loc i64, p Params) !(GeneralString, i64) {
	raw, next := RawElement.decode(src, loc, p)!
	if raw.tag.tag_class() != .universal || raw.tag.is_constructed()
		|| raw.tag.tag_number() != int(TagType.generalstring) {
		return error('GeneralString: bad tag of universal class type')
	}
	// no bytes
	if raw.length(p)! == 0 {
		// empty content
		return GeneralString{}, next
	}
	// check for ASCII charset
	if raw.payload.any(it < u8(` `) || it > u8(`~`)) {
		return error('GeneralString: bytes contains non-ascii chars')
	}
	ret := GeneralString{
		value: raw.payload.bytestr()
	}
	return ret, next
}

// Utility function
fn validate_general_string(s string) bool {
	if !s.is_ascii() {
		return false
	}
	return true
=======
// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// GeneralString handling routine
// Standard ASCII characters
// TODO: NEED TO BE FIXED, NOT TESTED
type GeneralString = string

pub fn new_generalstring(s string) !Encoder {
	if !is_generalstring(s) {
		return error('bad ascii string')
	}
	return GeneralString(s)
}

pub fn (gn GeneralString) tag() Tag {
	return new_tag(.universal, false, int(TagType.generalstring))
}

pub fn (gn GeneralString) length() int {
	return gn.len
}

pub fn (gn GeneralString) size() int {
	mut size := 0
	tag := gn.tag()
	t := calc_tag_length(tag)
	size += t

	lol := calc_length_of_length(gn.length())
	size += int(lol)

	size += gn.length()

	return size
}

pub fn (gn GeneralString) encode() ![]u8 {
	return serialize_generalstring(gn)
}

pub fn GeneralString.decode(src []u8) !GeneralString {
	_, val := decode_generalstring(src)!
	return GeneralString(val)
}

fn (gn GeneralString) str() string {
	return 'generalstring ${string(gn)}'
}

fn is_generalstring(c string) bool {
	return c.is_ascii()
}

fn serialize_generalstring(s string) ![]u8 {
	if !is_generalstring(s) {
		return error('contains invalid char')
	}

	t := new_tag(.universal, false, int(TagType.generalstring))
	mut out := []u8{}

	serialize_tag(mut out, t)
	p := s.bytes()
	serialize_length(mut out, p.len)
	out << p
	return out
}

fn decode_generalstring(src []u8) !(Tag, string) {
	if src.len < 2 {
		return error('decode numeric: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.generalstring) {
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

	if !is_generalstring(out.bytestr()) {
		return error('contains invalid char')
	}
	return tag, out.bytestr()
>>>>>>> main
}
