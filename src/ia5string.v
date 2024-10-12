// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// IA5String handling routine
// Standard ASCII characters
@[heap; noinit]
pub struct IA5String {
mut:
	value string
}

// new creates IA5String from string s
pub fn IA5String.new(s string) !IA5String {
	if !valid_ia5string(s) {
		return error('IA5String: contains non-ascii chars')
	}
	return IA5String{
		value: s
	}
}

pub fn (v IA5String) tag() Tag {
	return Tag{.universal, false, int(TagType.ia5string)}
}

pub fn (v IA5String) payload() ![]u8 {
	if !v.value.is_ascii() {
		return error('IA5String: contains non-ascii chars')
	}
	return v.value.bytes()
}

fn (v IA5String) str() string {
	if v.value.len == 0 {
		return 'IA5String: (<empty>)'
	}
	return 'IA5String: (${v.value})'
}

pub fn IA5String.parse(mut p Parser) !IA5String {
	tag := p.read_tag()!
	if !tag.expect(.universal, false, int(TagType.ia5string)) {
		return error('Bad Ia5String tag')
	}
	length := p.read_length()!
	bytes := p.read_bytes(length)!

	res := IA5String.from_bytes(bytes)!

	return res
}

pub fn IA5String.decode(bytes []u8) !(IA5String, i64) {
	bs, next := IA5String.decode_with_rule(bytes, .der)!
	return bs, next
}

fn IA5String.decode_with_rule(bytes []u8, rule EncodingRule) !(IA5String, i64) {
	tag, length_pos := Tag.decode_with_rule(bytes, 0, rule)!
	if !tag.expect(.universal, false, int(TagType.ia5string)) {
		return error('Unexpected non-ia5string tag')
	}
	length, content_pos := Length.decode_with_rule(bytes, length_pos, rule)!

	// if the length is 0, this mean if the payload is empty
	// otherwise, check for bound
	content := if length == 0 {
		[]u8{}
	} else {
		if content_pos >= bytes.len || content_pos + length > bytes.len {
			return error('IA5String: truncated payload bytes')
		}
		unsafe { bytes[content_pos..content_pos + length] }
	}

	result := IA5String.from_bytes(content)!
	next := content_pos + length

	return result, next
}

// from_bytes creates a new IA5String from bytes b
fn IA5String.from_bytes(b []u8) !IA5String {
	if b.any(it < u8(` `) || it > u8(`~`)) {
		return error('IA5String: bytes contains non-ascii chars')
	}
	return IA5String{
		value: b.bytestr()
	}
}

// Utility function
fn valid_ia5string(s string) bool {
	return s.is_ascii()
}
