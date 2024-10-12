// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ENUMERATED.
// Enumerated type treated as ordinary integer, only differs on tag value.
// The encoding of an enumerated value shall be that of the integer value with which it is associated.
// NOTE: It is primitive.
@[heap; noinit]
pub struct Enumerated {
pub:
	value int
}

fn (e Enumerated) str() string {
	return 'Enumerated: ({e.value})'
}

pub fn Enumerated.new(val int) Enumerated {
	return Enumerated{
		value: val
	}
}

pub fn (e Enumerated) tag() Tag {
	return Tag{.universal, false, int(TagType.enumerated)}
}

pub fn (e Enumerated) payload() ![]u8 {
	return e.payload_with_rule(.der)!
}

fn Enumerated.from_bytes(bytes []u8) !Enumerated {
	if !valid_bytes(bytes, true) {
		return error('Enumerated: failed check')
	}
	mut ret := i64(0)
	for i := 0; i < bytes.len; i++ {
		ret <<= 8
		ret |= i64(bytes[i])
	}

	ret <<= 64 - u8(bytes.len) * 8
	ret >>= 64 - u8(bytes.len) * 8

	if ret != i64(int(ret)) {
		return error('integer too large')
	}
	return Enumerated{
		value: int(ret)
	}
}

pub fn Enumerated.parse(mut p Parser) !Enumerated {
	tag := p.read_tag()!
	if !tag.expect(.universal, false, int(TagType.enumerated)) {
		return error('Bad Enumerated tag')
	}
	length := p.read_length()!
	bytes := p.read_bytes(length)!

	res := Enumerated.from_bytes(bytes)!

	return res
}

pub fn Enumerated.decode(src []u8) !(Enumerated, i64) {
	return Enumerated.decode_with_rule(src, .der)!
}

fn Enumerated.decode_with_rule(bytes []u8, rule EncodingRule) !(Enumerated, i64) {
	tag, length_pos := Tag.decode_with_rule(bytes, 0, rule)!
	if !tag.expect(.universal, false, int(TagType.enumerated)) {
		return error('Unexpected non-Enumerated tag')
	}
	length, content_pos := Length.decode_with_rule(bytes, length_pos, rule)!
	content := if length == 0 {
		[]u8{}
	} else {
		if content_pos >= bytes.len || content_pos + length > bytes.len {
			return error('Enumerated: truncated payload bytes')
		}
		unsafe { bytes[content_pos..content_pos + length] }
	}

	val := Enumerated.from_bytes(content)!
	next := content_pos + length

	return val, next
}

fn (e Enumerated) payload_with_rule(rule EncodingRule) ![]u8 {
	if rule != .der || rule != .ber {
		return error('Enumerated.pack: unsupported rule')
	}
	mut n := e.enumerated_len()
	mut dst := []u8{len: n}

	for j := 0; j < n; j++ {
		dst[j] = u8(e.value >> u32(n - 1 - j) * 8)
	}
	return dst
}

fn (e Enumerated) enumerated_len() int {
	mut i := e.value
	mut n := 1

	for i > 127 {
		n++
		i >>= 8
	}

	for i < -128 {
		n++
		i >>= 8
	}

	return n
}

// Utility function

// valid_bytes validates bytes meets some requirement for BER/DER encoding.
fn valid_bytes(src []u8, signed bool) bool {
	// Requirement for der encoding
	// The contents octets shall consist of one or more octets.
	if src.len == 0 {
		return false
	}

	// check for minimaly encoded
	// If the contents octets of an integer value encoding consist of more
	// than one octet, then the bits of the first octet and bit 8 of
	// the second octets shall not all be ones; and shall not all be zero.
	if src.len > 1 && ((src[0] == 0 && src[1] & 0x80 == 0)
		|| (src[0] == 0xff && src[1] & 0x80 == 0x80)) {
		return false
	}

	// reject negative for unsigned type
	if !signed && src[0] & 0x80 == 0x80 {
		return false
	}
	return true
}
