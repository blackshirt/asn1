// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// OCTETSTRING
// The ASN.1 OCTET STRING type contains arbitrary strings of octets.
// This type is very similar to BIT STRING, except that all values must be an integral number of eight bits.
// You can use constraints to specify a maximum length for an OCTET STRING type.
pub struct OctetString {
	value string
	tag   Tag = Tag{.universal, false, int(TagType.octetstring)}
}

// new_octetstring creates new octet string
pub fn OctetString.from_string(s string) !OctetString {
	if !valid_octet_string(s) {
		return error('not valid octet string')
	}
	return OctetString{
		value: s
	}
}

pub fn OctetString.from_bytes(src []u8) !OctetString {
	return OctetString.from_string(src.bytestr())!
}

fn valid_octet_string(s string) bool {
	// just return true
	return true
}

pub fn (os OctetString) tag() Tag {
	return os.tag
}

pub fn (os OctetString) value() string {
	return os.value
}

pub fn (os OctetString) payload(p Params) ![]u8 {
	return os.value.bytes()
}

pub fn (os OctetString) length(p Params) int {
	return os.value.bytes().len
}

pub fn (os OctetString) packed_length(p Params) int {
	mut n := 0

	n += os.tag().packed_length(p)
	len := Length.from_i64(os.value.bytes().len) or { panic(err) }
	n += len.packed_length(p)
	n += os.value.bytes().len

	return n
}

// The encoding of an octetstring value shall be either primitive or constructed
pub fn (os OctetString) encode(mut dst []u8, p Params) ! {
	if p.mode != .der && p.mode != .ber {
		return error('Integer: unsupported mode')
	}
	// packing in DER mode
	os.tag().encode(mut dst, p)!
	length := Length.from_i64(os.value.bytes().len)!
	length.encode(mut dst, p)!
	dst << os.value.bytes()
}

pub fn OctetString.decode(src []u8, loc i64, p Params) !(OctetString, i64) {
	raw, next := RawElement.decode(src, loc, p)!
	if raw.tag.class() != .universal || raw.tag.is_constructed()
		|| raw.tag.tag_number() != int(TagType.octetstring) {
		return error('OctetString: bad tag of universal class type')
	}
	// no bytes
	if raw.length(p) == 0 {
		return OctetString{}, next
	}

	os := OctetString.from_bytes(raw.payload)!
	return os, next
}
