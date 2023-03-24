// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ASN.1 NULL TYPE
struct Null {}

pub fn new_null() Encoder {
	return Null{}
}

pub fn (n Null) tag() Tag {
	return new_tag(.universal, false, int(TagType.null))
}

pub fn (n Null) length() int {
	return 0
}

pub fn (n Null) size() int {
	return 2
}

pub fn (n Null) encode() ![]u8 {
	return encode_null()
}

fn (n Null) str() string {
	return 'NULL'
}

fn encode_null() []u8 {
	mut dst := []u8{cap: 2}
	tag := new_tag(.universal, false, int(TagType.null))
	serialize_tag(mut dst, tag)
	serialize_length(mut dst, 0x00)
	return dst
}

fn decode_null(data []u8) ! {
	if data.len != 2 || (data[0] != 0x05 && data[1] != 0x00) {
		return error('null: invalid args')
	}
}
