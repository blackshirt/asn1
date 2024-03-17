// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ASN.1 NULL TYPE
struct Null {
	tag Tag = Tag{.universal, false, int(TagType.null)}
}

fn Null.new() Null {
	return Null{}
}

fn Null.new_with_tag(t Tag) Null {
	return Null{
		tag: t
	}
}

fn (n Null) packed_length() int {
	return 2
}

fn (n Null) tag() Tag {
	return n.tag
}

fn (n Null) pack_to_asn1(mut dst []u8, p Params) ! {
	if p.mode != .der && p.mode != .ber {
		return error('Integer: unsupported mode')
	}

	n.tag().pack_to_asn1(mut dst, p)!
	// the length is 0
	dst << [u8(0x00)]
}

fn Null.unpack(b []u8, loc i64, p Params) !(Null, i64) {
	if src.len < 2 {
		return error('Null: bad ia5string bytes length')
	}
	if p.mode != .der && p.mode != .ber {
		return error('Null: unsupported mode')
	}
	if loc > src.len {
		return error('Null: bad position offset')
	}

	tag, pos := Tag.unpack_from_asn1(b, loc, p)!
	if tag.tag_number() != int(TagType.null) {
		return error('Null: bad tag=${tag}')
	}
	len, idx := Length.unpack_from_asn1(b, pos, p)!
	if len != 0 {
		return error('Null: len != 0')
	}
	return Null{
		tag: tag
	}, idx
}

fn (n Null) str() string {
	return 'NULL'
}
