// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ASN.1 NULL TYPE
struct Null {}

fn Null.new() Null {
	return Null{}
}

fn (n Null) length() int {
	return 0
}

fn (n Null) packed_length() int {
	return 2
}

fn (n Null) tag() Tag {
	return new_tag(.universal, false, 5)
}

fn (n Null) pack_to_asn1(mut to []u8, mode EncodingMode) ! {
	match mode {
		.der {
			out << n.tag().pack()!
			// the length is 0
			out << [u8(0x00)]
		}
		else {
			return error('unsupported mode')
		}
	}
}

fn Null.unpack(b []u8, mode EncodingMode) !Null {
	match mode {
		.der {
			if data.len != 2 || (data[0] != 0x05 && data[1] != 0x00) {
				return error('Null: invalid args')
			}
			tag, pos := Tag.unpack(b, 0)!
			if tag.value != 0x05 {
				return error('NullL bad tag=${tag}')
			}
			len, idx := Length.unpack(b, pos)!
			if len != 0 {
				return error('Null: len != 0')
			}
			return Null{}
		}
		else {
			return error('unsupported mode')
		}
	}
}

fn (n Null) str() string {
	return 'NULL'
}
