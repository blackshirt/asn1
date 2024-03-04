// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// ASN.1 NULL TYPE
struct Null {
	// default null = 5
	tag Tag = new_tag(.universal, false, 5)
}

fn Null.new() Null {
	return Null.new_with_tag(none)
}

fn Null.new_with_tag(t ?Tag) Null {
	if t != none {
		return Null{tag=t}
	}
	// using default tag 
	return Null{}
}

fn (n Null) length() int {
	return 0
}

fn (n Null) packed_length() int {
	return 2
}

fn (n Null) tag() Tag {
	return t.tag 
}


fn (n Null) pack_to_asn1(mut to []u8, mode Mode=.der) ! {
	match mode {
		.der {
			out << n.tag.pack()!
			// the length is 0 
			out << [u8(0x00)]
		}
		else {
			return error("unsupported mode")
		}
	}
}

fn Null.unpack(b []u8, mode Mode) !Null {
	match mode {
		.der {
			if data.len != 2 || (data[0] != 0x05 && data[1] != 0x00) {
				return error('null: invalid args')
			}
			tag, pos := Tag.unpack(b, 0)!
			len, idx := Length.unpack(b, pos)!
			if len != 0 { return error("Null: len != 0")}
			return Null{tag=tag}

		}
		else {
			return error("unsupported mode")
		}
	}
}

fn (n Null) str() string {
	return 'NULL'
}