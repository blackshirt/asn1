// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module core

// Class is ASN.1 tag class.
// Currently most of universal class supported in this module, with limited support for other class.
enum Class {
	universal   		= 0x00
	application 		= 0x01
	context_specific    = 0x02
	private     		= 0x03
}

fn class_from_int(v int) !Class {
	match v {
		0x00 { return .universal }
		0x01 { return .application }
		0x02 { return .context_specific }
		0x03 { return .private }
		else {
			return error("Bad class number")
		}
	}
}

fn (c Class) str() string {
	match c {
		.universal { return "universal" }
		.application { return "application" }
		.context_specific { return "context_specific" }
		.private { return "private" }
	}
}

const class_mask 	= 0xc0 // 192, bits 8-7
const compound_mask = 0x20 //  32, bits 6
const tag_mask 		= 0x1f //  32, bits 1-5

// Encoder is a main interrface that wraps ASN.1 encoding functionality.
// Most of basic types in this module implements this interface.
pub interface Encoder {
	// tag of the underlying ASN.1 object
	tag() Tag
	// length of ASN.1 object (without tag and length part)
	length() int
	// length of encoded bytes of the object (included tag and length part)
	size() int
	// Serializes object to bytes array with DER encoding
	encode() ![]u8
}
