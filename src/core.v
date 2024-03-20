// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// Class is ASN.1 tag class.
// Currently most of universal class supported in this module, with limited support for other class.
pub enum Class {
	universal        = 0x00 // 0b00
	application      = 0x01 // 0b01
	context_specific = 0x02 // 0b10
	private          = 0x03 // 0b11
}

// class_from_int creates Class from integer v
pub fn Class.from_int(v int) !Class {
	match v {
		// vfmt off
		0x00 { return .universal }
		0x01 { return .application }
		0x02 { return .context_specific }
		0x03 { return .private }
		else {
			return error('Bad class number')
		}
		// vfmt on
	}
}

fn (c Class) str() string {
	match c {
		.universal { return 'universal' }
		.application { return 'application' }
		.context_specific { return 'context_specific' }
		.private { return 'private' }
	}
}

// vfmt off
// bit masking values for ASN.1 tag header
const class_mask 		= 0xc0 // 192, bits 8-7
const constructed_mask 	= 0x20 //  32, bits 6
const tag_numher_mask 	= 0x1f //  32, bits 1-5
// vfmt on

// Params is optional params passed to pack or unpacking
// of tag, length or ASN.1 element to drive how encoding works.
@[params]
pub struct Params {
pub mut:
	mode EncodingMode = .der
}

// encoding mode
pub enum EncodingMode {
	// Distinguished Encoding Rules (DER)
	der = 0
	// Basic Encoding Rules (BER)
	ber = 1
	// Octet Encoding Rules (OER)
	oer = 2
	// Packed Encoding Rules (PER)
	per = 3
	// XML Encoding Rules (XER)
	xer = 4
}
