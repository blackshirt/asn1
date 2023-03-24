// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// der_decode is main routine to do parsing of DER encoded data.
// Its accepts bytes arrays encoded in DER in `src` params and returns `Encoder` interfaces object,
// so, you should cast it to get underlying type.
// By default, in context specific class, its try to read as tagged object, whether its explicit or implicit.
// TODO: more robust parsing function to handle specific use cases.
pub fn der_decode(src []u8) !Encoder {
	tag, pos := read_tag(src, 0)!
	length, next := decode_length(src, pos)!
	if src.len > next + length {
		return error('malformed bytes, contains discarded bytes')
	}
	// remaining is a contents
	// contents := src[next..next + length]
	contents := read_bytes(src, next, length)!
	match tag.class {
		.universal {
			if tag.constructed {
				return parse_compound_element(tag, contents)!
			}

			return parse_primitive_element(tag, contents)!
		}
		.application {
			return new_asn_object(.application, tag.constructed, tag.number, contents)
		}
		.context {
			if tag.constructed {
				return read_explicit_context(tag, contents)!
			}
			return read_implicit_context(tag, contents)!
		}
		.private {
			return new_asn_object(.private, tag.constructed, tag.number, contents)
		}
	}
}

fn parse_primitive_element(tag Tag, contents []u8) !Encoder {
	if tag.is_constructed() {
		return error('not primitive tag ')
	}

	match tag.number {
		int(TagType.boolean) {
			return read_boolean(contents)
		}
		int(TagType.integer) {
			return new_integer_from_bytes(contents)
		}
		int(TagType.bitstring) {
			return new_bitstring_from_bytes(contents)
		}
		int(TagType.octetstring) {
			return new_octetstring(contents.bytestr())
		}
		int(TagType.null) {
			return new_null()
		}
		int(TagType.oid) {
			return new_oid_from_bytes(contents)!
		}
		int(TagType.numericstring) {
			return new_numeric_string(contents.bytestr())
		}
		int(TagType.printablestring) {
			return new_printable_string(contents.bytestr())
		}
		int(TagType.ia5string) {
			return new_ia5string(contents.bytestr())
		}
		int(TagType.utf8string) {
			return new_utf8string(contents.bytestr())
		}
		int(TagType.visiblestring) {
			return new_visiblestring(contents.bytestr())
		}
		int(TagType.utctime) {
			return new_utctime(contents.bytestr())
		}
		// TODO: add other type
		else {
			return error('unsupported tag type')
		}
	}
}

fn parse_compound_element(tag Tag, contents []u8) !Encoder {
	if !tag.is_constructed() {
		return error('not constructed tag')
	}

	match true {
		tag.is_sequence_tag() {
			return parse_seq(tag, contents)!
		}
		tag.is_set_tag() {
			return parse_set(tag, contents)!
		}
		tag.is_context() {
			return read_explicit_context(tag, contents)!
		}
		else {
			return new_asn_object(tag.class, tag.constructed, tag.number, contents)
		}
	}
}
