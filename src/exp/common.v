// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

fn parse_raw_expected(expected Tag, bytes []u8, start i64, rule EncodingRule) !(Asn1Element, []u8) {
	if bytes.len < 1 {
		return error('bytes underflow to read tag')
	}
	tag, length_pos := Tag.decode_with_expected(expected, bytes, start, rule)!
	if length_pos >= bytes.len {
		return error('Bad length_pos for length decode step')
	}
	length, content_pos := Length.decode_with_rule(bytes, length_pos, rule)!
	mut payload := []u8{}
	if length == 0 {
		elem := Asn1Element{
			cls:         tag.tag_class()
			constructed: tag.is_constructed()
			content:     payload
		}
		return elem, unsafe { bytes[content_pos + length..] }
	}
	if content_pos > bytes.len {
		return error('need more bytes: overflow')
	}
	if content_pos + length > bytes.len {
		return error('need more bytes')
	}
	payload = unsafe { bytes[content_pos..content_pos + length] }
	return Asn1Element{
		cls:         tag.tag_class()
		constructed: tag.is_constructed()
		content:     payload
	}, unsafe { bytes[content_pos + length..] }
}

fn parse_raw(bytes []u8, start i64) !(Tag, Length, []u8, []u8) {
	return error('not implemented')
}

fn parse_single_with_rule(src []u8, start i64, rule EncodingRule) ! {
	return error('not implemented')
}

fn parse_universal_type(src []u8, start i64, rule EncodingRule) !Element {
	tag, length_pos := Tag.decode_with_rule(src, start, rule)!
	if tag.tag_class() != .universal {
		return error('parse error: not an universal class, but %{tag.tag_class()}')
	}
	length, content_pos := Length.decode_with_rule(src, length_pos, rule)!

	payload := if length == 0 { []u8{} } else { unsafe { src[content_pos..content_pos + length] } }
	num := tag.tag_number()
	match num {
		int(TagType.null) {
			return Null.from_bytes_with_rule(payload, rule)!
		}
		int(TagType.boolean) {
			return Boolean.from_bytes_with_rule(payload, rule)!
		}
		else {
			return error('Not currently implemented')
		}
	}
}
