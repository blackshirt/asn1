// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

fn parse_universal_type(src []u8, start i64) !Element {
	tag, length_pos := Tag.decode_with_rule(src, start, .der)!
	if tag.tag_class() != .universal {
		return error('parse error: not an universal class, but %{tag.tag_class()}')
	}
	length, content_pos := Length.decode_with_rule(src, length_pos, .der)!

	payload := if length == 0 { []u8{} } else { unsafe { src[content_pos..content_pos + length] } }
	num := tag.tag_number()
	match num {
		int(TagType.null) {
			return Null.from_bytes_with_rule(payload, .der)!
		}
		int(TagType.boolean) {
			return Boolean.from_bytes_with_rule(payload, .der)!
		}
		else {
			return error('Not currently implemented')
		}
	}
}

fn parse_universal_primitive(tag Tag, content []u8) !Element {
	if tag.tag_class() != .universal {
		return error('parse on non-universal type')
	}
	if tag.is_constructed() {
		return error('parse on constructed type')
	}
	match tag.tag_number() {
		int(TagType.boolean) {
			return Boolean.from_bytes(content)!
		}
		int(TagType.null) {
			return Null.from_bytes(content)!
		}
		int(TagType.integer) {
			// return Integer.from_bytes(content)!
			return error('Not implemted')
		}
		int(TagType.enumerated) {
			return Enumerated.from_bytes(content)!
		}
		int(TagType.bitstring) {
			return BitString.from_bytes(content)!
		}
		int(TagType.ia5string) {
			return IA5String.from_bytes(content)!
		}
		int(TagType.utf8string) {
			return Utf8String.from_bytes(content)!
		}
		int(TagType.numericstring) {
			return NumericString.from_bytes(content)!
		}
		int(TagType.printablestring) {
			return PrintableString.from_bytes(content)!
		}
		int(TagType.generalstring) {
			return GeneralString.from_bytes(content)!
		}
		int(TagType.octetstring) {
			return OctetString.from_bytes(content)!
		}
		int(TagType.visiblestring) {
			return VisibleString.from_bytes(content)!
		}
		int(TagType.utctime) {
			return UtcTime.from_bytes(content)!
		}
		int(TagType.generalizedtime) {
			return GeneralizedTime.from_bytes(content)!
		}
		else {
			// return the raw element
			return Asn1Element{
				tag:     tag
				content: content
			}
		}
	}
}

fn parse_universal_constructed(tag Tag, content []u8) !Element {
	if tag.tag_class() != .universal {
		return error('parse on non-universal class')
	}
	if !tag.is_constructed() {
		return error('parse on non-constructed type')
	}
	match tag.tag_number() {
		int(TagType.sequence) {
			// todo: handle SequenceOf
			// return error('not implemented')
			return Sequence.from_bytes(content)!
		}
		int(TagType.set) {
			// return Set.from_bytes(content)!
			return error('not implemented')
		}
		else {
			return Asn1Element{
				tag:     tag
				content: content
			}
		}
	}
}

fn parse_private(tag Tag, content []u8) !PrivateELement {
	if tag.tag_class() != .private {
		return error('parse on non-application class')
	}
	return PrivateELement{
		tag:     tag
		content: content
	}
}

fn parse_application(tag Tag, content []u8) !ApplicationElement {
	if tag.tag_class() != .application {
		return error('parse on non-application class')
	}
	return ApplicationElement{
		tag:     tag
		content: content
	}
}

fn parse_context_specific(tag Tag, content []u8) !ContextElement {
	if tag.tag_class() != .context_specific {
		return error('parse on non-context-specific class')
	}
	if !tag.is_constructed() {
		return error('ContextSpecific tag shoud be constructed')
	}
	// mode and inner_tag is not set here without additional information,
	// So its still none here, and you should set it with correct value
	ctx := ContextElement{
		outer_tag: tag
		content:   content
	}
	return ctx
}
