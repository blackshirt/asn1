// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

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
		int(TagType.oid) {
			return Oid.from_bytes(content)!
		}
		int(TagType.integer) {
			return Integer.from_bytes(content)!
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
			return Sequence.from_bytes(content)!
		}
		int(TagType.set) {
			return Set.from_bytes(content)!
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

// parse_context_specific_with_mode parses tag and content as ContextElement when mode is availables
fn parse_context_specific_with_mode(tag Tag, content []u8, mode TaggedMode) !ContextElement {
	mut ctx := parse_context_specific(tag, content)!
	ctx.set_ctx_mode(mode)!

	return ctx
}

// parse_context_specific parses tag and content as ContextElement.
// The info of fields of ContextElement, ie, inner_tag and mode, is not availables here
// You should provides this later with the correct value.
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
		// inner_tag: ?
		// mode: ?
	}
	return ctx
}
