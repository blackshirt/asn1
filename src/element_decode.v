// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// Handling of deserialization of bytes array into some Element.
//

// decode decodes single element from bytes, its not allowing trailing data
pub fn decode(src []u8) !Element {
	return decode_with_options(src, '')
}

// decode_with_options decodes single element from bytes with options support, its not allowing trailing data.
// Its accepts options string to drive decoding process.
pub fn decode_with_options(bytes []u8, opt string) !Element {
	if opt.len == 0 {
		el, pos := Element.decode(bytes)!
		if pos > bytes.len {
			return error('decode on data with trailing data')
		}
		return el
	}
	fo := FieldOptions.from_string(opt)!
	return decode_with_field_options(bytes, fo)!
}

pub fn decode_with_field_options(bytes []u8, fo FieldOptions) !Element {
	// TODO
	if bytes.len == 0 {
		return error('Empty bytes')
	}
	fo.check_wrapper()!
	if fo.cls != '' {
		cls := TagClass.from_string(fo.cls)!
		mode := TaggedMode.from_string(fo.mode)!
		inner_tag := universal_tag_from_int(fo.inner)!

		inner_form := inner_tag.constructed
		constructed := if mode == .implicit { inner_form } else { true }
		outer_tag := Tag.new(cls, constructed, fo.tagnum)!
		if fo.optional {
			opt := decode_optional(bytes, outer_tag)!
			return opt
		}
		// unwrap
		mut p := Parser.new(bytes)
		curr_tag := p.peek_tag()!
		wrp_tag := fo.wrapper_tag()!

		if curr_tag.class != wrp_tag.class {
			return error('Get different class')
		}
		if curr_tag.number != wrp_tag.number {
			return error('Get different tag number')
		}
		el := p.read_tlv()!
		p.finish()!

		return el
	}
	return error('decode_with_field_options failed')
}

fn decode_optional(bytes []u8, expected_tag Tag) !Element {
	mut p := Parser.new(bytes)
	ct := p.peek_tag()!
	// when the tag is equal expected_tag, this mean, present this optional element
	if ct.equal(expected_tag) {
		// present
		el := p.read_tlv()!
		mut opt := Optional.new(el, none)!
		// set this optional presence to true
		opt.set_to_present()
		return opt
	}
	// optional element with no-presence semantic
	el := RawElement.new(expected_tag, []u8{})!
	opt := Optional.new(el, none)!
	return opt
}

fn (el Element) unwrap_with_options(fo FieldOptions) !Element {
	el.validate_options(fo)!

	// if unwrapping, el.tag() should == fo.inner produced by wrap operation
	return error('Not implemented')
}

// unwrap performs unwrapping operations to the element with options provided.
// Its technically reverse operation of the `.wrap()` applied to the element
// with the same options. If you provide with diferent options,
// the result is in undesired behaviour, even its success 
fn unwrap(el Element, fo FieldOptions) !Element {
	fo.validate_options()!
	// first, checks class of the element being to unwrap
	if el.tag().class == .universal {
		return error('you cant unwrap universal element')
	}
	// element being unwrap should have matching with tag within options.
	mode := TaggedMode.from_string(fo.mode)!
	inner_form := false
	constructed := if mode == .explicit {true} else {inner_form}
	tg := Tag.new(fo.cls, constructed, fo.tagnum)!

	//check for class
	cls := TagClass.from_string(go.cls)!
	if el.tag().class != cls {
		return error('unmatching tag class'}
	}
		
	// check tag equality 
	if !el.tag().equal(tg) {
		return error('Element tag unequal with tag from options')
	}
	
}
