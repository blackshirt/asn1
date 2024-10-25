// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// Handling functionality of Element's serialization.
//

// `encode` serializes element into bytes array. By default, its encode in .der rule with empty options.
// See  `encode_with_options` if you want pass an option string. See `field.v` for more option in detail.
//
// Examples:
//
// ```v
// obj := asn1.Utf8String.new('hi')!
// out := asn1.encode(obj)!
// assert out == [u8(0x0C), 0x02, 0x68, 0x69]
// ```
pub fn encode(el Element) ![]u8 {
	return encode_with_options(el, '')!
}

// `encode_with_options` serializes element into bytes array with options string passed to drive the result.
//
// Examples:
//
// `Utf8String` defined as `[5] IMPLICIT UTF8String` was encoded into `85 02 68 69`.
//
// `Utf8String` defined as `[5] EXPLICIT UTF8String` was encoded into `A5 04 0C 02 68 69`.
//
// ```v
// obj := asn1.Utf8String.new('hi')!
// implicit_out := asn1.encode_with_options(obj, 'context_specific:5;implicit;inner:12')!
// assert implicit_out == [u8(0x85), 0x02, 0x68, 0x69]
//
// explicit_out := asn1.encode_with_options(obj, 'context_specific:5;explicit;inner:0x0c')!
// assert explicit_out == [u8(0xA5), 0x04, 0x0C, 0x02, 0x68, 0x69]
// ```
pub fn encode_with_options(el Element, opt string) ![]u8 {
	return el.encode_with_options(opt)!
}

// `encode_with_field_options` serializes this element into bytes array with options defined in fo.
pub fn encode_with_field_options(el Element, fo FieldOptions) ![]u8 {
	return el.encode_with_field_options(fo)
}

fn (el Element) encode_with_options(opt string) ![]u8 {
	// treated as without option when nil
	if opt.len == 0 {
		out := encode_with_rule(el, .der)!
		return out
	}
	fo := FieldOptions.from_string(opt)!
	out := el.encode_with_field_options(fo)!
	return out
}

// encode_with_field_options serializes element into bytes arrays with supplied FieldOptions.
fn (el Element) encode_with_field_options(fo FieldOptions) ![]u8 {
	if el is Optional {
		return el.encode()
	}
	el.validate_options(fo)!
	if fo.has_default {
		def_element := fo.default_value or { return error('bad default_value') }
		// If this element is equal with default_value, by default its should not be serialized.
		if el.equal(def_element) {
			return []u8{}
		}
	}
	new_element := el.apply_field_options(fo)!
	out := encode_with_rule(new_element, .der)!
	return out
}

// encode_with_rule encodes element into bytes array with rule.
fn encode_with_rule(el Element, rule EncodingRule) ![]u8 {
	if rule != .der && rule != .ber {
		return error('Element: unsupported rule')
	}
	mut dst := []u8{}

	// when this element is Optional without presence flag, by default would
	// serialize this element into empty bytes otherwise, would serialize underlying element.
	if el is Optional {
		return el.encode()!
	}
	// otherwise, just serializes as normal
	el.tag().encode_with_rule(mut dst, rule)!
	// calculates the length of element,  and serialize this length
	payload := el.payload()!
	length := Length.new(payload.len)!
	length.encode_with_rule(mut dst, rule)!
	// append the element payload to destination
	dst << payload

	return dst
}

// Helper for wrapping element
//

// apply_wrappers_options turns this element into another element by wrapping it
// with the some options defined in FieldOptions.
fn (el Element) apply_wrappers_options(fo FieldOptions) !Element {
	// no wraps, and discard other wrapper options
	if fo.cls == '' {
		return el
	}
	// element being wrapped should have universal class
	if el.tag().class != .universal {
		return error('non-universal going to wrapped')
	}
	el.validate_wrapper(fo)!
	if fo.has_default {
		el.validate_default(fo)!
	}

	new_el := el.wrap_with_options(fo)!

	return new_el
}

// Helper for turns the element into Optional.
//
// apply_optional_options turns this element into another element with OPTIONAL semantic.
fn (el Element) apply_optional_options(fo FieldOptions) !Element {
	// not an optional element, just return the current element.
	if !fo.optional {
		return el
	}
	el.validate_optional(fo)!
	opt := if fo.optional { el.into_optional(fo.default_value)! } else { el }

	return opt
}

// into_optional turns this element into Optional with default_value if there.
fn (el Element) into_optional(with_default ?Element) !Element {
	if el is Optional {
		return error('already optional element')
	}
	opt := Optional.new(el, with_default)!
	return opt
}

// apply_field_options applies rules in field options into current element
// and turns this into another element.
// by default, optional attribute is more higher precedence over wrapper attribut, ie,
// take the wrap step and then turn into optional (if true)
fn (el Element) apply_field_options(fo FieldOptions) !Element {
	wrapped := el.apply_wrappers_options(fo)!
	// optional options take precedence over wrapper
	// wehen fo.optional is false, new_el is current wrapped element
	new_el := wrapped.apply_optional_options(fo)!
	return new_el
}

fn (el Element) set_default_value(mut fo FieldOptions, value Element) ! {
	// the default tag should match with the current tag
	if el.tag() != value.tag() {
		return error('unmatching tag of default value')
	}
	fo.install_default(value, false)!
	el.validate_default(fo)!
}

// wrap_with_rule wraps universal element into another class.
// we prohibit dan defines some rules when its happen and  returns an error instead
// 1. wrapping into .universal class is not allowed
// 2. wrapping with the same class is not allowed too
// 3. wrapping non-universal class element is not allowed (maybe removed on futures.)
// Notes :
// Three additional information about tagging:
//		CHOICEs are always explicitly tagged even if implicit tagging is in effect.
//		EXPLICIT TAGs are always constructed, they encapsulate the TLV they prefix.
//		An IMPLICIT TAG 'inherits' the constructed bit of the TLV whose 'T' is overwritten,
//		examples:
//		a) '[5] IMPLICIT INTEGER' has tag 0x85 (overwriting 0x02 = INTEGER)
//		b) '[5] IMPLICIT SEQUENCE' has tag 0xA5 (overwriting 0x30 = SEQUENCE, CONSTRUCTED)
fn (el Element) wrap_with_options(fo FieldOptions) !Element {
	el.validate_options(fo)!
	// we dont allow optional element to be wrapped
	if el is Optional {
		return error('optional is not allowed to be wrapped')
	}
	// wraps into .universal is not allowed
	if fo.cls == 'universal' {
		return error('no need to wrap into universal class')
	}

	el_cls := el.tag().tag_class()
	// error when in the same class
	if el_cls == TagClass.from_string(fo.cls)! {
		return error('no need to wrap into same class')
	}
	// we dont allow other than .universal class to be wrapped
	if el_cls != .universal {
		return error('No need to wrap non-universal class')
	}
	mode := TaggedMode.from_string(fo.mode)!
	payload := if mode == .explicit { encode_with_rule(el, .der)! } else { el.payload()! }
	cls := TagClass.from_string(fo.cls)!

	// when in implicit mode, wrapper's tag depends on form of element being wrapped.
	// otherwise, when in explicit mode, should be in constructed form.
	inner_form := el.tag().is_constructed()
	constructed := if mode == .implicit { inner_form } else { true }

	match cls {
		.context_specific {
			// maybe constructed or primitive.
			return ContextElement.new(fo.tagnum, mode, el)!
		}
		.application {
			return ApplicationElement.new(constructed, fo.tagnum, payload)!
		}
		.private {
			return PrivateELement.new(constructed, fo.tagnum, payload)!
		}
		else {
			return error('class wrapper not allowed')
		}
	}
}

// wrao performs wrap to element and turns this element into another one.
fn wrap(el Element, cls TagClass, nunber int, mode TaggedMode) !Element {
	if el is Optional {
		return error('Optional cant be wrapped')
	}
	if cls == .universal {
		return error('you cant wrap into universal')
	}
	// get inner form
	inner_form := el.tag().is_constructed()
	constructed := if mode == .implicit { inner_form } else { true }

	// gets payload of the new element
	content := if mode == .implicit { el.payload()! } else { encode_with_rule(el, .der)! }

    // new tag 
	ntag := Tag.new(cls, constructed, tagnun)!
	match cls {
		.context_specific {
			return ContextElement.new(tagnum, mode, el)!
		}
		.application {
			return ApplicationElement.new(constructed, tagnum, content)!
		}
		.private {
			return PrivateELement.new(constructed, tagnum, content)!
		}
		else {
			return error('Wraps to the wrong class')
		}
	}
}