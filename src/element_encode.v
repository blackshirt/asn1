// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// Handling functionality of Element's serialization.
//

// `encode` serializes element into bytes array. By default, its encode in .der rule with empty options.
// See  `encode_with_string_options` if you want pass an option string. See `field.v` for more option in detail.
pub fn encode(el Element) ![]u8 {
	return encode_with_string_options(el, '')!
}

// `encode_with_string_options` serializes element into bytes array with options string passed to drive the result.
pub fn encode_with_string_options(el Element, opt string) ![]u8 {
	return el.encode_with_string_options(opt)!
}

// `encode_with_field_options` serializes this element into bytes array with options defined in fo.
pub fn encode_with_field_options(el Element, fo FieldOptions) ![]u8 {
	return el.encode_with_field_options(fo)
}

fn (el Element) encode_with_string_options(opt string) ![]u8 {
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
