module asn1

// This file is for supporting configure through string options.
// so, you can tag your struct field with attributes, for example @[context_specific:10; optional; has_default. tagged: explicit]
// Field options attributes handling

// limit of string option length
const max_string_option_length = 255
const max_attributes_length = 4

@[heap; noinit]
struct FieldOptions {
mut:
	// wrapper class
	cls string
	// set to true when this should be optional element
	optional bool
	// set to true when optional should present, if unsure, set to false
	present bool
	// set to true when element has default value
	has_default bool
	// tag number for wrapper element tagnum when cls != ''
	tagnum int = -1
	// default value for element when has_default value is true
	default_value &Element = unsafe { nil }
	// make sense in explicit context, when cls != '' and cls == .context_specific
	mode string
}

// validate validates FieldOptions to meet criteria
fn (fo &FieldOptions) validate() ! {
	// if fo.cls != '' the tagnum should provide correct value
	if valid_tagclass_name(fo.cls) {
		// tagnum should be set up correctly
		if fo.tagnum <= 0 {
			return error('fo.cls is being set but fo.tagnum not specified')
		}
		// for .context_specific class, provides with mode explicit or implicit
		if fo.cls == 'context_specific' {
			if !valid_mode_value(fo.mode) {
				return error('for .context_specific class, provides with explicit or implicit mode')
			}
		}
	}
	if fo.has_default && fo.default_value == unsafe { nil } {
		return error('fo.has_default without default_value')
	}
}

fn (mut fo FieldOptions) install_default(el Element, force bool) ! {
	if fo.has_default {
		if fo.default_value == unsafe { nil } {
			fo.default_value = &el
			return
		}
		// not nil
		if !force {
			return error('set force to overide')
		}
		// replace the old one, or should we check its matching tag ?
		fo.default_value = &el
	}
	return error('you can not install default value when has_default being not set')
}

// parse_string_option parses string as an attribute of field options
// Its allows string similar to `application:4; optional; has_default` to be treated as an field options
fn parse_string_option(s string) !&FieldOptions {
	if s.len == 0 {
		return &FieldOptions{}
	}
	if s.len > max_string_option_length {
		return error('string option exceed limit')
	}

	trimmed := s.trim_space()
	attrs := trimmed.split(';')

	opt := parse_attrs_to_field_options(attrs)!

	return opt
}

// parses and validates []string into FieldOptions
fn parse_attrs_to_field_options(attrs []string) !&FieldOptions {
	mut fo := &FieldOptions{}
	if attrs.len == 0 {
		return fo
	}
	if attrs.len > max_attributes_length {
		return error('max allowed attrs.len')
	}

	mut tag_ctr := 0 // tag marker counter
	mut opt_ctr := 0 // optional marker counter
	mut def_ctr := 0 // has_default marker counter
	mut mod_ctr := 0 // mode marker counter

	for attr in attrs {
		if !is_tag_marker(attr) && !is_optional_marker(attr) && !is_default_marker(attr)
			&& !is_mode_marker(attr) {
			return error('unsuppported keyword')
		}
		if is_tag_marker(attr) {
			cls, num := parse_tag_marker(attr)!
			tag_ctr += 1
			if tag_ctr > 1 {
				return error('multiples tag format defined')
			}
			tnum := num.int()
			if tnum < 0 {
				return error('bad tag number')
			}
			fo.cls = cls
			fo.tagnum = tnum
		}
		if is_optional_marker(attr) {
			_, present := parse_optional_marker(attr)!
			opt_ctr += 1
			if opt_ctr > 1 {
				return error('multiples optional tag')
			}
			fo.optional = true
			fo.present = present
		}
		if is_default_marker(attr) {
			_ := parse_default_marker(attr)!
			def_ctr += 1
			if def_ctr > 1 {
				return error('multiples has_default flag')
			}
			fo.has_default = true
		}
		if is_mode_marker(attr) {
			_, value := parse_mode_marker(attr)!
			mod_ctr += 1
			if mod_ctr > 1 {
				return error('multiples mode key defined')
			}
			fo.mode = value
		}
	}

	return fo
}

// parse 'application:number' format
fn parse_tag_marker(attr string) !(string, string) {
	src := attr.trim_space()
	if is_tag_marker(src) {
		field := src.split(':')
		if field.len != 2 {
			return error('bad tag marker length')
		}
		first := field[0].trim_space()
		if !valid_tagclass_name(first) {
			return error('bad tag name')
		}
		second := field[1].trim_space()
		if !valid_tagclass_number(second) {
			return error('bad tag number')
		}
		return first, second
	}
	return error('not a tag marker')
}

fn is_tag_marker(attr string) bool {
	return attr.starts_with('application') || attr.starts_with('private')
		|| attr.starts_with('context_specific') || attr.starts_with('universal')
}

fn valid_tagclass_name(tag string) bool {
	return tag == 'application' || tag == 'private' || tag == 'context_specific'
		|| tag == 'universal'
}

// it should be represented in int or hex number
fn valid_tagclass_number(s string) bool {
	return s.is_int() || s.is_hex()
}

// parse 'mode:explicit [or implicit]' format
//
fn parse_mode_marker(s string) !(string, string) {
	src := s.trim_space()
	if is_mode_marker(src) {
		item := src.split(':')
		if item.len != 2 {
			return error('bad mode marker')
		}
		key := item[0].trim_space()
		value := item[1].trim_space()
		if !valid_mode_key(key) {
			return error('bad mode key')
		}
		if !valid_mode_value(value) {
			return error('bad mode value')
		}

		return key, value
	}
	return error('not mode marker')
}

fn valid_mode_key(s string) bool {
	return s == 'mode'
}

fn valid_mode_value(s string) bool {
	return s == 'explicit' || s == 'implicit'
}

fn is_mode_marker(attr string) bool {
	return attr.starts_with('mode')
}

// parse 'has_default' marker
fn parse_default_marker(attr string) !string {
	src := attr.trim_space()
	if is_default_marker(src) {
		if valid_default_marker(src) {
			return src
		}
		return error('bad has_default marker')
	}
	return error('not has_default marker')
}

fn is_default_marker(attr string) bool {
	return attr.starts_with('has_default')
}

fn valid_default_marker(attr string) bool {
	return attr == 'has_default'
}

// parse 'optional' or 'optional:true [false]' marker
fn parse_optional_marker(attr string) !(string, bool) {
	src := attr.trim_space()
	if is_optional_marker(src) {
		item := src.split(':')
		// only allow 'optional' or 'optional:true'
		if item.len != 1 && item.len != 2 {
			return error('bad optional marker length')
		}
		mut present := false
		if item.len == 2 {
			value := item[1].trim_space()
			if !valid_optional_present_value(value) {
				return error('bad optional value')
			}
			if value == 'true' {
				present = true
			}
		}
		key := item[0].trim_space()
		if !valid_optional_key(key) {
			return error('bad optional key')
		}

		return key, present
	}
	return error('not optional marker')
}

fn is_optional_marker(attr string) bool {
	return attr.starts_with('optional')
}

fn valid_optional_key(attr string) bool {
	return attr == 'optional'
}

fn valid_optional_present_value(attr string) bool {
	return attr == 'true' || attr == 'false'
}

// is_element check whethers T is fullfills Element
fn is_element[T]() bool {
	s := $if T is Element { true } $else { false }
	return s
}

fn has_tag_method[T]() bool {
	$for method in T.methods {
		$if method.name == 'tag' {
			$if method.return_type is Tag {
				return true
			}
		}
	}
	return false
}

fn encode(el Element) ![]u8 {
	return encode_with_options(el, '')!
}

fn encode_with_options(el Element, opt string) ![]u8 {
	fo := parse_string_option(opt)!
	mut out := []u8{}
	el.encode_with_options(mut out, fo)!
	return out
}

fn (el Element) raw_encode(mut dst []u8) ! {
	out := el.encode()!
	dst << out
}

fn wrap(el Element, cls TagClass, num int, mode TaggedMode) ![]u8 {
	if cls == .universal {
		return error('no need to wrap into universal class')
	}
	// error when in the same class
	if el.tag().tag_class() == cls {
		return error('no need to wrap into same class')
	}
	newtag := Tag.new(cls, true, num)!
	mut dst := []u8{}
	match mode {
		.explicit {
			// explicit add the new tag to serialized element
			newtag.encode(mut dst)!
			el.raw_encode(mut dst)!
		}
		.implicit {
			// implicit replaces the el tag with the new one
			newtag.encode(mut dst)!
			dst << el.payload()!
		}
	}
	return dst
}

fn (el Element) encode_as_optional(mut out []u8, present bool) ! {
	if !present {
		return
	}
	el.raw_encode(mut out)!
}

fn (el Element) encode_with_options(mut out []u8, opt &FieldOptions) ! {
	// treated as without option when nil
	if opt == unsafe { nil } {
		el.raw_encode(mut out)!
		return
	}
	opt.validate()!
	// when optional is true, treated differently when present or not
	// in some rules, optional element should not be included in encoding
	if opt.optional {
		if !opt.present {
			// not present, do nothing
			out << []u8{}
			return
		}
		// check for other flag
		if opt.cls != '' {
			if opt.tagnum <= 0 {
				return error('provides with the correct tagnum')
			}
			class := el.tag().tag_class().str().to_lower()
			if class != opt.cls {
				mut dst := []u8{}
				cls := TagClass.from_string(opt.cls)!
				match opt.mode {
					'explicit' {
						wrapped := wrap(el, cls, opt.tagnum, .explicit)!
						dst << wrapped
					}
					'implicit' {
						wrapped := wrap(el, cls, opt.tagnum, .implicit)!
						dst << wrapped
					}
					else {}
				} // endof match
			}
			// endof opt.cls != cls
		}
	} else {
		// not an optional
		if opt.cls != '' {
			if opt.tagnum <= 0 {
				return error('provides with correct tagnum')
			}
			cls := TagClass.from_string(opt.cls)!
			if opt.mode != '' {
				mode := TaggedMode.from_string(opt.mode)!
				wrapped := wrap(el, cls, opt.tagnum, mode)!
				out << wrapped
			} else {
				// otherwise treat with .explicit
				wrapped := wrap(el, cls, opt.tagnum, .explicit)!
				out << wrapped
			}
		}
	}
}

struct Asn1Element {
mut:
	tag     Tag
	payload []u8
	opt     &FieldOptions = unsafe { nil }
}

fn (ae Asn1Element) tag() Tag {
	return ae.tag
}

fn (ae Asn1Element) payload() ![]u8 {
	return ae.payload
}

fn (ae Asn1Element) encode(mut dst []u8) ! {
	// no options, regular encode with default ctx
	ctx := Context{}
	if ae.opt == unsafe { nil } {
		ae.tag().encode_with_context(mut dst, ctx)!
		payload := ae.payload()!
		length := Length.from_i64(payload.len)!
		length.encode_with_context(mut dst, ctx)!
		// append the element payload to destionation
		dst << payload
		return
	}
	return error('not implemented')
}

/*


fn (el Element) encode_with_options(opt &FieldOptions) ![]u8 {
	opt.validate()!
	out := []u8{}
	if opt.optional {
		if opt.present {
			// make optional object from element
			obj := make_optional_from_element(el)!
			// is this need wrapped ?
			if opt.wrapper != unsafe { nil } {
				if el.tag().tag_class() == opt.wrapper {
					// no need to wrap
					return
				}
				// different tag class..wraps it
				wrapped_obj := wrap_element(obj, opt.tagclass, opt.tagnum, true)!
				wrapped_obj.encode(mut out)!
				return out
			}
			//
			obj.encode(mut out)!
			return out
		}
	}
	// not an optional element
	el.encode(mut out)!

	return out
}

fn make_optional_from_element(el Element) ()
*/
