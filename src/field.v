module asn1

// This file is for supporting configure through string options.
// so, you can tag your struct field with attributes, for example @[context_specific:10; optional; has_default. tagged: explicit]
// Field options attributes handling

// limit of string option length
const max_string_option_length = 255
const max_attributes_length = 4

@[noinit]
struct FieldOptions {
mut:
	// wrapper class
	wrapper &TagClass = unsafe { nil }
	// set to true when should be optional element
	optional bool
	// set to true when optional element has default value
	has_default bool
	// tag number for wrapper element tagnum != nil when wrapper != nil
	tagnum &int = unsafe { nil }
	// default value for optional element when has_default value is true
	default_value &Element = unsafe { nil }
	// make sense in explicit context, when wrapper != nil and wrapper == .context_specific
	mode &TaggedMode = unsafe { nil }
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

// validate validates FieldOptions to meet criteria
fn (fo &FieldOptions) validate() ! {
	// if wrapper != nil, the tagnum should be provided ( != nil )
	if fo.wrapper != unsafe { nil } {
		// tagnum should be set
		if fo.tagnum == unsafe { nil } {
			return error('non nill fo.wrapper, but fo.tagnume not specified')
		}
		// for .context_specific class, provides with mode mode, explicit or implicit
		if fo.wrapper == .context_specific {
			if fo.mode == unsafe { nil } {
				return error('for .context_specific class, provides with mode mode, explicit or implicit')
			}
		}
	}
	if fo.has_default && fo.default_value == unsafe { nil } {
		return error('fo.has_default without default_value')
	}
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

	fo := parse_attrs_to_field_options(attrs)!

	return fo
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

	mut tag_cnt := 0
	mut opt_cnt := 0
	mut def_cnt := 0
	mut mod_cnt := 0

	for attr in attrs {
		if !is_tag_marker(attr) && !is_optional_marker(attr) && !is_default_marker(attr)
			&& !is_mode_marker(attr) {
			return error('unsuppported keyword')
		}
		if is_tag_marker(attr) {
			cls, num := parse_tag_marker(attr)!
			tag_cnt += 1
			if tag_cnt > 1 {
				return error('multiple tag format defined')
			}
			wrapper := TagClass.from_string(cls)!
			tnum := num.int()
			fo.wrapper = &wrapper
			fo.tagnum = &tnum
		}
		if is_optional_marker(attr) {
			_ := parse_optional_marker(attr)!
			opt_cnt += 1
			if opt_cnt > 1 {
				return error('multiples optional tag')
			}
			fo.optional = true
		}
		if is_default_marker(attr) {
			_ := parse_default_marker(attr)!
			def_cnt += 1
			if def_cnt > 1 {
				return error('multiples has_default flag')
			}
			fo.has_default = true
		}
		if is_mode_marker(attr) {
			_, value := parse_mode_marker(attr)!
			mod_cnt += 1
			if mod_cnt > 1 {
				return error('multiples mode key defined')
			}
			tmode := TaggedMode.from_string(value)!
			fo.mode = &tmode
		}
	}

	return fo
}

// parse 'application:number' format
fn parse_tag_marker(attr string) !(string, string) {
	if is_tag_marker(attr) {
		src := attr.trim_space()
		field := src.split(':')
		if field.len != 2 {
			return error('bad tag marker length')
		}
		first := field[0]
		if !valid_tagclass_name(first) {
			return error('bad tag name')
		}
		second := field[1]
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
	if is_mode_marker(s) {
		src := s.trim_space()
		item := src.split(':')
		if item.len != 2 {
			return error('bad mode marker')
		}
		key := item[0]
		value := item[1]
		if !valid_mode_key(item[0]) {
			return error('bad mode key')
		}
		if !valid_mode_value(item[1]) {
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
	if is_default_marker(attr) {
		s := attr.trim_space()
		if valid_default_marker(s) {
			return s
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

// parse 'optional' marker
fn parse_optional_marker(attr string) !string {
	if is_optional_marker(attr) {
		s := attr.trim_space()
		if valid_optional_marker(s) {
			return s
		}
		return error('bad optional marker')
	}
	return error('not optional marker')
}

fn is_optional_marker(attr string) bool {
	return attr.starts_with('optional')
}

fn valid_optional_marker(attr string) bool {
	return attr == 'optional'
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

fn wraps(el Element, cls TagClass, num int) !Element {
   newtag := Tag.new(cls, true, num)!
   
}

/*
fn make_payload[T]() ![]u8 {
}

fn encode_element(el Element) ![]u8 {
	return encode_element_with_options(el, '')!
}

fn encode_element_with_options(el Element, opts string) ![]u8 {
	opt := field_options_from_string(opts)!
	mut out := []u8{}
	el.encode_with_options(mut out, opt)!
	return out
}

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
