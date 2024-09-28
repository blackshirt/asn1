module asn1

// This file is for supporting configure through string options.
// so, you can tag your struct field with attributes, for example @[context_specific:10; optional; has_default. tagged: explicit]
// Field options attributes handling

// limit of string option length
const max_string_option_length = 255

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
	tagged &TaggedMode = unsafe { nil }
}

fn (mut fo FieldOptions) install_default(el Element, force bool) ! {
	if fo.has_default {
		if fo.default_value == unsafe { nil } {
			fo.default_value = el
			return
		}
		// not nil
		if !force {
			return error('set force to overide')
		}
		// replace the old one, or should we check its matching tag ?
		fo.default_value = el
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
		// for .context_specific class, provides with tagged mode, explicit or implicit
		if fo.wrapper == .context_specific {
			if fo.tagged == unsafe { nil } {
				return error('for .context_specific class, provides with tagged mode, explicit or implicit')
			}
		}
	}
	if fo.has_default && fo.default_value == unsafe { nil } {
		return error('fo.has_default without default_value')
	}
}

// creates empty field options
fn empty_field_options() &FieldOptions {
	return &FieldOptions{}
}

// field_options_from_string parses and creates FieldOptions from string s
fn field_options_from_string(s string) !&FieldOptions {
	attrs := parse_string_option(s)!
	out := parse_attrs_to_field_options(attrs)!
	fo.validate()!
	return fo
}

// parse_string_option parses string as an attribute of field options
// Its allows string similar to `application:4; optional; has_default` to be treated as an field options
fn parse_string_option(s string) ![]string {
	if s.len == 0 {
		return []string{}
	}
	if s.len > max_string_option_length {
		return error('string option exceed limit')
	}

	mut res := []string{}
	trimmed := s.trim_space()
	out := trimmed.split(';')
	validate_attrs(out)!
	for item in out {
		res << item
	}
	return out
}

fn parse_attrs_to_field_options(attrs []string) !&FieldOptions {
	validate_attrs(attrs)!

	mut fo := &FieldOptions{}
	if find_optional_marker(attrs) {
		fo.optional = true
	}
	if attrs_has_default_flag(attrs) {
		fo.has_default = true
	}

	// check for tag class
	tc, wrapkey := find_tag_marker(attrs)!
	if tc {
		wrapper := wrapkey.trim_space()
		if !valid_tagclass_format(wrapped) {
			return error('not valid tag wrapper ')
		}
		res := wrapper.split(':')
		// should be in 'application:number' format
		if res.len != 2 {
			return error('not valid tag class length')
		}
		// first is the tag class wrapper
		first := res[0]
		if !valid_tagclass_name(first) {
			return error('not valid tag class name')
		}
		// the second parts is should be a tag number
		// ie, valid int (or hex) number
		second := res[1]
		if !valid_tagclass_number(second) {
			return error('not a valid tag number')
		}
		match first {
			'application' { fo.tagclass = .application }
			'context_specific' { fo.tagclass = .context_specific }
			'private' { fo.tagclass = .private }
			'universal' { fo.tagclass = .universal }
			else {}
		}
		tnum := second.int()
		fo.tagnum = tnum
	}

	return fo
}

fn validate_attrs(attrs []string) ! {
	if attrs.len == 0 {
		// do nothing
		return
	}
	// tagclass is present
	tcls_present, wrapkey := find_tag_marker(attrs)!
	if tcls_present {
		wrapped := wrapkey.trim_space()
		if !valid_tagclass_format(wrapped) {
			return error('not valid tag wrapper ')
		}
	}
}

// when this present, treat the field as an optional element
fn find_optional_marker(attrs []string) !(bool, string) {
	if attrs.len == 0 {
		return false, ''
	}
	for field in attrs {
		if field.starts_with('optional') {
			item := field.trim_space()
			if item != 'optional' {
				return error('bad optional marker')
			}
			return true, field 
		}
	}
	return false, ''
}

// has_default
fn find_has_default_marker(attrs []string) !(bool, string) {
	if attrs.len == 0 {
		return false, ''
	}
	for field in attrs {
		if field.starts_with('has_default') {
			item := field.trim_space()
			if item != 'has_default' {
				return error('bad has_default marker')
			}
			return true, field 
		}
	}
	return false, ''
}

// 
fn find_tagged_marker(attrs []string) !(bool, string) {
	if attrs.len == 0 {
		return false, ''
	}
	for field in attrs {
		if field.starts_with('tagged') {
			item := field.trim_space()
			src := item.split(':')
			if src.len != 2 {
				return error('bad tagged mode format')
			}
			first := src[0]
			if first != 'tagged' {
				return error('malformed tagged key')
			}
			second := src[1]
			if second != 'explicit' && second != 'implicit' {
				return error('malformed tagged key')
			}
			return true, field
		}
	}
	return false, ''
}

// support for context_specific tagged mode: 'tagged: explicit [or implicit]'
fn validate_tagged_mode(s string) ! {
	tagged := s.trim_space()
	if !tagged.starts_with('tagged') {
		return error('not start with tagged key')
	}
	mode := tagged.split(':')
	if mode.len != 2 {
		return error('tagged not fully defined')
	}
	// tagged: explicit [or implicit]
	if mode[0] != 'tagged' {
		return error('wrong key for tagged, get: ${mode[0].str()}')
	}
	if mode[1] != 'explicit' && mode[1] != 'implicit' {
		return error('wrong tagged mode ${mode[1].str()}')
	}
}

// Tag "application: number" option format handling
//
// find_tag_marker find and validates "application: number" format when we found it
fn find_tag_marker(attrs []string) !(bool, string) {
	if attrs.len == 0 {
		return false, ''
	}
	for item in attrs {
		if item.starts_with('application') || item.starts_with('private')
			|| item.starts_with('context_specific') || item.starts_with('universal') {
			field := item.trim_space()
			src := field.split(':')
			if src.len != 2 {
				return error('bad tag format')
			}
			first := src[0]
			if !valid_tagclass_name(first) {
				return error('bad tag name')
			}
			second := src[1]
			if !valid_tagclass_name(second) {
				return error('bad tag number')
			}
			// we found it
			return true, item
		}
	}
	return false, ''
}

fn valid_tagclass_name(tag string) bool {
	return tag == 'application' || tag == 'private' || tag == 'context_specific'
		|| tag == 'universal'
}

fn valid_tagclass_number(s string) bool {
	return s.is_int() || s.is_hex()
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
			if opt.tagclass != unsafe { nil } {
				if el.tag().tag_class() == opt.tagclass {
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
