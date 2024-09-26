module asn1

// This file is for supporting configure through string options.
// so, you can tag your struct field with attributes, for example @[application:10; optional; has_default]
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
	explicit bool
}

// validate validates FieldOptions to meet criteria
fn (fo &FieldOptions) validate() ! {
	// if wrapper != nil, the tagnum should be provided ( != nil )
	if fo.wrapper != unsafe { nil } && fo.tagnum == unsafe { nil } {
		return error('non nill fo.wrapper, but fo.tagnume not specified')
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
	if s.len > max_string_option_length {
		return error('string option exceed limit')
	}
	if s.len == 0 {
		return []string{}
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

	mut opts := &FieldOptions{}

	if attrs_has_optional_flag(attrs) {
		opts.optional = true
	}
	if attrs_has_default_flag(attrs) {
		opts.has_default = true
	}

	return opts
}

fn validate_attrs(attrs []string) ! {
	if attrs.len == 0 {
		// do nothing
		return
	}
	// tagclass is present
	tcls_present, wrapkey := attrs_has_tagclass_wrapper(attrs)
	if tcls_present {
		wrapped := wrapkey.trim_space()
		if !valid_tagclass_format(wrapped) {
			return error('not valid tag wrapper ')
		}
	}
}

// when this present, treat the field as an optional element
fn attrs_has_optional_flag(attrs []string) bool {
	return 'optional' in attrs
}

// handles has_default attribute
fn attrs_has_default_flag(attrs []string) bool {
	return 'has_default' in attrs
}

// Tag
//
// treats as an tag class wrapper
fn attrs_has_tagclass_wrapper(attrs []string) (bool, string) {
	if attrs.len == 0 {
		return false, ''
	}
	for attr in attrs {
		// even its not in 'application:tagnum' format
		if attr.starts_with('application') || attr.starts_with('context_specific')
			|| attr.starts_with('private') || attr.starts_with('universal') {
			return true, attr
		}
	}
	return false, ''
}

fn valid_tagclass_attr_name(s string) bool {
	return src == 'application' || src == 'private' || src == 'context_specific'
		|| src == 'universal'
}

fn valid_tagclass_attr_number(s string) bool {
	return s.is_int() || s.is_hex()
}

// valid tag class 'application: 5' format
fn valid_tagclass_format(attr string) bool {
	if attr.starts_with('application') || attr.starts_with('context_specific')
		|| attr.starts_with('private') || attr.starts_with('universal') {
		res := attr.split(';')
		// should be in 'application:number' format
		if res.len != 2 {
			return false
		}
		// first is the tag class wrapper
		first := res[0]
		if !valid_tagclass_attr_name(first) {
			return false
		}
		// the second parts is should be a tag number
		// ie, valid int (or hex) number
		second := res[1]
		if !valid_tagclass_attr_number(second) {
			return false
		}
		return true
	}
	return false
}

fn tag_class_from_string(s string) !TagClass {
	match s {
		'application' { return .application }
		'universal' { return .universal }
		'private' { return .private }
		'context_specific' { return .context_specific }
		else { return error('not valid tag') }
	}
}

// get the tag class and tag number
fn tag_class_and_number(s string) !(TagClass, u32) {
	if !valid_tagclass_format(s) {
		return error('Not valid tag class format')
	}
	res := s.split(';')
	tc := res[0]
	tn := res[1]
	if !valid_tagclass_attr_name(tc) {
		return error('Not valid class name')
	}
	if !valid_tagclass_attr_number(tn) {
		return error('not valid tag num format')
	}
	tcls := tag_class_from_string(tc)!
	tnum := tagnum_from_int(tn.int())!
	return tcls, tnum
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
