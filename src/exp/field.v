module asn1

// This file is for supporting configure through string options.
// so, you can tag your struct field with attributes, for example @[context_specific:10; optional; has_default. tagged: explicit]
// Field options attributes handling

// limit of string option length
const max_string_option_length = 255
const max_attributes_length = 5

@[heap; noinit]
struct FieldOptions {
mut:
	// wrapper class
	cls    string
	tagnum int = -1 // tag number for wrapper element when cls != ''
	mode   string // mode in 'explicit' or 'implicit' when cls !+ ''
	inner  int = -1 // set to some value when mode = 'impllcit'
	// set to true when this should be optional element
	optional bool
	// set to true when optional should present, if unsure, just set to false
	present bool
	// set to true when element has default value
	has_default bool
	// default value for element when has_default value is true
	default_value ?Element
}

// validate validates FieldOptions to meet criteria
fn (fo &FieldOptions) validate() ! {
	fo.validate_wrapper_part()!
	if fo.has_default && fo.default_value == none {
		return error('fo.has_default without default_value')
	}
	// mode present without class wrapper present is error
	if fo.cls == '' && fo.mode != '' {
		return error('mode key presents without cls being setted')
	}
}

fn (fo &FieldOptions) validate_wrapper_part() ! {
	if fo.cls != '' {
		if !valid_tagclass_name(fo.cls) {
			return error('you provides invalid cls')
		}
		// provides the tag number
		if fo.tagnum <= 0 {
			return error('provides with the correct tagnum')
		}
		// yous should provide the mode
		if fo.mode == '' {
			return error('mode not set')
		}
		if !valid_mode_value(fo.mode) {
			return error('bad mode value provided')
		}
		// check when implicit
		if fo.mode == 'implicit' {
			if fo.inner <= 0 {
				return error('inner tag number was not set in implicit mode')
			}
		}
	}
}

fn (mut fo FieldOptions) install_default(el Element, force bool) ! {
	if fo.has_default {
		if fo.default_value == none {
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
	mut inn_ctr := 0 // inner counter

	for attr in attrs {
		if !is_tag_marker(attr) && !is_optional_marker(attr) && !is_default_marker(attr)
			&& !is_mode_marker(attr) && !is_inner_tag_marker(attr) {
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
		if is_inner_tag_marker(attr) {
			_, value := parse_inner_tag_marker(attr)!
			if inn_ctr > 1 {
				return error('multiples inner tag format defined')
			}
			inn_tnum := value.int()
			if inn_tnum < 0 {
				return error('bad inner tag number')
			}

			fo.inner = inn_tnum
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
		if !valid_string_tag_number(second) {
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
fn valid_string_tag_number(s string) bool {
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

// parse inner tag when in implicit mode, inner: 100
fn parse_inner_tag_marker(attr string) !(string, string) {
	src := attr.trim_space()
	if is_inner_tag_marker(src) {
		item := src.split(':')
		if item.len != 2 {
			return error('bad inner tag marker length')
		}
		first := item[0].trim_space()
		if !valid_inner_tag_key(first) {
			return error('bad inner key')
		}
		second := item[0].trim_space()
		if !valid_string_tag_number(second) {
			return error('bad inner tag number')
		}
		return first, second
	}
	return error('not inner tag marker')
}

fn is_inner_tag_marker(s string) bool {
	return s.starts_with('inner')
}

fn valid_inner_tag_key(s string) bool {
	return s == 'inner'
}

fn valid_inner_tag_class(s string) bool {
	return s == 'universal'
}

fn valii_inner_tag_form(s string) bool {
	return s == 'false' || s == 'true'
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
