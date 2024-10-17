module asn1

// This file is for supporting configure through string options.
// so, you can tag your struct field with attributes, for example @[context_specific:10; optional; has_default. mode: explicit]
// Field options attributes handling

// Limit of string option length
const max_string_option_length = 255
const max_attributes_length = 5

// FieldOptions is a structure to accomodate and allowing configures your complex structures
// through string or arrays of string stored in FieldOptions fields.
// For example, you can tagging your fields of some element with tagging like `@[context_specific:10; optional; mode: explicit]`.
// Its will be parsed and can be used to drive encoding or decoding of Element.
@[heap; noinit]
pub struct FieldOptions {
mut:
	// Following fields, ie, `cls`, `tagnum`, `mode` and `inner` was for wrapping (and unwrapping) purposes.
	// This fields currently applied to (strictly) UNIVERSAL element.
	// In the encoding (decoding) phase, it would be checked if this options meet the criteria.
	// So, you can wrap (unwrap) your element with this configuration.
	// examples of options string contains: `application:100; mode: explicit; inner:universal, false, 4`.
	// Its would be parsed into: cls=application, tagnum=100; mode: explicit, inner: `universal, false, 4`
	cls    string
	tagnum int = -1
	mode   string
	inner  string

	// Following fields applied to element with OPTIONAL behaviour, with or without DEFAULT value.
	// Set `optional` to true when this element has OPTIONAL keyword in the definition of element.
	// Usually element with OPTIONAL keyword is not presents in the encoding (decoding) data.
	// The `present` field tells us if this optional be marked to be present in the data (encoding or decoding).
	// This present field negates optionality of the element, efectively marked as present.
	// If not sure, just set this field to false.
	optional bool
	present  bool

	// This field applied to element with DEFAULT keyword behaviour.
	// Its applied into wrapping of element or optionality of the element.
	// If some element has DEFAULT keyword, set this field to true and gives default element into `default_value` field.
	has_default   bool
	default_value ?Element
}

// `from_string` parses string as an attribute of field options.
// Its allows string similar to `application:4; optional; has_default` to be treated as an field options.
// See FieldOptions in `field_options.v` for more detail.
pub fn FieldOptions.from_string(s string) !FieldOptions {
	if s.len == 0 {
		return FieldOptions{}
	}
	if s.len > max_string_option_length {
		return error('string option exceed limit')
	}

	trimmed := s.trim_space()
	attrs := trimmed.split(';')

	opt := FieldOptions.from_attrs(attrs)!

	return opt
}

// `from_attrs` parses and validates []string into FieldOptions.
pub fn FieldOptions.from_attrs(attrs []string) !FieldOptions {
	mut fo := FieldOptions{}
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
		item := attr.trim_space()
		if !is_tag_marker(item) && !is_optional_marker(item) && !is_default_marker(item)
			&& !is_mode_marker(item) && !is_inner_tag_marker(item) {
			return error('unsupported keyword')
		}
		if is_tag_marker(item) {
			cls, num := parse_tag_marker(item)!
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
		if is_optional_marker(item) {
			_, status := parse_optional_marker(item)!
			opt_ctr += 1
			if opt_ctr > 1 {
				return error('multiples optional tag')
			}
			present := if status == 'true' { true } else { false }
			fo.optional = true
			fo.present = present
		}
		if is_default_marker(item) {
			_ := parse_default_marker(item)!
			def_ctr += 1
			if def_ctr > 1 {
				return error('multiples has_default flag')
			}
			fo.has_default = true
		}
		if is_mode_marker(item) {
			_, value := parse_mode_marker(item)!
			mod_ctr += 1
			if mod_ctr > 1 {
				return error('multiples mode key defined')
			}
			fo.mode = value
		}
		if is_inner_tag_marker(item) {
			_, value := parse_inner_tag_marker(item)!
			if inn_ctr > 1 {
				return error('multiples inner tag format defined')
			}
			if !is_valid_inner_value(value) {
				return error('Bad inner string value')
			}
			fo.inner = value
		}
	}

	return fo
}

// wrapper_tag gets wrapper Tag from FieldOptions
pub fn (fo FieldOptions) wrapper_tag() !Tag {
	if fo.cls == '' {
		return error('You cant build wrapper tag from empty string')
	}
	fo.validate_wrapper_part()!
	cls := TagClass.from_string(fo.cls)!
	return Tag.new(cls, true, fo.tagnum)!
}

// inner_tag gets inner Tag from FieldOptions.
pub fn (fo FieldOptions) inner_tag() !Tag {
	if fo.inner == '' {
		return error('You cant create tag from empty inner string')
	}
	if !is_valid_inner_value(fo.inner) {
		return error('FieldOptions contains invalid inner value')
	}

	cls, frm, num := parse_inner_value(fo.inner)!

	class := TagClass.from_string(cls)!
	form := if frm == 'true' { true } else { false }
	number := num.int()

	tag := Tag.new(class, form, number)!

	return tag
}

// validate validates FieldOptions to meet criteria.
fn (fo FieldOptions) validate() ! {
	fo.validate_wrapper_part()!
	fo.validate_default_part()!
	// mode present without class wrapper present is error
	if fo.cls == '' && fo.mode != '' {
		return error('mode key presents without cls being setted')
	}
}

fn (fo FieldOptions) validate_wrapper_part() ! {
	if fo.cls != '' {
		if !valid_tagclass_name(fo.cls) {
			return error('you provides invalid cls')
		}
		// provides the tag number
		if fo.tagnum <= 0 {
			return error('provides with the correct tagnum')
		}

		// when wrapped, you should provide inner tag value.
		if fo.inner == '' {
			return error('inner value is not set in wrapped mode')
		}
	}
}

fn (fo FieldOptions) validate_default_part() ! {
	if fo.has_default {
		if fo.default_value == none {
			return error('has_default withoud default value')
		}
	}
}

// install_default tries to install and sets element el as a default value when has_default flag of FieldOptions
// has been set into true, or error if has_default is false.
// When default_value has been set with some value before this, its would return error until you force it
// by setingt force flag into true.
pub fn (mut fo FieldOptions) install_default(el Element, force bool) ! {
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

// Wrapping (unwrapping) helper.
//
// parse 'application:number' format
// format: `class:number` without constructed keyword.
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

// parse 'mode:explicit [or implicit]' format.
// format: `mode: explicit` or `mode: implicit`
fn parse_mode_marker(s string) !(string, string) {
	src := s.trim_space()
	if is_mode_marker(src) {
		item := src.split(':')
		if item.len != 1 && item.len != 2 {
			return error('bad mode marker')
		}
		key := item[0].trim_space()
		if !valid_mode_key(key) {
			return error('bad mode key')
		}
		if item.len == 1 {
			// without mode, just set to explicit
			return key, 'explicit'
		}
		value := item[1].trim_space()
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

// parse inner value to be used by decoder, only support 'universal' class currently.
// format : `inner:class,true[or false],number`
// Its returns inner, class, true (or false), number.
fn parse_inner_tag_marker(attr string) !(string, string) {
	src := attr.trim_space()
	if is_inner_tag_marker(src) {
		item := src.split(':')
		if item.len != 2 {
			return error('bad inner tag marker length')
		}
		// 'inner' part
		key := item[0].trim_space()
		if !valid_inner_tag_key(key) {
			return error('bad inner key')
		}
		value := item[1].trim_space()
		if !is_valid_inner_value(value) {
			return error('Get unexpected inner value')
		}
		return key, value
	}
	return error('not inner tag marker')
}

fn parse_inner_value(s string) !(string, string, string) {
	// 'class,form,number' part
	value := s.trim_space()
	// splits by comma
	fields := value.split(',')
	if fields.len != 3 {
		return error('Bad inner value length')
	}
	cls := fields[0].trim_space()
	if !valid_inner_tag_class(cls) {
		return error('Bad inner class')
	}
	form := fields[1].trim_space()
	if !valid_inner_tag_form(form) {
		return error('Bad inner form')
	}
	number := fields[2].trim_space()
	if !valid_string_tag_number(number) {
		return error('Bad inner number')
	}

	return cls, form, number
}

fn is_valid_inner_value(s string) bool {
	// 'class,form,number' part
	value := s.trim_space()
	// splits by comma
	fields := value.split(',')
	if fields.len != 3 {
		return false
	}
	cls := fields[0].trim_space()
	if !valid_inner_tag_class(cls) {
		return false
	}
	form := fields[1].trim_space()
	if !valid_inner_tag_form(form) {
		return false
	}
	number := fields[2].trim_space()
	if !valid_string_tag_number(number) {
		return false
	}
	return true
}

fn is_inner_tag_marker(s string) bool {
	return s.starts_with('inner')
}

fn valid_inner_tag_key(s string) bool {
	return s == 'inner'
}

fn valid_inner_tag_class(s string) bool {
	return s == 'universal' // || s == 'application' || s == 'private'
}

fn valid_inner_tag_form(s string) bool {
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
fn parse_optional_marker(attr string) !(string, string) {
	src := attr.trim_space()
	if is_optional_marker(src) {
		item := src.split(':')
		// only allow 'optional' [same as: `optional:false] or 'optional:true'
		if item.len != 1 && item.len != 2 {
			return error('bad optional marker length')
		}
		key := item[0].trim_space()
		if !valid_optional_key(key) {
			return error('bad optional key')
		}

		mut present := 'false'
		if item.len == 2 {
			value := item[1].trim_space()
			if !valid_optional_present_value(value) {
				return error('bad optional value')
			}
			if value == 'true' {
				present = 'true'
			}
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
