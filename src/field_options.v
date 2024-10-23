module asn1

// This file is for supporting configure through string options.
// so, you can tag your struct field with supported attributes defined here.

// Limit of string option length
const max_string_option_length = 255
const max_attributes_length = 5

// Configuration format for field tagging.
//
// Currently, this configurations option support following string config, ie,
// a. `class:number`, for wrapping the element with other non-universal class, for examole: `private:100`.
// b: `explicit` or `implicit` mode.
// c. `inner:5` the tag number of element being wrapped, should in UNIVERSAL class.
// b. `optional` tagging for element with OPTIONAL behaviour.
// c. `has_default` tagging for element with DEFAULT behaviour.

// Field options attributes handling.
//
// FieldOptions is a structure to accomodate and allowing configures your complex structures
// through string or arrays of string stored in FieldOptions fields.
// For example, you can tagging your fields of some element with tagging
// like `@[context_specific:10; explicit; inner:5; optional]`.
// Its will be parsed and can be used to drive encoding or decoding of Element.
@[heap; noinit]
pub struct FieldOptions {
mut:
	// The fields `cls`, `tagnum`, `mode` and `inner` was used
	// for wrapping (and unwrapping) purposes. turn some element
	// into another element configured with this options.
	// This fields currently strictly applied to UNIVERSAL element.
	// In the encoding (decoding) phase, it would be checked
	// if this options meet required criteria.
	// Limitation applied on the wrapper fields:
	// 1. Wrap into UNIVERSAL is not allowed (cls != universal)
	// 2. Wrapped element should have UNIVERSAL class.
	// 3. You should provide mode for wrapping, explicit or implicit.
	// 4. If cls == '', no wrapping is performed, discarding all wrapper options
	cls    string // should cls != 'universal'
	tagnum int = -1 // Provides with wrapper tag number.
	mode   string // explicit or implicit, depends on definition schema.
	inner  int = -1 // should valid universal tag number.

	// optional field applied to element with OPTIONAL behaviour, with or without DEFAULT value.
	// Set `optional` to true when this element has OPTIONAL keyword in the definition of element.
	// Usually element with OPTIONAL keyword is not presents in the encoding (decoding) data.
	optional bool

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
	// check whether this string is a valid one.
	if !is_asn1_options_marker(trimmed) {
		return error('You have not provides correct options marker')
	}
	attrs := trimmed.split(';')
	opt := FieldOptions.from_attrs(attrs)!
	// checks
	opt.check_wrapper()!

	return opt
}

// filtered_attrs filters and takes only supported asn1 marker from arrays of string.
fn filtered_attrs(attrs []string) []string {
	mut filtered := []string{}
	for attr in attrs {
		item := attr.trim_space()
		if is_asn1_options_marker(item) {
			filtered << item
		}
	}
	return filtered
}

// `from_attrs` parses and validates []string into FieldOptions.
pub fn FieldOptions.from_attrs(attrs []string) !FieldOptions {
	mut fo := FieldOptions{}
	if attrs.len == 0 {
		return fo
	}

	mut tag_ctr := 0 // tag marker counter
	mut opt_ctr := 0 // optional marker counter
	mut def_ctr := 0 // has_default marker counter
	mut mod_ctr := 0 // mode marker counter
	mut inn_ctr := 0 // inner counter

	// take only valid supported asn1 marker
	filtered := filtered_attrs(attrs)
	if filtered.len > max_attributes_length {
		return error('max allowed filtered.len')
	}

	for attr in filtered {
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
		if is_mode_marker(item) {
			value := parse_mode_marker(item)!
			mod_ctr += 1
			if mod_ctr > 1 {
				return error('multiples mode key defined')
			}
			if !valid_mode_value(value) {
				return error('Bad mode values')
			}
			fo.mode = value
		}
		if is_inner_tag_marker(item) {
			_, value := parse_inner_tag_marker(item)!
			inn_ctr += 1
			if inn_ctr > 1 {
				return error('multiples inner tag format defined')
			}
			if !valid_inner_value(value) {
				return error('Bad inner value')
			}
			num := value.int()
			fo.inner = num
		}
		if is_optional_marker(item) {
			opt := parse_optional_marker(item)!
			opt_ctr += 1
			if opt_ctr > 1 {
				return error('multiples optional tag')
			}
			present := if valid_optional_key(opt) { true } else { false }
			fo.optional = present
		}
		if is_default_marker(item) {
			default_marker := parse_default_marker(item)!
			def_ctr += 1
			if def_ctr > 1 {
				return error('multiples has_default flag')
			}
			has_default := if valid_default_marker(default_marker) { true } else { false }
			fo.has_default = has_default
		}
	}

	// check
	fo.check_wrapper()!

	return fo
}

// wrapper_tag makes a wrapper Tag from FieldOptions for current element.
// The form of wrapper tag depends on tagged mode being supplied,
// if implicit, its follows the inner tag being wrapped (primitive or constructed one)
// If explicit, the wrapper tag would in non-primitive form.
fn (fo FieldOptions) wrapper_tag() !Tag {
	if fo.cls == '' {
		return error('You cant build wrapper tag from empty string')
	}
	fo.check_wrapper()!
	cls := TagClass.from_string(fo.cls)!
	if !valid_mode_value(fo.mode) {
		return error('Invalid mode')
	}
	inner_tag := fo.inner_tag()!
	form := inner_tag.constructed
	if fo.mode == 'implicit' {
		// implicit tagging allows to be applied on non-constructed element, inherited from inner.
		return Tag.new(cls, form, fo.tagnum)!
	}
	return Tag.new(cls, true, fo.tagnum)!
}

// inner_tag gets inner Tag from FieldOptions.
fn (fo FieldOptions) inner_tag() !Tag {
	if fo.inner < 0 || fo.inner > max_universal_tagnumber {
		return error('You cant create tag from empty inner string')
	}
	utag := universal_tag_from_int(fo.inner)!

	return utag
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

// check_wrapper validates wrapper's part of fields options.
fn (fo FieldOptions) check_wrapper() ! {
	// Validates wrapper part
	// Its discard all check when fo.cls is empty string, its marked as non-wrapped element.
	if fo.cls != '' {
		if !valid_tagclass_name(fo.cls) {
			return error('Get unexpected fo.cls value')
		}
		// provides the tag number
		if fo.tagnum < 0 {
			return error('Get unexpected fo.tagnum}')
		}
		// wraps into UNIVERSAL type is not allowed
		if fo.cls == 'universal' {
			return error('wraps into universal class is not allowed')
		}
		if !valid_mode_value(fo.mode) {
			return error('Invalid zonk or uncorerct mode value')
		}
		// when wrapped, you should provide inner tag number value.
		if fo.inner < 0 {
			return error('You provides incorrect inner number')
		}
		if fo.inner > max_universal_tagnumber {
			return error('Inner number exceed universal limit')
		}
	}
}

// WRAPPING (UNWRAPPING) OPTIONS.
//
// parse 'application=number' format
// format: `class=number` without constructed keyword.
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
		|| attr.starts_with('context_specific')
}

fn valid_tagclass_name(tag string) bool {
	return tag == 'application' || tag == 'private' || tag == 'context_specific'
}

// it should be represented in int or hex number
fn valid_string_tag_number(s string) bool {
	return s.is_int() || s.is_hex()
}

// EXPLICIT OR IMPLICIT OPTIONS.
//
// parse 'explicit [or implicit]' format.
fn parse_mode_marker(s string) !string {
	item := s.trim_space()
	if is_mode_marker(item) {
		if !valid_mode_value(item) {
			return error('bad mode value')
		}

		return item
	}
	return error('not mode marker')
}

fn is_mode_marker(attr string) bool {
	return attr.starts_with('explicit') || attr.starts_with('implicit')
}

fn valid_mode_value(s string) bool {
	return s == 'explicit' || s == 'implicit'
}

// INNER TAG OPTIONS.
//
// parse inner value to be used by decoder, only support 'universal' class currently.
// format : `inner=number`
fn parse_inner_tag_marker(attr string) !(string, string) {
	src := attr.trim_space()
	if is_inner_tag_marker(src) {
		item := src.split(':')
		if item.len != 2 {
			return error('bad inner tag marker length')
		}
		// 'inner:number' part
		key := item[0].trim_space()
		if !valid_inner_tag_key(key) {
			return error('bad inner key')
		}
		value := item[1].trim_space()
		if !valid_inner_value(value) {
			return error('Get unexpected inner value')
		}
		return key, value
	}
	return error('not inner tag marker')
}

fn is_inner_tag_marker(s string) bool {
	return s.starts_with('inner')
}

fn valid_inner_tag_key(s string) bool {
	return s == 'inner'
}

fn valid_inner_value(s string) bool {
	// 'inner: number' part
	value := s.trim_space()
	return valid_string_tag_number(value)
}

// OPTIONAL.
//
// parse 'optional' marker
fn parse_optional_marker(attr string) !string {
	key := attr.trim_space()
	if is_optional_marker(key) {
		if !valid_optional_key(key) {
			return error('bad optional key')
		}
		return key
	}
	return error('not optional marker')
}

fn is_optional_marker(attr string) bool {
	return attr.starts_with('optional')
}

fn valid_optional_key(attr string) bool {
	return attr == 'optional'
}

// DEFAULT OPTIONS.
//
// parse 'has_default' marker
fn parse_default_marker(attr string) !string {
	item := attr.trim_space()
	if is_default_marker(item) {
		if !valid_default_marker(item) {
			return error('bad has_default marker')
		}
		return item
	}
	return error('not has_default marker')
}

fn is_default_marker(attr string) bool {
	return attr.starts_with('has_default')
}

fn valid_default_marker(attr string) bool {
	return attr == 'has_default'
}

// UTILTIY
//
// is_asn1_options_marker checks if provided string is valid supported field options string.
fn is_asn1_options_marker(s string) bool {
	item := s.trim_space()
	// belowng to one of five supported marker.
	valid := is_tag_marker(item) || is_mode_marker(item) || is_inner_tag_marker(item)
		|| is_optional_marker(item) || is_default_marker(item)

	return valid
}
