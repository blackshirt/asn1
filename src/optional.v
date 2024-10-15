module asn1

// OPTIONAL
//
// note: At the abstract ASN.1 level the absence of a DEFAULT value in an encoding is the same as its being present.
// Contrast this with OPTIONAL, where a value being present in the encoding is semantically distinct from its being absent.
// In some encoding rules (like BER/PER) it is at the whim of the sender whether a DEFAULT value is encoded or not
// (except for primitive type values in PER which are required by the PER standard to be absent in the encoding),
// while with others (like DER) the DEFAULT value is NEVER encoded. For all encoding rules,
// if the component that has a DEFAULT value is not encoded the receiving application must behave as though the DEFAULT value had been encoded.
@[heap; noinit]
pub struct Optional {
	// underlying element marked as an optional
	tag     Tag
	content []u8
mut:
	// presence of this flag negates optionality of this elemeent.
	// set to true when its should present, if notu sure, just set to to false
	present bool
	// set to none when have no default
	default_value ?Element
}

fn (opt Optional) validate() ! {
	/*
	if opt.has_default && opt.default_value == none {
		return error('Optional with has_default but default_value is none')
	}
	if opt.has_default && opt.default_value != none {
		val := opt.default_value or { return error('none') }
		if opt.elem.tag() != val.tag() {
			return error('default value with different tag is not allowed')
		}
	}
	*/
}

// Optional.new creates and marked element as an Optional from some element.
pub fn Optional.new(el Element) !Optional {
	return Optional{
		tag:     el.tag()
		content: el.payload()!
	}
}

pub fn (mut opt Optional) set_default(el Element) ! {
	if !opt.tag.equal(el.tag()) {
		return error('default value with different tag is not allowed')
	}
	opt.default_value = el
}

pub fn (mut opt Optional) with_default(el Element) !&Optional {
	opt.set_default(el)!
	return opt
}

pub fn (mut opt Optional) with_present(present bool) Optional {
	opt.present = present
	return opt
}

pub fn (opt Optional) tag() Tag {
	return opt.tag()
}

pub fn (opt Optional) payload() ![]u8 {
	// opt.validate()!
	return opt.content
}

pub fn (opt Optional) encode() ![]u8 {
	return opt.encode_with_rule(.der)!
}

fn (opt Optional) encode_with_rule(rule EncodingRule) ![]u8 {
	if opt.present {
		elem := RawElement{
			tag:     opt.tag
			content: opt.content
		}
		return encode_with_rule(elem, .der)!
	}
	// not present
	return []u8{}
}

fn (opt Optional) into_element() !Element {
	match opt.tag.class {
		.universal {
			return parse_universal(opt.tag, opt.content)!
		}
		.application {
			return parse_application(opt.tag, opt.content)!
		}
		.context_specific {
			return parse_context_specific(opt.tag, opt.content)!
		}
		.private {
			return parse_private(opt.tag, opt.content)!
		}
	}
}

// `into_object` tries to turns this optional into real underlying object T.
// Its return object T on success or error on fails.
pub fn (opt Optional) into_object[T]() !T {
	$if T !is Element {
		return error('T is not element')
	}
	$if T is Optional {
		return error('T is optional')
	}
	elem := opt.into_element()!
	if elem is Optional {
		return error('elem is also optional')
	}
	return elem.into_object[T]()!
}
