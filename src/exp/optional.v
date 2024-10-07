module asn1

// OPTIONAL
//
// note: At the abstract ASN.1 level the absence of a DEFAULT value in an encoding is the same as its being present.
// Contrast this with OPTIONAL, where a value being present in the encoding is semantically distinct from its being absent.
// In some encoding rules (like BER/PER) it is at the whim of the sender whether a DEFAULT value is encoded or not
// (except for primitive type values in PER which are required by the PER standard to be absent in the encoding),
// while with others (like DER) the DEFAULT value is NEVER encoded. For all encoding rules,
// if the component that has a DEFAULT value is not encoded the receiving application must behave as though the DEFAULT value had been encoded.
@[heap]
struct Optional {
	// underlying element marked as an optional
	elem Element
mut:
	// set to true when its should present, default to false
	present       bool
	has_default   bool
	default_value ?Element
}

fn (opt Optional) validate() ! {
	if opt.has_default && opt.default_value == none {
		return error('Optional with has_default but default_value is none')
	}
	if opt.has_default && opt.default_value != none {
		val := opt.default_value or { return error('none') }
		if opt.elem.tag() != val.tag() {
			return error('default value with different tag is not allowed')
		}
	}
}

fn new_optional(el Element) &Optional {
	return &Optional{
		elem: el
	}
}

fn (mut opt Optional) set_default(el Element) ! {
	if !opt.has_default {
		return
	}
	if opt.elem.tag() != el.tag() {
		return error('default value with different tag is not allowed')
	}
	opt.default_value = el
}

fn (mut opt Optional) with_default(el Element) !&Optional {
	opt.set_default(el)!
	return opt
}

fn (mut opt Optional) with_has_default(flag bool) &Optional {
	opt.has_default = flag
	return opt
}

fn (mut opt Optional) with_present(present bool) &Optional {
	opt.present = present
	return opt
}

fn (opt Optional) tag() Tag {
	return opt.elem.tag()
}

fn (opt Optional) payload() ![]u8 {
	opt.validate()!
	return opt.elem.payload()!
}

fn (opt Optional) into_t[T]() !T {
	$if T !is Element {
		return error('T is not element')
	}
	return el.into_object[T]()!
}
