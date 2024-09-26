module asn1

// OPTIONAL
//
// note: At the abstract ASN.1 level the absence of a DEFAULT value in an encoding is the same as its being present.
// Contrast this with OPTIONAL, where a value being present in the encoding is semantically distinct from its being absent.
// In some encoding rules (like BER/PER) it is at the whim of the sender whether a DEFAULT value is encoded or not
// (except for primitive type values in PER which are required by the PER standard to be absent in the encoding),
// while with others (like DER) the DEFAULT value is NEVER encoded. For all encoding rules,
// if the component that has a DEFAULT value is not encoded the receiving application must behave as though the DEFAULT value had been encoded.
struct Optional[T] {
	// set to true when its should present
	present bool
	// when present, its should be T type
	el            T
	has_default   bool
	default_value &T = unsafe { nil }
}

fn validate_optional(opt Optional[T]) ! {
	if opt.has_default {
		if opt.default_value == unsafe { nil } {
			return error('Optional has default_value, but default_value is nil')
		}
	}
}

fn Optional.from_element(el Element) Optional {
	return Optional{
		el: el
	}
}

fn (opt Optional) tag() Tag {
	return opt.el.tag()
}

fn (opt Optional) payload() ![]u8 {
	return opt.el.payload()!
}

fn (opt Optional) encode() ![]u8 {
	mut out := []u8{}
	// when its not present, its should be encoded into empty bytes
	if !opt.present {
		return out
	}
	// when present, its should be serializable
	opt.tag().encode(mut out)!
	out << opt.payload()!

	return out
}
