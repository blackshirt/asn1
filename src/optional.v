module asn1

// OPTIONAL
//
struct Optional[T] {
	// set to true when its should present
	present bool
	// when present, its should be T type
	el            T
	has_default   bool
	default_value &T = unsafe { nil }
}

fn Optional.from_element(el Element) Optional {
	return Optional{
		el: el
	}
}

fn (o Optional) tag() ?Tag {
	t := o.el or { return none }
	return t.tag()
}

fn (o Optional) payload() ![]u8 {
	el := o.el or { return []u8{cap: 0} }

	return el.payload()!
}
