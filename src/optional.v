module asn1

// OPTIONAL
//
struct Optional {
	el ?Element
}

struct FieldParams {
	optional    bool
	has_default bool
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
