module asn1

// Raw ASN.1 Element
pub struct RawElement {
mut:
	// the tag of the RawElement
	tag Tag
	// payload is the value of this RawElement, its depend how its would be interpreted.
	// when the tag is primitive, its represents real value of this RawElement.
	// otherwise, if its a constructed, its contains another unparsed RawElement
	payload []u8
}

// tag returns the tag of the RawElement
pub fn (re RawElement) tag() Tag {
	return re.tag
}

// payload is payload of this RawElement
pub fn (re RawElement) payload() ![]u8 {
	return re.payload
}

fn (re RawElement) rawelement_size() !int {
	ctx := default_params()
	return re.rawelement_size_with_context(ctx)!
}

fn (re RawElement) rawelement_size_with_context(ctx &Params) !int {
	mut n := 0
	n += re.tag.tag_size()!
	payload := re.payload_with_context(ctx)!
	length := Length.from_i64(payload.len)!
	n += length.length_size_with_rule(ctx.rule)!
	n += payload.len

	return n
}

// encode writes RawElement to dst with default context
pub fn (re RawElement) encode(mut dst []u8) ! {
	ctx := default_params()
	re.encode_with_context(mut dst, ctx)!
}

fn (re RawElement) encode_with_context(mut dst []u8, ctx &Params) ! {
	if ctx.rule != .der && ctx.rule != .ber {
		return error('RawElement: unsupported rule')
	}
	re.tag.encode_with_rule(mut dst, ctx.rule)!
	payload := re.payload_with_context(ctx)!
	length := Length.from_i64(payload.len)!
	length.encode_with_rule(mut dst, ctx.rule)!
	dst << payload
}

pub fn RawElement.decode(src []u8) !(RawElement, i64) {
	return RawElement.decode_from_offset(src, 0)!
}

fn RawElement.decode_from_offset(src []u8, loc i64) !(RawElement, i64) {
	ctx := default_params()
	return RawElement.decode_with_context(src, loc, ctx)!
}

fn RawElement.decode_with_context(src []u8, loc i64, ctx &Params) !(RawElement, i64) {
	// minimal length bytes contains tag and the length is two bytes
	if src.len < 2 {
		return error('RawElement: bytes underflow')
	}
	// guard check
	if ctx.rule != .der && ctx.rule != .ber {
		return error('RawElement: bad rule')
	}
	mut raw := RawElement{}
	tag, pos := Tag.decode_with_rule(src, loc, ctx.rule)!
	raw.tag = tag
	// check if the offset position is not overflowing src.len
	if pos >= src.len {
		return error('RawElement: pos overflow')
	}
	// read the length part
	len, idx := Length.decode_with_rule(src, pos, ctx.rule)!
	// check if len == 0, its mean this parsed element has no content bytes
	// on last offset
	if len == 0 {
		raw.payload = []u8{}
	} else {
		// len !=0
		// check if idx + len is not overflow src.len, if its not happen,
		// this element has a content, or return error if not.
		// when idx == src.len, but len != 0, its mean the input is truncated
		// its also same mean for idx+len is over to the src.len
		if idx >= src.len || idx + len > src.len {
			return error('RawElement: truncated src bytes')
		}
		payload := unsafe { src[idx..idx + len] }
		if len != payload.len {
			return error('RawElement: unmatching length')
		}
		raw.payload = payload
	}
	return raw, idx + len
}

/*
// as_tagged treats and parse the RawElement r as TaggedType element with inner_tag is
// an expected tag of inner Element being tagged.
pub fn (r RawElement) as_tagged(rule Taggedrule, inner_tag Tag, ctx &Params) !TaggedType {
	// make sure the tag is in constructed form, when it true, the r.payload is an ASN.1 Element
	// when rule is explicit or the r.payload is bytes content by itself when rule is implicit.
	if r.tag.is_constructed() {
		if r.payload.len == 0 {
			return error('tag is constructed but no payload')
		}
		if rule == .explicit {
			raw, _ := RawElement.decode(r.payload, 0, ctx)!
			if raw.tag != inner_tag {
				return error('expected inner_tag != parsed tag')
			}

			if raw.payload.len == 0 {
				// empty sub payload
				inner := RawElement{
					tag:     raw.tag
					payload: raw.payload
				}
				tt := TaggedType{
					outer_tag: r.tag
					rule:      .explicit
					inner_el:  inner
				}
				return tt
			}
			// otherwise are ok
			sub := raw.payload

			// if tag is constructed, its maybe recursive thing
			inner_el := if raw.tag.is_constructed() {
				parse_constructed_element(raw.tag, sub)!
			} else {
				// otherwise its a primitive type
				parse_primitive_element(raw.tag, sub)!
			}
			tt := TaggedType{
				outer_tag: r.tag
				rule:      .explicit
				inner_el:  inner_el
			}
			return tt
		}
		// as in implicit rule, r.payload is a contents payload by itself
		// TODO: should we can treat r.payload as ASN1 element when inner_tag is constructed
		// FIXME:
		// otherwise, its just RawElement
		inner_el := RawElement.new(inner_tag, r.payload)
		tt := TaggedType{
			outer_tag: r.tag
			rule:      .implicit
			inner_el:  inner_el
		}
		return tt
	}
	return error('This RawElement can not be treated as TaggedType')
}
*/

// CHOICE
// Note: not tested
// We represent ASN.1 CHOICE as an arbitryary `asn1.Element` which is possible to do something
// in more broader scope. You should validate your choice against yours predefined choice list.
type Choice = Element

// new creates a new Choice from element el
pub fn Choice.new(el Element) Choice {
	return Choice(el)
}

// validate_choice performs validation and check if this choice was valid choice and
// was contained within choice list cl.
pub fn (c Choice) validate_choice(cl []Choice) bool {
	for el in cl {
		// check if one of the choice in choice list has matching tag and payload with
		// the given choice
		chp := c.payload() or { panic(err) }
		elp := el.payload() or { panic(err) }
		if c.tag() == el.tag() && chp == elp {
			return true
		}
	}
	return false
}

// ANY DEFINED BY
//
// Note: not tested
// AnyDefinedBy do not implements `asn1.Element`, so its can't be used as an ASN.1 ELement.
pub struct AnyDefinedBy {
	// params is raw bytes contents, its maybe contains only payload element
	// or full encoded element, or just null bytes. Its depends on the context.
pub:
	params []u8
}

// from_element creates AnyDefinedBy from ASN.1 Element el. Its stores
// encoded element as AnyDefinedBy's content.
pub fn AnyDefinedBy.from_element(el Element, ctx &Params) !AnyDefinedBy {
	mut out := []u8{}
	el.encode(mut out, ctx)!
	return AnyDefinedBy{
		params: out
	}
}

// from_bytes creates AnyDefinedBy from raw bytes in b in uninterpreted way.
pub fn AnyDefinedBy.from_bytes(b []u8) AnyDefinedBy {
	return AnyDefinedBy{
		params: b
	}
}

// as_element interpretes this AnyDefinedBy params as an ASN.1 Element
pub fn (a AnyDefinedBy) as_element(ctx &Params) !Element {
	el, pos := Element.decode_with_context(a.params, 0, ctx)!
	if pos != a.params.len {
		return error('AnyDefinedBy params contains unprocessed bytes')
	}
	return el
}

// as_raw returns AnyDefinedBy as raw bytes
pub fn (a AnyDefinedBy) as_raw() []u8 {
	return a.params
}

// AnyDefinedBy.decode parses and decodes bytes in src into AnyDefinedBy.
// Its try to interprete the bytes as an encoded ASN.1 Element
pub fn AnyDefinedBy.decode(src []u8, loc i64, ctx &Params) !(AnyDefinedBy, i64) {
	el, pos := Element.decode_with_context(src, loc, ctx)!
	ret := AnyDefinedBy.from_element(el, ctx)!
	return ret, pos
}
