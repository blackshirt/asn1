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
	// field options
	opts &FieldOptions = unsafe { nil }
}

// RawElement.new creates a new raw ASN.1 Element
fn RawElement.new(t Tag, payload []u8) RawElement {
	el := RawElement{
		tag:     t
		payload: payload
	}
	return el
}

// tag returns the tag of the RawElement
pub fn (re RawElement) tag() Tag {
	return re.tag
}

// payload is payload of this RawElement
pub fn (re RawElement) payload() ![]u8 {
	ctx := Context{}
	return re.payload_with_context(ctx)!
}

fn (re RawElement) payload_with_context(ctx Context) ![]u8 {
	if cxt.rule != .der && ctx.rule != .ber {
		return error('RawElement: unsupported rule')
	}
	return re.payload
}

pub fn (re RawElement) rawelement_size() !int {
	ctx := Context{}
	return re.rawelement_size_with_context(ctx)!
}

fn (re RawElement) rawelement_size_with_context(ctx Context) !int {
	mut n := 0
	n += re.tag.tag_size()!
	payload := re.payload_with_context(ctx)!
	length := Length.from_i64(payload.len)!
	n += length.length_size_with_context(ctx)!
	n += payload.len

	return n
}

// encode writes RawElement to dst with default context
pub fn (re RawElement) encode(mut dst []u8) ! {
	ctx := Context{}
	re.encode_with_context(mut dst, ctx)!
}

fn (re RawElement) encode_with_context(mut dst []u8, ctx Context) ! {
	if ctx.rule != .der && ctx.rule != .ber {
		return error('RawElement: unsupported rule')
	}
	re.tag.encode_with_context(mut dst, ctx)!
	payload := re.payload_with_context(ctx)!
	length := Length.from_i64(payload.len)!
	length.encode_with_context(mut dst, ctx)!
	dst << payload
}

pub fn RawElement.decode(src []u8) !(RawElement, i64) {
	return RawElement.decode_from_offset(src, 0)!
}

fn RawElement.decode_from_offset(src []u8, loc i64) !(RawElement, i64) {
	ctx := Context{}
	return RawElement.decode_with_context(src, loc, ctx)!
}

fn RawElement.decode_with_context(src []u8, loc i64, ctx Context) !(RawElement, i64) {
	// minimal length bytes contains tag and the length is two bytes
	if src.len < 2 {
		return error('RawElement: bytes underflow')
	}
	// guard check
	if ctx.rule != .der && ctx.rule != .ber {
		return error('RawElement: bad rule')
	}
	mut raw := RawElement{}
	tag, pos := Tag.decode_with_context(src, loc, ctx)!
	raw.tag = tag
	// check if the offset position is not overflowing src.len
	if pos >= src.len {
		return error('RawElement: pos overflow')
	}
	// read the length part
	len, idx := Length.decode_with_context(src, pos, ctx)!
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
pub fn (r RawElement) as_tagged(rule Taggedrule, inner_tag Tag, ctx Context) !TaggedType {
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
pub fn AnyDefinedBy.from_element(el Element, ctx Context) !AnyDefinedBy {
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
pub fn (a AnyDefinedBy) as_element(ctx Context) !Element {
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
pub fn AnyDefinedBy.decode(src []u8, loc i64, ctx Context) !(AnyDefinedBy, i64) {
	el, pos := Element.decode_with_context(src, loc, ctx)!
	ret := AnyDefinedBy.from_element(el, ctx)!
	return ret, pos
}

pub fn Element.decode(src []u8) !(Element, i64) {
	ctx := Context{}
	el, pos := Element.decode_with_context(src, 0, ctx)!
	return el, pos
}

// decode deserializes back bytes in src from offet `loc` into Element.
// Basically, its tries to parse a Universal class Elememt when it is possible.
// Other class parsed as a RawElement.
fn Element.decode_with_context(src []u8, loc i64, ctx Context) !(Element, i64) {
	raw, next := RawElement.decode_with_context(src, loc, ctx)!
	bytes := raw.payload

	match raw.tag.tag_class() {
		.universal {
			if raw.tag.is_constructed() {
				return parse_constructed_element(raw.tag, bytes)!, next
			}
			return parse_primitive_element(raw.tag, bytes)!, next
		}
		// other classes parsed as a RawElement
		else {
			return RawElement.new(raw.tag, bytes), next
		}
	}
}

fn (el Element) expect_tag(t Tag) bool {
	return el.tag() == t
}

// equal_with checks whether this two element equal and holds the same tag and content
fn (el Element) equal_with(other Element) bool {
	a := el.payload() or { return false }
	b := other.payload() or { return false }
	return el.tag() == other.tag() && a == b
}

fn (el Element) as_raw_element(ctx Context) !RawElement {
	re := RawElement.new(el.tag(), el.payload(ctx)!)
	return re
}

fn (el Element) expect_tag_class(c TagClass) bool {
	return el.tag().tag_class() == c
}

fn (el Element) expect_tag_form(constructed bool) bool {
	return el.tag().is_constructed() == constructed
}

fn (el Element) expect_tag_type(t TagType) bool {
	typ := el.tag().number.universal_tag_type() or { panic('unsupported tag type') }
	return typ == t
}

fn (el Element) expect_tag_number(number int) bool {
	tagnum := el.tag().tag_number()
	return int(tagnum) == number
}

// ElementList is arrays of ELement
type ElementList = []Element

// ElementList.from_bytes parses bytes in src as series of Element or return error on fails
pub fn ElementList.from_bytes(src []u8, ctx Context) ![]Element {
	mut els := []Element{}
	if src.len == 0 {
		// empty list
		return els
	}
	mut i := i64(0)
	for i < src.len {
		el, pos := Element.decode(src, i)!
		els << el
		i += pos
	}
	if i > src.len {
		return error('i > src.len')
	}
	if i < src.len {
		return error('The src contains unprocessed bytes')
	}
	return els
}

// hold_different_tag checks whether this array of Element
// contains any different tag, benefit for checking whether the type
// with this elements is sequence or sequence of type.
pub fn (els []Element) hold_different_tag() bool {
	// if els has empty length we return false, so we can treat
	// it as a regular sequence or set.
	if els.len == 0 {
		return false
	}
	// when this return true, there is nothing in elements
	// has same tag for all items, ie, there are some item
	// in the elements hold the different tag.
	tag0 := els[0].tag()
	return els.any(it.tag() != tag0)
}

// contains checks whether this array of Element contains the Element el
pub fn (els []Element) contains(el Element) bool {
	for e in els {
		if !el.equal_with(el) {
			return false
		}
	}
	return true
}

// wrap wraps this element into another element, think of TaggedType with default context.
// you should provide different class for wrapping.
fn (el Element) wrap(cls TagClass, tagnum int) !Element {
	// do nothing when the class is same
	if el.tag().tag_class() == cls {
		return
	}
	if cls == .universal {
		return error('No need wrap into universal class')
	}
	// new element payload's is the serialized the wrapped element
	payload := el.encode()!
	new_tag := Tag.new(cls, true, tagnum)!
	raw := RawElement.new(new_tag, payload)

	return raw
}
