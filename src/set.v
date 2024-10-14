// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

const default_set_tag = Tag{.universal, true, int(TagType.set)}

// SET and SET OF
//
// SET and SET OF contains an unordered series of fields of one or more types.
// This differs from a SEQUENCE which contains an ordered list.
// in DER encoding, SET types elements are sorted into tag order, and,
// for SET OF types elements are sorted into ascending order of encoding.
@[noinit]
pub struct Set {
mut:
	//	maximal size of this set fields
	max_size int = default_seqset_fields
	// fields is the elements of the set
	fields []Element
}

pub fn (s Set) tag() Tag {
	return default_set_tag
}

pub fn (s Set) payload() ![]u8 {
	return s.payload_with_rule(.der)!
}

fn (s Set) payload_with_rule(rule EncodingRule) ![]u8 {
	mut out := []u8{}
	for item in s.fields {
		obj := encode_with_rule(item, rule)!
		out << obj
	}
	return out
}

fn (s Set) str() string {
	if s.fields.len == 0 {
		return 'Set(max: ${s.max_size}): <empty>'
	}
	return 'Set(max: ${s.max_size}): ${s.fields.len} fields'
}

pub fn (set Set) fields() []Element {
	return set.fields
}

fn Set.parse(mut p Parser) !Set {
	return error('not yet implemented')
}

fn Set.decode(bytes []u8) !(Set, i64) {
	return Set.decode_with_rule(bytes, 0, .der)!
}

fn Set.decode_with_rule(bytes []u8, loc i64, rule EncodingRule) !(Set, i64) {
	tag, length_pos := Tag.decode_with_rule(bytes, loc, rule)!
	if !tag.equal(default_set_tag) {
		return error('Get unexpected non-set tag')
	}
	length, content_pos := Length.decode_with_rule(bytes, length_pos, rule)!
	payload := if length == 0 {
		[]u8{}
	} else {
		if content_pos + length > bytes.len {
			return error('Not enought bytes to read on')
		}
		unsafe { bytes[content_pos..content_pos + length] }
	}
	next := content_pos + length
	set := Set.from_bytes(payload)!
	return set, next
}

// by default allow add with the same tag
fn (mut set Set) add_element(el Element) ! {
	set.relaxed_add_element(el, true)!
}

// add_element allows adding a new element into current sequence fields.
// Its does not allow adding element when is already the same tag in the fields.
// but, some exception when you set relaxed to true
fn (mut set Set) relaxed_add_element(el Element, relaxed bool) ! {
	if set.fields.len == 0 {
		// just adds it then return
		set.fields << el
		return
	}

	for item in set.fields {
		if item.equal_with(el) {
			return error('has already in the fields')
		}
	}
	filtered_by_tag := set.fields.filter(it.equal_tag(el))
	if filtered_by_tag.len == 0 {
		set.fields << el
		return
	} else {
		if !relaxed {
			return error('You can not insert element without forcing')
		}
		set.fields << el
		return
	}
}

// bytes should set.fields payload, not includes the tag
fn Set.from_bytes(bytes []u8) !Set {
	mut set := Set{}
	if bytes.len == 0 {
		return set
	}
	mut i := i64(0)
	for i < bytes.len {
		el, _ := Element.decode_with_rule(bytes, i, .der)!
		i += el.encoded_len()
		set.add_element(el)!
	}
	if i > bytes.len {
		return error('i > bytes.len')
	}
	if i < bytes.len {
		return error('The src contains unprocessed bytes')
	}
	return set
}

fn (mut set Set) set_limit(limit int) ! {
	if limit > max_seqset_fields {
		return error('Provided limit was exceed current one')
	}
	set.max_size = limit
}

/*
fn (mut els []Element) sort_the_set() []Element {
	// without &, its return an error: sort_with_compare callback function parameter
	// `a` with type `asn1.Element` should be `&asn1.Element`
	els.sort_with_compare(fn (a &Element, b &Element) int {
		if a.tag().class != b.tag().class {
			s := if int(a.tag().class) < int(b.tag().class) { -1 } else { 1 }
			return s
		}
		if a.tag() == b.tag() {
			// compare by contents instead just return 0
			mut aa := []u8{}
			a.encode(mut aa) or { panic(err) }
			mut bb := []u8{}
			b.encode(mut bb) or { panic(err) }
			return aa.bytestr().compare(bb.bytestr())
		}
		q := if a.tag().number < b.tag().number { -1 } else { 1 }
		return q
	})
	return els
}

fn (mut els []Element) sort_the_setof() ![]Element {
	els.sort_with_compare(fn (a &Element, b &Element) int {
		mut aa := []u8{}
		a.encode(mut aa) or { panic(err) }
		mut bb := []u8{}
		b.encode(mut bb) or { panic(err) }
		return aa.bytestr().compare(bb.bytestr())
	})
	return els
}
*/

// ASN.1 SET OF
//
@[noinit]
pub struct SetOf[T] {
mut:
	max_size int = default_seqset_fields
pub:
	fields []T
}

pub fn (so SetOf[T]) tag() Tag {
	return default_set_tag
}

pub fn (so SetOf[T]) payload() ![]u8 {
	return so.payload_with_rule(.der)!
}

fn (so SetOf[T]) payload_with_rule(rule EncodingRule) ![]u8 {
	$if T !is Element {
		return error('T is not an element')
	}
	mut out := []u8{}
	for el in so.fields {
		obj := encode_with_rule(el, rule)!
		out << obj
	}
	return out
}

/*
// Required for DER encoding.
// The encodings of the component values of a set value shall appear in an order determined by their tags.
// The canonical order for tags is based on the outermost tag of each type and is defined as follows:
//   a) those elements or alternatives with universal class tags shall appear first, followed by those with
//      application class tags, followed by those with context-specific tags, followed by those with private class
//      tags;
//   b) within each class of tags, the elements or alternatives shall appear in ascending order of their tag
//      numbers.

fn (mut objs []Encoder) sort_the_set() []Encoder {
	// without &, its return an error: sort_with_compare callback function parameter
	// `a` with type `asn1.Encoder` should be `&asn1.Encoder`
	objs.sort_with_compare(fn (a &Encoder, b &Encoder) int {
		if a.tag().class != b.tag().class {
			s := if int(a.tag().class) < int(b.tag().class) { -1 } else { 1 }
			return s
		}
		if a.tag() == b.tag() {
			// compare by contents instead just return 0
			aa := a.encode() or { return 0 }
			bb := b.encode() or { return 0 }
			return aa.bytestr().compare(bb.bytestr())
		}
		q := if a.tag().number < b.tag().number { -1 } else { 1 }
		return q
	})
	return objs
}

fn (mut objs []Encoder) sort_the_setof() ![]Encoder {
	objs.sort_with_compare(fn (a &Encoder, b &Encoder) int {
		aa := a.encode() or { return 0 }
		bb := b.encode() or { return 0 }
		return aa.bytestr().compare(bb.bytestr())
	})
	return objs
}

pub fn (set Set) encode() ![]u8 {
	mut dst := []u8{}
	tag := set.tag()
	serialize_tag(mut dst, tag)

	serialize_length(mut dst, set.length())

	mut objs := set.elements.clone()

	// sorted
	if set.is_set_of() {
		objs.sort_the_setof()!
	} else {
		objs.sort_the_set()
	}

	for obj in objs {
		o := obj.encode()!
		dst << o
	}
	return dst
}

pub fn Set.decode(src []u8) !Set {
	if src.len < 2 {
		return error('Set: underflow')
	}
	tag, pos := read_tag(src, 0)!
	if !tag.is_set_tag() {
		return error('bad tags n look like not a set tag=${tag}')
	}

	length, next := decode_length(src, pos)!
	sub := read_bytes(src, next, length)!

	set := parse_set(tag, sub)!

	return set
}

// is_set_of checks whether the set holds the same elements (its a set of type)
pub fn (set Set) is_set_of() bool {
	tag := set.tag.number
	if tag != int(TagType.set) {
		return false
	}
	// take the tag of the first obj
	tag0 := set.elements[0].tag()

	for obj in set.elements {
		if obj.tag() != tag0 {
			return false
		}
	}

	return true
}
*/
