// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// SET and SET OF
//
// SET and SET OF contains an unordered series of fields of one or more types.
// This differs from a SEQUENCE which contains an ordered list.
// in DER encoding, SET types elements are sorted into tag order, and,
// for SET OF types elements are sorted into ascending order of encoding.
@[heap; noinit]
pub struct Set {
mut:
	//	maximal size of this set fields
	max_size int = default_seqset_fields
pub:
	// fields is the elements of the set
	fields []Element
}

fn (s Set) str() string {
	if s.fields.len == 0 {
		return 'Set(max: ${s.max_size}): <empty>'
	}
	return 'Set(max: ${s.max_size}): ${s.fields.len} fields'
}

pub fn (s Set) tag() Tag {
	return s.tag
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

pub fn (s Set) encode(mut dst []u8, p Params) ! {
	if p.rule != .der && p.rule != .ber {
		return error('set: unsupported rule')
	}
	// recheck
	if !s.tag().is_constructed() && s.tag().tag_number() != int(TagType.set) {
		return error('Not a valid set tag')
	}
	// pack in DER rule
	s.tag.encode(mut dst, p)!
	payload := s.payload(p)!
	length := Length.from_i64(payload.len)!
	length.encode(mut dst, p)!
	dst << payload
}

pub fn Set.decode(src []u8, loc i64, p Params) !(Set, i64) {
	raw, next := RawElement.decode(src, loc, p)!

	if raw.tag.tag_class() != .universal && !raw.tag.is_constructed()
		&& raw.tag.tag_number() != int(TagType.set) {
		return error('Set: bad set tag')
	}

	if raw.payload.len == 0 {
		// empty sequence
		set := Set.new(false)
		return set, next
	}

	mut set := Set.parse_contents(raw.tag, raw.payload)!
	// check for hold_different_tag
	if !set.elements.hold_different_tag() {
		// set sequence into sequenceof type
		set.setof = true
	}
	return set, next
}

// Utility function
//
fn Set.parse_contents(tag Tag, contents []u8, p Params) !Set {
	if !tag.is_constructed() && tag.tag_number() != int(TagType.set) {
		return error('Set: not set tag')
	}
	mut i := 0
	// by default, we create regular Set type
	// if you wish SET OF type, call `.set_into_setof()`
	// on this set to have SET OF behavior,
	// or you can call it later.
	mut set := Set.new(false)
	for i < contents.len {
		raw, _ := RawElement.decode(contents, i, p)!
		// TODO: still no check
		sub := raw.payload
		if raw.tag.is_constructed() {
			obj := parse_constructed_element(raw.tag, sub)!
			set.add_element(obj)!
			i += obj.packed_length(p)!
		} else {
			obj := parse_primitive_element(raw.tag, sub)!
			set.add_element(obj)!
			i += obj.packed_length(p)!
		}
	}
	return set
}

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

// SET OF
//
@[heap; noinit]
pub struct SetOf[T] {
mut:
	max_size int = default_seqset_fields
pub:
	fields []T
}

pub fn (so SetOf[T]) tag() Tag {
	return Tag{.universal, true, u32(TagType.set)}
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
// new_set creates universal set.
pub fn new_set() Set {
	return new_set_with_class(.universal)
}

// new_set_with_class creates new set with specific ASN.1 class.
pub fn new_set_with_class(c TagClass) Set {
	set := Set{
		tag: Tag.new(c, true, int(TagType.set))
	}
	return set
}

fn new_set_from_multiencoder(en []Encoder) !Set {
	mut set := new_set()
	set.add_multi(en)
	return set
}

fn parse_set(tag Tag, contents []u8) !Set {
	if !tag.is_set_tag() {
		return error('not set tag')
	}

	mut i := 0
	mut set := new_set_with_class(tag.class)
	for i < contents.len {
		t, idx := read_tag(contents, i)!
		ln, next := decode_length(contents, idx)!

		sub := read_bytes(contents, next, ln)!
		match t.constructed {
			true {
				obj := parse_compound_element(t, sub)!
				set.add(obj)
				i += obj.size()
			}
			false {
				obj := parse_primitive_element(t, sub)!
				set.add(obj)
				i += obj.size()
			}
		}
	}
	return set
}

pub fn (mut set Set) add(obj Encoder) Set {
	set.elements.add(obj)
	return set
}

pub fn (mut set Set) add_multi(objs []Encoder) Set {
	set.elements.add_multi(objs)
	return set
}

pub fn (set Set) tag() Tag {
	return Tag.new(.universal, true, int(TagType.set))
}

pub fn (set Set) length() int {
	mut length := 0
	for obj in set.elements {
		n := obj.size()
		length += n
	}
	return length
}

pub fn (set Set) size() int {
	mut size := 0
	tag := set.tag()
	t := calc_tag_length(tag)
	size += t

	l := calc_length_of_length(set.length())
	size += int(l)

	for o in set.elements {
		n := o.size()
		size += n
	}
	return size
}

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
