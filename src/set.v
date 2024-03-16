// Copyright (c) 2022, 2023 blackshirt. All rights reserved.
// Use of this source code is governed by a MIT License
// that can be found in the LICENSE file.
module asn1

// SET and SET OF
//
// SET and SET OF contains an unordered series of fields of one or more types.
// This differs from a SEQUENCE which contains an ordered list.
//
// Internal machinery of SET and SET OF was built using the same machinery with
// SEQUENCE and SEQUENCE OF.
pub struct Set {
	tag Tag = new_tag(c, true, int(TagType.set))
mut:
	elements []Encoder
}

// new_set creates universal set.
pub fn new_set() Set {
	return new_set_with_class(.universal)
}

// new_set_with_class creates new set with specific ASN.1 class.
pub fn new_set_with_class(c Class) Set {
	set := Set{
		tag: new_tag(c, true, int(TagType.set))
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

fn (set Set) tag() Tag {
	return new_tag(.universal, true, int(TagType.set))
}

fn (set Set) length() int {
	mut length := 0
	for obj in set.elements {
		n := obj.size()
		length += n
	}
	return length
}

fn (set Set) size() int {
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

fn (set Set) encode() ![]u8 {
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

// is_set_of checks whether the set holds the same elements (its a set of type)
fn (set Set) is_set_of() bool {
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
