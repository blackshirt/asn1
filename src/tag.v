module asn1

// ASN1 identifier tag handling

// Tag represents identifier of the ASN1 element (object)
// ASN.1 Tag number can be represented in two form, short form and long form.
// The short form for tag number below <= 30 and stored enough in single byte,
// where long form for tag number > 30, and stored in two or more bytes.
// See limit restriction comment above.
pub struct Tag {
mut:
	class       TagClass = .universal
	constructed bool
	number      TagNumber
}

// `Tag.new` creates new ASN.1 tag identifier. Its accepts params of TagClass `cls`,
// the tag form in the form of constructed or primitive in `constructed` boolean flag, and the integer tag `number`.
pub fn Tag.new(cls TagClass, constructed bool, number int) !Tag {
	return Tag{
		class:       cls
		constructed: constructed
		number:      TagNumber.from_int(number)!
	}
}

// tag_class return the ASN.1 class of this tag
pub fn (t Tag) tag_class() TagClass {
	return t.class
}

// is_constructed tells us whether this tag is constructed or not
pub fn (t Tag) is_constructed() bool {
	return t.constructed
}

// tag_number return the tag nunber of this tag
pub fn (t Tag) tag_number() int {
	return t.number
}

// encode serializes tag t into bytes array and appended into dst
pub fn (t Tag) encode(mut dst []u8, p Params) ! {
	// we currently only support .der or (stricter) .ber
	if p.mode != .der && p.mode != .ber {
		return error('Tag: unsupported mode')
	}
	// makes sure TagNumber is valid
	if t.number > max_tag_number {
		return error('Tag: tag number exceed limit')
	}
	// get the class type and constructed bit and build the bytes tag.
	// if the tag number > 0x1f, represented in long form required two or more bytes,
	// otherwise, represented in short form, fit in single byte.
	mut b := (u8(t.class) << 6) & tag_class_mask
	if t.constructed {
		b |= constructed_mask
	}
	// The tag is in long form
	if t.number >= 0x1f {
		b |= tag_numher_mask // 0x1f
		dst << b
		t.number.pack_base128(mut dst)
	} else {
		// short form
		b |= u8(t.number)
		dst << b
	}
}

// Tag.decode deserializes bytes back into Tag structure start from `loc` offset.
// By default, its decodes in .der encoding mode, if you want more control, pass your `Params`.
// Its return Tag and next offset to operate on, and return error if it fails to decode.
pub fn Tag.decode(bytes []u8, loc i64, p Params) !(Tag, i64) {
	// preliminary check
	if bytes.len < 1 {
		return error('Tag: bytes underflow')
	}
	if p.mode != .der && p.mode != .ber {
		return error('Tag: unsupported mode')
	}
	// when accessing byte at ofset `loc` within bytes, ie, `b := bytes[loc]`,
	// its maybe can lead to panic when the loc is not be checked.
	if loc >= bytes.len {
		return error('Tag: invalid pos')
	}
	mut pos := loc
	// first byte of tag bytes
	b := bytes[pos]
	pos += 1

	// First we get the first byte from the bytes, check and gets the class and constructed bits
	// and the tag number marker. If this marker == 0x1f, it tells whether the tag number is represented
	// in multibyte (long form), or short form otherwise.
	class := int((b & tag_class_mask) >> 6)
	constructed := b & constructed_mask == constructed_mask
	mut number := TagNumber.from_int(int(b & tag_numher_mask))!

	// check if this `number` is in long (multibyte) form, and interpretes more bytes as a tag number.
	if number == 0x1f {
		// we only allowed `max_tag_length` bytes following to represent tag number.
		number, pos = TagNumber.decode(bytes, pos)!

		// pos is the next position to read next bytes, so check tag bytes length
		if pos >= max_tag_length + loc + 1 {
			return error('Tag: tag bytes is too long')
		}
		if number < 0x1f {
			// requirement for DER encoding.
			// TODO: the other encoding may remove this restriction
			return error('Tag: non-minimal tag')
		}
	}
	// build the tag
	tag := Tag{
		class:       TagClass.from_int(class)!
		constructed: constructed
		number:      number
	}
	return tag, pos
}

// clone_with_class clones teh tag t into new tag with class is set to c
pub fn (mut t Tag) clone_with_class(c TagClass) Tag {
	mut new := t
	new.class = c
	return new
}

pub fn (mut t Tag) clone_with_tag(v int) !Tag {
	mut new := t
	val := TagNumber.from_int(v)!
	t.number = val
	return new
}

// `packed_length` calculates length of bytes needed to store tag number, include one byte
// marker that tells if the tag number is in long form (>= 0x1f)
pub fn (t Tag) packed_length(p Params) !int {
	n := if t.number < 0x1f { 1 } else { 1 + t.number.bytes_len() }
	return n
}
