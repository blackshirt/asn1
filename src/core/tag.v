module core

// ASN1 identifier tag handling

// Maximum number of bytes to represent tag value, includes the tag byte.
// We impose limit on the tag number to be in range 0..16383. See comment on `TagValue` type below.
// Its big enough to accomodate and represent different of yours own tag number.
// Its represents 2 bytes length, maximum bytes arrays to represent tag value is
// [u8(0x1f), u8(0xff), 0x7f] or 16383 in base 128.
const max_tag_length = 3
const max_tag_value = 16383

// Tag represents identifier of the ASN1 element (object)
// ASN.1 tag value can be represented in two form, short form and long form.
// The short form for tag value below <= 30 and stored enough in single byte,
// where long form for tag value > 30, and stored in two or more bytes (see limit restriction above).
struct Tag {
mut:
	cls      Class
	compound bool
	value    TagValue
}

// `new_tag` creates new tag identifier. Its accepts params of Class `c`, constructed or primitive
// form in `compound` boolean flag, and the tag `value`.
fn new_tag(c Class, compound bool, value int) !Tag {
	return Tag{
		cls: c
		compound: compound
		value: TagValue.from_int(value)!
	}
}

// pack serializes tag t into bytes array and appended into dst
fn (t Tag) pack(mut dst []u8) {
	mut b := u8(t.cls) << 6
	if t.compound {
		b |= compound_mask
	}

	if t.value >= 0x1f {
		b |= tag_mask // 0x1f
		dst << b
		t.value.pack_base128(mut dst)
	} else {
		b |= u8(t.value)
		dst << b
	}
}

// unpack deserializes bytes of data to Tag structure, start from offset loc position.
// Its return Tag and next offset to operate on, and return error if fail to unpack.
fn Tag.unpack(data []u8, loc int) !(Tag, int) {
	if data.len < 1 {
		return error('get ${data.len} bytes for reading tag, its not enough')
	}
	mut pos := loc
	if pos > data.len {
		return error('invalid len')
	}

	b := data[pos]
	pos += 1

	cls := int((b & class_mask) >> 6)
	compound := b & compound_mask == compound_mask
	mut value := TagValue.from_int(int(b & tag_mask))!

	// check if this `value` is a long (multibyte) form, and interpretes more bytes as a tag value.
	if value == 0x1f {
		// we mimic go version of tag handling, only allowed `max_tag_length` bytes following
		// to represent tag value.
		value, pos = TagValue.unpack_base128(data, pos)!

		// pos is the next position to read next bytes, so check tag bytes length
		if pos >= core.max_tag_length + loc + 1 {
			return error('tag bytes is too big')
		}
		if value < 0x1f {
			// requirement for DER encoding.
			// TODO: the other encoding may remove this restriction
			return error('non-minimal tag')
		}
	}
	tag := Tag{
		cls: class_from_int(cls)!
		compound: compound
		value: value
	}
	return tag, pos
}

// clone_with_class clones t to new Tag with class is set to c
fn (mut t Tag) clone_with_class(c Class) Tag {
	if t.cls == c {
		return t
	}
	mut new := t
	new.cls = c
	return new
}

fn (mut t Tag) clone_with_tag(v int) !Tag {
	if t.value == v {
		return t
	}
	val := TagValue.from_int(v)!
	mut new := t
	t.value = val
	return new
}

// `tag_length` calculates length of bytes needed to store tag value.
fn (t Tag) tag_length() int {
	n := if t.value < 0x1f { 1 } else { 1 + t.value.bytes_needed() }
	return n
}

// ASN.1 Tag value part
// ASN.1 imposes no limit on the tag number, but the NIST Stable Implementation Agreements (1991)
// and its European and Asian counterparts limit the size of tags to 16383.
// see https://www.oss.com/asn1/resources/asn1-faq.html#tag-limitation
type TagValue = int

fn TagValue.from_int(v int) !TagValue {
	if v < 0 {
		return error('TagValue: negative value')
	}
	if v > core.max_tag_value {
		return error('TagValue: ${v} is too big, dont exceed ${core.max_tag_value}')
	}
	return TagValue(v)
}

// bytes_needed tells amount of bytes needed to store v in base 128
fn (v TagValue) bytes_needed() int {
	if v == 0 {
		return 1
	}
	mut n := v
	mut ret := 0

	for n > 0 {
		ret += 1
		n >>= 7
	}

	return ret
}

fn (v TagValue) length() int {
	mut len := 1
	// when value is greater than 31 (0x1f), its more bytes
	// to represent this value.
	if v >= 0x1f {
		n := v.bytes_needed()
		len += n
	}
	return len
}

// pack_base128 serializes TagValue v into bytes and append it into `to` in base 128
fn (v TagValue) pack_base128(mut to []u8) {
	n := v.bytes_needed()
	for i := n - 1; i >= 0; i-- {
		mut o := u8(v >> u32(i * 7))
		o &= 0x7f
		if i != 0 {
			o |= 0x80
		}

		to << o
	}
}

// unpack deserializes bytes into TagValue from offset loc in base 128.
fn TagValue.unpack_base128(bytes []u8, loc int) !(TagValue, int) {
	mut pos := loc
	mut ret := 0
	for s := 0; pos < bytes.len; s++ {
		ret <<= 7
		b := bytes[pos]

		if s == 0 && b == 0x80 {
			return error('integer is not minimaly encoded')
		}

		ret |= b & 0x7f
		pos += 1

		if b & 0x80 == 0 {
			if ret > core.max_tag_value {
				return error('base 128 integer too large')
			}
			val := TagValue.from_int(ret)!
			return val, pos
		}
	}
	return error('truncated base 128 integer')
}

// universal_tag_type transforrms this TagValue into available Universal class of TagType,
// or return error if it is unknown value.
fn (v TagValue) universal_tag_type() !TagType {
	// currently, only support Standard universal tag value
	if v > 36 {
		return error('TagValue: unknown TagType value=${v}')
	}
	match v {
		0 {
			return .reserved
		} //        = 0 //	reserved for BER
		1 {
			return .boolean
		} //     = 1 // BOOLEAN
		2 {
			return .integer
		} //       = 2 // INTEGER
		3 {
			return .bitstring
		} //      = 3 // BIT STRING
		4 {
			return .octetstring
		} //    = 4 // OCTET STRING
		5 {
			return .null
		} //            = 5 // NULL
		6 {
			return .oid
		} //            = 6 // OBJECT IDENTIFIER
		7 {
			return .objdesc
		} //        = 7 // ObjectDescriptor
		8 {
			return .external
		} //        = 8 //	INSTANCE OF, EXTERNAL
		9 {
			return .real
		} //           = 9 // REAL
		10 {
			return .enumerated
		} //    = 10 // ENUMERATED
		11 {
			return .embedded
		} //        = 11 // EMBEDDED PDV
		12 {
			return .utf8string
		} //      = 12 // UTF8String
		13 {
			return .relativeoid
		} //     = 13 // RELATIVE-OID
		14 {
			return .time
		} //            = 14
		16 {
			return .sequence
		} //      = 16 // SEQUENCE, SEQUENCE OF, Constructed
		17 {
			return .set
		} //            = 17 ///SET, SET OF, Constructed
		18 {
			return .numericstring
		} //   = 18 // NumericString
		19 {
			return .printablestring
		} // = 19 // PrintableString
		20 {
			return .t61string
		} //     = 20 // eletexString, T61String
		21 {
			return .videotexstring
		} // = 21 // VideotexString
		22 {
			return .ia5string
		} //     = 22 // IA5String
		23 {
			return .utctime
		} //       = 23 // UTCTime
		24 {
			return .generalizedtime
		} // = 24 // GeneralizedTime
		25 {
			return .graphicstring
		} //   = 25 // GraphicString
		26 {
			return .visiblestring
		} //   = 26 // VisibleString, ISO646String
		27 {
			return .generalstring
		} //  = 27 // GeneralString
		28 {
			return .universalstring
		} //= 28 // UniversalString
		29 {
			return .characterstring
		} //= 29 // CHARACTER STRING
		30 {
			return .bmpstring
		} //      = 30 // BMPString
		31 {
			return .date
		} //           = 0x1f,
		32 {
			return .time_of_day
		} //    = 0x20,
		33 {
			return .date_time
		} //       = 0x21,
		34 {
			return .duration
		} //      = 0x22,
		35 {
			return .i18_oid
		} //         = 0x23,  // Internationalized OID
		36 {
			return .relative_i18_oid
		} // = 0x24  // Internationalized Relative OID
		else {
			return error('reserved or unknonw value')
		}
	}
}

// Standard universal tag value. Some of them was deprecated,
// so its not going to be supported on this module.
enum TagType {
	reserved         = 0
	//	reserved for BER
	boolean          = 1
	// BOOLEAN
	integer          = 2
	// INTEGER
	bitstring        = 3
	// BIT STRING
	octetstring      = 4
	// OCTET STRING
	null             = 5
	// NULL
	oid              = 6
	// OBJECT IDENTIFIER
	objdesc          = 7
	// ObjectDescriptor
	external         = 8
	//	INSTANCE OF, EXTERNAL
	real             = 9
	// REAL
	enumerated       = 10
	// ENUMERATED
	embedded         = 11
	// EMBEDDED PDV
	utf8string       = 12
	// UTF8String
	relativeoid      = 13
	// RELATIVE-OID
	time             = 14
	// deprecated
	// 0x0f is reserved
	sequence         = 16
	// SEQUENCE, SEQUENCE OF, Constructed
	set              = 17
	///SET, SET OF, Constructed
	numericstring    = 18
	// NumericString
	printablestring  = 19
	// PrintableString
	t61string        = 20
	// eletexString, T61String
	videotexstring   = 21
	// VideotexString
	ia5string        = 22
	// IA5String
	utctime          = 23
	// UTCTime
	generalizedtime  = 24
	// GeneralizedTime
	graphicstring    = 25
	// GraphicString
	visiblestring    = 26
	// VisibleString, ISO646String
	generalstring    = 27
	// GeneralString
	universalstring  = 28
	// UniversalString
	characterstring  = 29
	// CHARACTER STRING
	bmpstring        = 30
	// BMPString
	date             = 0x1f
	time_of_day      = 0x20
	date_time        = 0x21
	duration         = 0x22
	i18_oid          = 0x23
	// Internationalized OID
	relative_i18_oid = 0x24
	// Internationalized Relative OID
	// Reserved 0x25 and above
}

fn (t TagType) str() string {
	match t {
		.boolean { return 'boolean' }
		.integer { return 'integer' }
		.bitstring { return 'bitstring' }
		.octetstring { return 'octetstring' }
		.null { return 'null' }
		.oid { return 'oid' }
		.enumerated { return 'enumerated' }
		.utf8string { return 'utf8string' }
		.sequence { return 'sequence or sequence of' }
		.set { return 'set or set of' }
		.numericstring { return 'numericstring' }
		.printablestring { return 'printablestring' }
		.ia5string { return 'ia5string' }
		.utctime { return 'utctime' }
		.generalizedtime { return 'generalizedtime' }
		.visiblestring { return 'visiblestring' }
		else { return 'unsupported name' }
	}
}
