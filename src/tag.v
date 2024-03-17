module asn1

// ASN1 identifier tag handling

// Maximum number of bytes to represent tag number, includes the tag byte.
// We impose limit on the tag number to be in range 0..16383. See comment on `TagNumber` type below.
// Its big enough to accomodate and represent different of yours own tag number.
// Its represents 2 bytes length where maximum bytes arrays to represent tag number
// in multibyte (long) form is `[u8(0x1f), 0xff, 0x7f]` or 16383 in base 128.
const max_tag_length = 3
const max_tag_number = 16383

// Tag represents identifier of the ASN1 element (object)
// ASN.1 Tag number can be represented in two form, short form and long form.
// The short form for tag number below <= 30 and stored enough in single byte,
// where long form for tag number > 30, and stored in two or more bytes.
// See limit restriction comment above.
pub struct Tag {
mut:
	cls         Class = .universal
	constructed bool
	number      TagNumber
}

// `new_tag` creates new ASN.1 tag identifier. Its accepts params of Class `c`,
// constructed or primitive form in `constructed` boolean flag, and the integer tag `number`.
pub fn new_tag(c Class, constructed bool, number int) !Tag {
	return Tag{
		cls: c
		constructed: constructed
		number: TagNumber.from_int(number)!
	}
}

// class return the ASN.1 class of this tag
pub fn (t Tag) class() Class {
	return t.cls
}

// is_constructed tells us whether this tag is constructed or not
pub fn (t Tag) is_constructed() bool {
	return t.constructed
}

// tag_number return the tag nunber of this tag
pub fn (t Tag) tag_number() int {
	return t.number
}

// pack_to_asn1 serializes tag t into bytes array and appended into dst
pub fn (t Tag) pack_to_asn1(mut dst []u8, p Params) ! {
	// we currently only support .der or (stricter) .ber
	if p.mode != .der && p.mode != .ber {
		return error('Tag: unsupported mode')
	}
	// makes sure TagNumber is valid
	if t.number > asn1.max_tag_number {
		return error('Tag: tag number exceed limit')
	}
	// get the class type and constructed bit and build the bytes tag.
	// if the tag number > 0x1f, represented in long form required two or more bytes,
	// otherwise, represented in short form, fit in single byte.
	mut b := (u8(t.cls) << 6) & class_mask
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

// unpack_from_asn1 deserializes bytes back into Tag structure start from `loc` offset.
// By default, its unpack in .der encoding mode, if you want more control, pass your `Params`.
// Its return Tag and next offset to operate on, and return error if it fails to unpack.
pub fn Tag.unpack_from_asn1(bytes []u8, loc i64, p Params) !(Tag, i64) {
	// preliminary check
	if bytes.len < 1 {
		return error('Tag: bytes underflow')
	}
	if p.mode != .der && p.mode != .ber {
		return error('Tag: unsupported mode')
	}
	if loc > bytes.len {
		return error('Tag: invalid pos')
	}
	mut pos := loc
	// first byte of tag bytes
	b := bytes[pos]
	pos += 1

	// First we get the first byte from the bytes, check and gets the class and constructed bits
	// and the tag number marker. If this marker == 0x1f, it tells whether the tag number is represented
	// in multibyte (long form), or short form otherwise.
	cls := int((b & class_mask) >> 6)
	constructed := b & constructed_mask == constructed_mask
	mut number := TagNumber.from_int(int(b & tag_numher_mask))!

	// check if this `number` is in long (multibyte) form, and interpretes more bytes as a tag number.
	if number == 0x1f {
		// we only allowed `max_tag_length` bytes following to represent tag number.
		number, pos = TagNumber.unpack_from_asn1(bytes, pos)!

		// pos is the next position to read next bytes, so check tag bytes length
		if pos >= asn1.max_tag_length + start + 1 {
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
		cls: Class.from_int(cls)!
		constructed: constructed
		number: number
	}
	return tag, pos
}

// clone_with_class clones teh tag t into new tag with class is set to c
fn (mut t Tag) clone_with_class(c Class) Tag {
	if t.cls == c {
		return t
	}
	mut new := t
	new.cls = c
	return new
}

fn (mut t Tag) clone_with_tag(v int) !Tag {
	if t.number == v {
		return t
	}
	val := TagNumber.from_int(v)!
	mut new := t
	t.number = val
	return new
}

// `packed_length` calculates length of bytes needed to store tag number, include one byte
// marker that tells if the tag number is in long form (>= 0x1f)
pub fn (t Tag) packed_length() int {
	n := if t.number < 0x1f { 1 } else { 1 + t.number.bytes_len() }
	return n
}

// ASN.1 Tag Number
// ASN.1 imposes no limit on the tag number, but the NIST Stable Implementation Agreements (1991)
// and its European and Asian counterparts limit the size of tags to 16383.
// see https://www.oss.com/asn1/resources/asn1-faq.html#tag-limitation
type TagNumber = int

// from_int creates TagNumber from integer v. Its does not support to pass
// negative integer, its not make sense for now.
pub fn TagNumber.from_int(v int) !TagNumber {
	if v < 0 {
		return error('TagNumber: negative number')
	}
	if v > asn1.max_tag_number {
		return error('TagNumber: ${v} is too big, dont exceed ${asn1.max_tag_number}')
	}
	return TagNumber(v)
}

// bytes_len tells amount of bytes needed to store v in base 128
fn (v TagNumber) bytes_len() int {
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

fn (v TagNumber) tag_number_length() int {
	// when number is greater than 31 (0x1f), its more bytes
	// to represent this number.
	len := if v < 0x1f { 1 } else { v.bytes_len() + 1 }
	return len
}

// pack_base128 serializes TagNumber v into bytes and append it into `to` in base 128
// the p of Params is not make sense here, its only for places holder for expandable things,
// when its has different meaning with standard, just ignore them now.
fn (v TagNumber) pack_base128(mut to []u8, p Params) {
	n := v.bytes_len()
	for i := n - 1; i >= 0; i-- {
		mut o := u8(v >> u32(i * 7))
		o &= 0x7f
		if i != 0 {
			o |= 0x80
		}

		to << o
	}
}

// unpack_from_asn1 deserializes bytes into TagNumber from loc offset in base 128.
// Its return deserialized TagNumber and next offset to process on.
fn TagNumber.unpack_from_asn1(bytes []u8, loc i64, p Params) !(TagNumber, i64) {
	if loc > bytes.len {
		return error('TagNumber: invalid pos')
	}
	mut pos := loc
	mut ret := 0
	for s := 0; pos < bytes.len; s++ {
		ret <<= 7
		b := bytes[pos]

		if s == 0 && b == 0x80 {
			// requirement for DER encoding
			return error('TagNumber: integer is not minimaly encoded')
		}

		ret |= b & 0x7f
		pos += 1

		if b & 0x80 == 0 {
			if ret > asn1.max_tag_number {
				return error('TagNumber: base 128 integer too large')
			}
			val := TagNumber.from_int(ret)!
			return val, pos
		}
	}
	return error('TagNumber: truncated base 128 integer')
}

// `universal_tag_type` transforrms this TagNumber into available Universal class of TagType,
// or return error if it is unknown number.
fn (v TagNumber) universal_tag_type() !TagType {
	// currently, only support Standard universal tag number
	if v > 36 {
		return error('TagNumber: unknown TagType number=${v}')
	}
	match v {
		// vfmt off
		0 { return .reserved } 
		1 {	return .boolean } 
		2 { return .integer	} 
		3 { return .bitstring } 
		4 { return .octetstring } 
		5 { return .null } 
		6 { return .oid } 
		7 { return .objdesc } 
		8 { return .external } 
		9 { return .real } 
		10 { return .enumerated } 
		11 { return .embedded } 
		12 { return .utf8string } 
		13 { return .relativeoid } 
		14 { return .time } 
		16 { return .sequence } 
		17 { return .set } 
		18 { return .numericstring } 
		19 { return .printablestring } 
		20 { return .t61string } 
		21 { return .videotexstring } 
		22 { return .ia5string } 
		23 { return .utctime } 
		24 { return .generalizedtime } 
		25 { return .graphicstring } 
		26 { return .visiblestring } 
		27 { return .generalstring } 
		28 { return .universalstring } 
		29 { return .characterstring } 
		30 { return .bmpstring } 
		31 { return .date } 
		32 { return .time_of_day } 
		33 { return .date_time } 
		34 { return .duration } 
		35 { return .i18_oid } 
		36 { return .relative_i18_oid } 
		// vfmt on
		else {
			return error('reserved or unknonw number')
		}
	}
}

// Standard universal tag number. Some of them was deprecated,
// so its not going to be supported on this module.
pub enum TagType {
	//	reserved for BER
	reserved         = 0
	// BOOLEAN type
	boolean          = 1
	// INTEGER type
	integer          = 2
	// BIT STRING
	bitstring        = 3
	// OCTET STRING
	octetstring      = 4
	// NULL
	null             = 5
	// OBJECT IDENTIFIER
	oid              = 6
	// ObjectDescriptor
	objdesc          = 7
	//	INSTANCE OF, EXTERNAL
	external         = 8
	// REAL
	real             = 9
	// ENUMERATED
	enumerated       = 10
	// EMBEDDED PDV
	embedded         = 11
	// UTF8String
	utf8string       = 12
	// RELATIVE-OID
	relativeoid      = 13
	// deprecated
	// 0x0f is reserved
	time             = 14
	// SEQUENCE, SEQUENCE OF, Constructed
	sequence         = 16
	///SET, SET OF, Constructed
	set              = 17
	// NumericString
	numericstring    = 18
	// PrintableString
	printablestring  = 19
	// TeletexString, T61String
	t61string        = 20
	// VideotexString
	videotexstring   = 21
	// IA5String
	ia5string        = 22
	// UTCTime
	utctime          = 23
	// GeneralizedTime
	generalizedtime  = 24
	// GraphicString
	graphicstring    = 25
	// VisibleString, ISO646String
	visiblestring    = 26
	// GeneralString
	generalstring    = 27
	// UniversalString
	universalstring  = 28
	// CHARACTER STRING
	characterstring  = 29
	// BMPString
	bmpstring        = 30
	date             = 0x1f
	time_of_day      = 0x20
	date_time        = 0x21
	duration         = 0x22
	// Internationalized OID
	i18_oid          = 0x23
	// Internationalized Relative OID
	// Reserved 0x25 and above
	relative_i18_oid = 0x24
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
