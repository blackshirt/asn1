module core

// ASN1 identifier tag handling 

// Maximum number of bytes to represent tag value, includes tag byte.
// Implementation detail:
// We impose limit on the tag number to be in range 0..8943
// Its big enough to define and represent different of yours own tag number.
// For 5 bytes length, maximum bytes arrays to represent tag value is
// [u8(0x1f), 0xff, 0xff, 0xff, 0x7f] or 268435455 in base 128, so, its
// big enough to hold and represent different of tag value or type.
const max_tag_length  = 5
const max_tag_value   = 268435455

// Tag represents identifier of the ASN1 element (object)
struct Tag {
mut:
	cls      Class
	compound bool
	value    TagValue
}

// `new_tag` creates new tag with class `c`, `compound` boolean flag, and tag `value`.
fn new_tag(c Class, compound bool, value int) !Tag {
	return Tag{
		cls: c
		compound: compound
		value: TagValue.new_from_int(value)!
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
    mut value :=  TagValue.new_from_int(int(b & tag_mask))!
	
	if value == 0x1f {
		// we mimic go version of tag handling, only allowed `max_tag_length` bytes following
		// to represent tag value.
		value, pos = TagValue.unpack_base128(data, pos)!
		// pos is the next position to read next bytes, so check tag bytes length
		if pos >= asn1.max_tag_length + loc + 1  {
			return error('tag bytes is too big')
		}
		if value < 0x1f {
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
fn (t Tag) clone_with_class(c Class) Tag {
    if t.cls == c { return }
    mut new := t 
    new.cls = c 
    return new 
}

fn (t Tag) clone_with_tag(v int) Tag {
    if t.value == v { return }
    val := TagValue.new_from_int(v)!
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
// ASN.1 imposes no limit on the tag number, 
// but the NIST Stable Implementation Agreements (1991) 
// and its European and Asian counterparts limit the size of tags to 16383.
// see https://www.oss.com/asn1/resources/asn1-faq.html#tag-limitation
type TagValue = i64 

fn TagValue.new_from_int(v int) !TagValue {
    if v < 0 { 
        return error("negative value")
    }
    if v > max_tag_value { 
        return error("v is too big")
    }
    return TagValue(i64(v))
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
	mut r64 := i64(0)
	for s := 0; pos < bytes.len; s++ {
		r64 <<= 7
		b := bytes[pos]

		if s == 0 && b == 0x80 {
			return error('integer is not minimaly encoded')
		}

		r64 |= i64(b & 0x7f)
		pos += 1

		if b & 0x80 == 0 {
			if r64 > max_i64 {
				return error('base 128 integer too large')
			}
			return TagValue(r64), pos
		}
	}
	return error('truncated base 128 integer')
}

// tag_type transforrms this TagValue into available Universal class of TagType, or return error if unknown value 
fn (v TagValue) tag_type() !TagType {
    // currently, only support Standard universal tag value
    if v > 36 {
        return error("TagValue: unknown TagType value=${v}")
    }
    match v {
        0 { return .reserved } //        = 0 //	reserved for BER
	    1 { return .boolean  } //     = 1 // BOOLEAN
	    2 { return .integer  } //       = 2 // INTEGER
	    3 { return .bitstring } //      = 3 // BIT STRING
	    4 { return .octetstring } //    = 4 // OCTET STRING
	    5 { return .null } //            = 5 // NULL
	    6 { return .oid } //            = 6 // OBJECT IDENTIFIER
	    7 { return .objdesc } //        = 7 // ObjectDescriptor
	    8 { return  .external } //        = 8 //	INSTANCE OF, EXTERNAL
	    9 { return  .real } //           = 9 // REAL
	    10 { return  .enumerated } //    = 10 // ENUMERATED
	    11 { return .embedded } //        = 11 // EMBEDDED PDV
	    12 { return .utf8string } //      = 12 // UTF8String
	    13 { return .relativeoid } //     = 13 // RELATIVE-OID
        14 { return .time } //            = 14
	    16 { return .sequence   } //      = 16 // SEQUENCE, SEQUENCE OF, Constructed
	    17 { return .set  } //            = 17 ///SET, SET OF, Constructed
	    18 { return  .numericstring } //   = 18 // NumericString
	    19 { return  .printablestring } // = 19 // PrintableString
	    20 { return .t61string   } //     = 20 // eletexString, T61String
	    21 { return .videotexstring  } // = 21 // VideotexString
	    22 { return  .ia5string   } //     = 22 // IA5String
	    23 { return  .utctime   } //       = 23 // UTCTime
	    24 { return  .generalizedtime } // = 24 // GeneralizedTime
	    25 { return .graphicstring } //   = 25 // GraphicString
	    26 { return  .visiblestring } //   = 26 // VisibleString, ISO646String
	    27 { return  .generalstring  } //  = 27 // GeneralString
	    28 { return .universalstring  } //= 28 // UniversalString
	    29 { return .characterstring  } //= 29 // CHARACTER STRING
	    30 { return  .bmpstring  } //      = 30 // BMPString
        31 { return .date  } //           = 0x1f,
        32 { return  .time_of_day  } //    = 0x20,
        33 { return .date_time } //       = 0x21,
        34 { return .duration   } //      = 0x22,
        35 { return  .i18_oid } //         = 0x23,  // Internationalized OID
        36 { return  .relative_i18_oid } // = 0x24  // Internationalized Relative OID
        else {
            return error("reserved or unknonw value")
        }
    }
}



// Standard universal tag value. Some of them was deprecated, 
// so its not going to be supported on this module.
enum TagType {
	reserved        = 0 //	reserved for BER
	boolean         = 1 // BOOLEAN
	integer         = 2 // INTEGER
	bitstring       = 3 // BIT STRING
	octetstring     = 4 // OCTET STRING
	null            = 5 // NULL
	oid             = 6 // OBJECT IDENTIFIER
	objdesc         = 7 // ObjectDescriptor
	external        = 8 //	INSTANCE OF, EXTERNAL
	real            = 9 // REAL
	enumerated      = 10 // ENUMERATED
	embedded        = 11 // EMBEDDED PDV
	utf8string      = 12 // UTF8String
	relativeoid     = 13 // RELATIVE-OID
    time            = 14 // deprecated
    // 0x0f is reserved
	sequence        = 16 // SEQUENCE, SEQUENCE OF, Constructed
	set             = 17 ///SET, SET OF, Constructed
	numericstring   = 18 // NumericString
	printablestring = 19 // PrintableString
	t61string       = 20 // eletexString, T61String
	videotexstring  = 21 // VideotexString
	ia5string       = 22 // IA5String
	utctime         = 23 // UTCTime
	generalizedtime = 24 // GeneralizedTime
	graphicstring   = 25 // GraphicString
	visiblestring   = 26 // VisibleString, ISO646String
	generalstring   = 27 // GeneralString
	universalstring = 28 // UniversalString
	characterstring = 29 // CHARACTER STRING
	bmpstring       = 30 // BMPString
    date            = 0x1f
    time_of_day     = 0x20
    date_time       = 0x21
    duration        = 0x22
    i18_oid         = 0x23  // Internationalized OID
    relative_i18_oid = 0x24  // Internationalized Relative OID
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
