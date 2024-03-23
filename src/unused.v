module asn1

/*
// der_decode is main routine to do parsing of DER encoded data.
// Its accepts bytes arrays encoded in DER in `src` params and returns `Encoder` interfaces object,
// so, you should cast it to get underlying type.
// By default, in context specific class, its try to read as tagged object, whether its explicit or implicit.
// TODO: more robust parsing function to handle specific use cases.
pub fn der_decode(src []u8) !Encoder {
	tag, pos := read_tag(src, 0)!
	length, next := decode_length(src, pos)!
	if src.len > next + length {
		return error('malformed bytes, contains discarded bytes')
	}

	// remaining is a contents
	// contents := src[next..next + length]
	contents := read_bytes(src, next, length)!
	match tag.class {
		.universal {
			if tag.constructed {
				return parse_compound_element(tag, contents)!
			}

			return parse_primitive_element(tag, contents)!
		}
		.application {
			return new_asn_object(.application, tag.constructed, tag.number, contents)
		}
		.context {
			if tag.constructed {
				return read_explicit_context(tag, contents)!
			}
			return read_implicit_context(tag, contents)!
		}
		.private {
			return new_asn_object(.private, tag.constructed, tag.number, contents)
		}
	}
}

fn parse_primitive_element(tag Tag, contents []u8) !Encoder {
	if tag.is_constructed() {
		return error('not primitive tag ')
	}

	match tag.number {
		int(TagType.boolean) {
			return read_boolean(contents)
		}
		int(TagType.integer) {
			return new_integer_from_bytes(contents)
		}
		int(TagType.bitstring) {
			return new_bitstring_from_bytes(contents)
		}
		int(TagType.octetstring) {
			return new_octetstring(contents.bytestr())
		}
		int(TagType.null) {
			return new_null()
		}
		int(TagType.oid) {
			return new_oid_from_bytes(contents)!
		}
		int(TagType.numericstring) {
			return new_numeric_string(contents.bytestr())
		}
		int(TagType.printablestring) {
			return new_printable_string(contents.bytestr())
		}
		int(TagType.ia5string) {
			return new_ia5string(contents.bytestr())
		}
		int(TagType.utf8string) {
			return new_utf8string(contents.bytestr())
		}
		int(TagType.visiblestring) {
			return new_visiblestring(contents.bytestr())
		}
		int(TagType.utctime) {
			return new_utctime(contents.bytestr())
		}
		// TODO:
		//   - add other type
		//   - relaxed parsing by return raw asn1 object.
		else {
			return error('unsupported tag type')
		}
	}
}

fn parse_compound_element(tag Tag, contents []u8) !Encoder {
	if !tag.is_constructed() {
		return error('not constructed tag')
	}

	match true {
		tag.is_sequence_tag() {
			return parse_seq(tag, contents)!
		}
		tag.is_set_tag() {
			return parse_set(tag, contents)!
		}
		tag.is_context() {
			return read_explicit_context(tag, contents)!
		}
		else {
			return new_asn_object(tag.class, tag.constructed, tag.number, contents)
		}
	}
}

// contents gets the contents (values) part of ASN.1 object, that is,
// bytes values of the object  without tag and length parts.
pub fn (enc Encoder) contents() ![]u8 {
	bytes := enc.encode()!

	// actual length bytes of data
	length := enc.length()
	if length == 0 {
		return []u8{}
	}

	// length of encoded bytes included header
	size := enc.size()

	// header length
	hdr := size - length
	out := read_bytes(bytes, hdr, length)!
	return out
}

// Cast function.
// Its cast encoder type to real instance type.

// as_sequence cast encoder to sequence
pub fn (e Encoder) as_sequence() !Sequence {
	if e is Sequence {
		// without dereferencing, its result in error: error: fn `as_sequence` expects you to return
		// a non reference type `!asn1.Sequence`, but you are returning `&asn1.Sequence` instead
		return *e
	}
	return error('not sequence type')
}

// as_set cast encoder to set
pub fn (e Encoder) as_set() !Set {
	if e is Set {
		return *e
	}
	return error('not set type')
}

// as_boolean cast encoder to ASN.1 boolean
pub fn (e Encoder) as_boolean() !Boolean {
	if e is Boolean {
		return *e
	}
	return error('not boolean type')
}

// as_integer cast encoder to ASN.1 integer
pub fn (e Encoder) as_integer() !AsnInteger {
	if e is AsnInteger {
		return *e
	}
	return error('not integer type')
}

// as_bitstring cast encoder to ASN.1 bitstring
pub fn (e Encoder) as_bitstring() !BitString {
	if e is BitString {
		return *e
	}
	return error('not bitstring type')
}

// as_octetstring cast encoder to ASN.1 OctetString
pub fn (e Encoder) as_octetstring() !OctetString {
	if e is OctetString {
		return *e
	}
	return error('not octetstring type')
}

// as_null cast encoder to ASN.1 null type
pub fn (e Encoder) as_null() !Null {
	if e is Null {
		return *e
	}
	return error('not null type')
}

// as_oid cast encoder to ASN.1 object identifier type.
pub fn (e Encoder) as_oid() !Oid {
	if e is Oid {
		return *e
	}
	return error('not oid type')
}

// as_enumerated cast encoder to ASN.1 enumerated type.
fn (e Encoder) as_enumerated() !Enumerated {
	if e is Enumerated {
		return *e
	}
	return error('not enumerated type')
}

// as_utf8string cast encoder to ASN.1 UTF8String.
pub fn (e Encoder) as_utf8string() !UTF8String {
	if e is UTF8String {
		return *e
	}
	return error('not utf8string type')
}

// as_numericstring cast encoder to ASN.1 NumericString.
pub fn (e Encoder) as_numericstring() !NumericString {
	if e is NumericString {
		return *e
	}
	return error('not numericstring type')
}

// as_printablestring cast encoder to ASN.1 PrintableString.
pub fn (e Encoder) as_printablestring() !PrintableString {
	if e is PrintableString {
		return *e
	}
	return error('not printablestring type')
}

// as_ia5string cast encoder to ASN.1 IA5String.
pub fn (e Encoder) as_ia5string() !IA5String {
	if e is IA5String {
		return *e
	}
	return error('not ia5string type')
}

// as_visiblestring cast encoder to ASN.1 VisibleString.
pub fn (e Encoder) as_visiblestring() !VisibleString {
	if e is VisibleString {
		return *e
	}
	return error('not visiblestring type')
}

// as_utctime cast encoder to ASN.1 UtcTime.
pub fn (e Encoder) as_utctime() !UtcTime {
	if e is UtcTime {
		return *e
	}
	return error('not utctime type')
}

// as_generalizedtime cast encoder to ASN.1 GeneralizedTime.
pub fn (e Encoder) as_generalizedtime() !GeneralizedTime {
	if e is GeneralizedTime {
		return *e
	}
	return error('not generalizedtime type')
}

// length gets the bytes length of multi encoder.
fn (enc []Encoder) length() int {
	mut length := 0
	for obj in enc {
		n := obj.size()
		length += n
	}
	return length
}

// encode serializes multi encoder objects to bytes arrays.
fn (enc []Encoder) encode() ![]u8 {
	mut dst := []u8{}
	for e in enc {
		obj := e.encode()!
		dst << obj
	}
	return dst
}

// add encoder to existing encoder arrays.
fn (mut enc []Encoder) add(e Encoder) {
	enc << e
}

// add multi encoder to existing encoder arrays.
fn (mut enc []Encoder) add_multi(es []Encoder) {
	enc << es
}

// ASN1Object is generic ASN.1 Object representation.
// Its implements Encoder, so it can be used
// to support other class of der encoded ASN.1 object
// other than universal class supported in this module.
struct ASN1Object {
	tag Tag
	// tag of the ASN.1 object
	values []u8
	// unencoded values of the object.
}

// `new_asn_object` creates new ASN.1 Object
pub fn new_asn_object(class Class, constructed bool, tagnum int, values []u8) ASN1Object {
	return ASN1Object{
		tag: Tag{
			class: class
			constructed: constructed
			number: tagnum
		}
		values: values
	}
}

pub fn (obj ASN1Object) tag() Tag {
	return obj.tag
}

pub fn (obj ASN1Object) length() int {
	return obj.values.len
}

pub fn (obj ASN1Object) size() int {
	mut size := 0
	tag := obj.tag()

	tg := calc_tag_length(tag)
	size += tg

	ln := calc_length_of_length(obj.length())
	size += int(ln)

	size += obj.length()

	return size
}

// encode serialize ASN.1 object to bytes array. its return error on fail.
pub fn (obj ASN1Object) encode() ![]u8 {
	return serialize_asn_object(obj)
}

fn serialize_asn_object(obj ASN1Object) ![]u8 {
	mut dst := []u8{}

	serialize_tag(mut dst, obj.tag())
	serialize_length(mut dst, obj.length())

	dst << obj.values

	return dst
}
*/

/*
// calculate lenght of bytes needed to store n
fn calc_length(n int) int {
	mut i := n
	mut num := 1
	for i > 255 {
		num++
		i >>= 8
	}
	return num
}

		
// bytes part of the length
fn append_length(mut dst []u8, i int) []u8 {
	mut n := calc_length(i)

	for ; n > 0; n-- {
		dst << u8(i >> (n - 1) * 8)
	}

	return dst
}

		
// calculates length of length bytes
fn calc_length_of_length(value int) int {
	mut length := 1
	if value >= 128 {
		s := calc_length(value)
		// length += 1
		length += s
	}
	return length
}


// serialize_length encodes value to dst
fn serialize_length(mut dst []u8, value int) []u8 {
	// mut dst := []u8{}
	// long form
	if value >= 128 {
		length := calc_length(value)
		dst << 0x80 | u8(length)
		dst = append_length(mut dst, value)
	} else {
		// short form
		dst << u8(value)
	}

	return dst
}

// decode_length decodes bytes from positon `loc` and returns integer length value and
// next offset to read bytes data from.
fn decode_length(buf []u8, loc int) !(int, int) {
	mut pos := loc
	if pos >= buf.len {
		return error('truncated tag or length')
	}
	mut b := buf[pos]
	pos += 1
	mut length := 0
	if b & 0x80 == 0 {
		length = int(b & 0x7f)
	} else {
		num_bytes := b & 0x7f
		if num_bytes == 0 {
			return error('unsupported undefinite length')
		}

		for i := 0; i < num_bytes; i++ {
			if pos >= buf.len {
				return error('truncated tag or length')
			}
			b = buf[pos]
			pos += 1
			if length > (max_i64 >> 8) {
				return error('Length: integer overflow')
			}
			length <<= 8
			length |= int(b)
			if length == 0 {
				return error('leading zeros')
			}
		}

		// do not allow values <0x80 to be encoded in long form
		if length < 0x80 {
			// dump(length)
			return error('dont needed in long form')
		}
	}
	return length, pos
}


// `serialize_tag` return bytes of serialized tag.
// This routine supports multi byte tag form to represents tag value that bigger than 31 (0x1f).
fn serialize_tag(mut dst []u8, tag Tag) []u8 {
	mut b := u8(tag.cls) << 6
	if tag.compound {
		b |= compound_mask
	}

	if tag.value >= 0x1f {
		b |= tag_mask // 0x1f
		dst << b
		dst = encode_base128_int(mut dst, i64(tag.value))
	} else {
		b |= u8(tag.value)
		dst << b
	}

	return dst
}

// `read_tag` reading bytes of data from location (offset) `loc` to tag.
// It's return the tag structure and the next position (offset) `pos` for reading the length part.
fn read_tag(data []u8, loc int) !(Tag, int) {
	if data.len < 1 {
		return error('get ${data.len} bytes for reading tag, its not enough')
	}
	mut pos := loc
	if pos > data.len {
		return error('invalid len')
	}

	b := data[pos]
	pos += 1

	mut value := int(b & tag_mask)
	compound := b & compound_mask == compound_mask
	cls := int(b >> 6)

	if value == 0x1f {
		// we mimic go version of tag handling, only allowed `max_tag_length` bytes following
		// to represent tag value.
		value, pos = decode_base128_int(data, pos)!
		// pos is the next position to read next bytes, so check tag bytes length
		if (pos - loc - 1) >= asn1.max_tag_length {
			return error('tag bytes is too big')
		}
		if value < 0x1f {
			return error('non-minimal tag')
		}
	}
	tag := Tag{
		// casting numbers to enums, should be done inside `unsafe{}` blocks
		cls: unsafe { Class(cls) }
		compound: compound
		value: value
	}
	return tag, pos
}

fn valid_integer(src []u8, signed bool) bool {
	if src.len == 0 {
		return false
	}

	// check for minimaly encoded
	if src.len > 1 && ((src[0] == 0 && src[1] & 0x80 == 0)
		|| (src[0] == 0xff && src[1] & 0x80 == 0x80)) {
		return false
	}

	// reject negative for unsigned type
	if !signed && src[0] & 0x80 == 0x80 {
		return false
	}
	return true
}

// i64 handling

// serialize i64
fn serialize_i64(s i64) ![]u8 {
	t := new_tag(.universal, false, int(TagType.integer))
	mut out := []u8{}

	serialize_tag(mut out, t)

	n := length_i64(s)
	mut src := []u8{len: n}

	i64_to_bytes(mut src, s)
	serialize_length(mut out, src.len)
	out << src
	return out
}

fn decode_i64(src []u8) !(Tag, i64) {
	if src.len < 2 {
		return error('decode: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.integer) {
		return error('bad tag')
	}
	if pos > src.len {
		return error('truncated input')
	}

	// mut length := 0
	length, next := decode_length(src, pos)!

	if next > src.len {
		return error('truncated input')
	}
	out := read_bytes(src, next, length)!

	val := read_i64(out)!

	return tag, val
}

// read_i64 read src as signed i64
fn read_i64(src []u8) !i64 {
	if !valid_integer(src, true) {
		return error('i64 check return false')
	}
	mut ret := i64(0)

	if src.len > 8 {
		return error('too large integer')
	}
	for i := 0; i < src.len; i++ {
		ret <<= 8
		ret |= i64(src[i])
	}

	ret <<= 64 - u8(src.len) * 8
	ret >>= 64 - u8(src.len) * 8

	// try to serialize back, and check its matching original one
	// and gives a warning when its not match.
	$if debug {
		a := new_integer(ret)
		c := a.contents()!
		if c != src {
			eprintln('maybe integer bytes not in shortest form')
		}
	}
	return ret
}

fn length_i64(val i64) int {
	mut i := val
	mut n := 1

	for i > 127 {
		n++
		i >>= 8
	}

	for i < -128 {
		n++
		i >>= 8
	}

	return n
}

fn i64_to_bytes(mut dst []u8, i i64) {
	mut n := length_i64(i)

	for j := 0; j < n; j++ {
		dst[j] = u8(i >> u32((n - 1 - j) * 8))
	}
}

// i32 handling
//
// read_i32 readt  from bytes
fn read_i32(src []u8) !int {
	if !valid_integer(src, true) {
		return error('i32 check return false')
	}

	ret := read_i64(src)!
	if ret != i64(int(ret)) {
		return error('integer too large')
	}

	return int(ret)
}

fn serialize_i32(s i32) ![]u8 {
	out := serialize_i64(i64(s))!
	return out
}

fn decode_i32(src []u8) !(Tag, i32) {
	if src.len < 2 {
		return error('decode: bad payload len')
	}
	tag, pos := read_tag(src, 0)!
	if tag.number != int(TagType.integer) {
		return error('bad tag')
	}
	if pos > src.len {
		return error('truncated input')
	}
	length, next := decode_length(src, pos)!

	if next > src.len {
		return error('truncated input')
	}
	out := read_bytes(src, next, length)!
	val := read_i32(out)!

	return tag, val
}
*/
