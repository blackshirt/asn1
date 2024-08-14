module asn1

// ASN.1 GENERALSTRING Handling
// It may contain any characters from a "G" and "C" set of any standardized character sets.
// A "G" set contains some specified set of graphic (i.e., printable) characters,
// while a "C" set contains a group of control characters.
// For example, the "G" set in the ASCII character set consists of the characters with ASCII numbers 33 through 126,
// while the "C" set is those characters with ASCII numbers 0 through 31.
// For historical reasons, the characters SPACE (number 32) and DELETE (number 127)
// are not considered to be in either the C set or the G set, but instead stand on their own
// We only treated GeneralString as an us-ascii charset
pub struct GeneralString {
	value string
mut:
	tag Tag = Tag{.universal, false, int(TagType.generalstring)}
}

// TODO: proper check GeneralString validation
// from_string creates GeneralString from string s
pub fn GeneralString.from_string(s string) !GeneralString {
	if !s.is_ascii() {
		return error('GeneralString: contains non-ascii chars')
	}
	return GeneralString{
		value: s
	}
}

// GeneralString.from_raw_element transforms RawElement in `re` into GeneralString
pub fn GeneralString.from_raw_element(re RawElement, p Params) !GeneralString {
	// check validity of the RawElement tag
	if re.tag.tag_class() != .universal {
		return error('RawElement class is not .universal, but : ${re.tag.tag_class()}')
	}
	if p.mode == .der {
		if re.tag.is_constructed() {
			return error('RawElement constructed is not allowed in .der')
		}
	}
	if re.tag.number.universal_tag_type()! != .generalstring {
		return error('RawElement tag does not hold .generalstring type')
	}
	bytes := re.payload(p)!
	bs := GeneralString.from_bytes(bytes, p)!

	return bs
}

// from_bytes creates GeneralString from bytes b
pub fn GeneralString.from_bytes(b []u8, p Params) !GeneralString {
	// Params p is not used here, but maybe to be implemented in future
	if b.any(it < u8(` `) || it > u8(`~`)) {
		return error('GeneralString: bytes contains non-ascii chars')
	}
	return GeneralString{
		value: b.bytestr()
	}
}

pub fn (g GeneralString) tag() Tag {
	return g.tag
}

pub fn (g GeneralString) value() string {
	return g.value
}

pub fn (g GeneralString) payload(p Params) ![]u8 {
	if !g.value.is_ascii() {
		return error('GeneralString: contains non-ascii chars')
	}
	return g.value.bytes()
}

pub fn (g GeneralString) length(p Params) !int {
	return g.value.bytes().len
}

pub fn (g GeneralString) packed_length(p Params) !int {
	mut n := 0

	n += g.tag.packed_length(p)!
	len := Length.from_i64(g.value.bytes().len)!
	n += len.packed_length(p)!
	n += g.value.bytes().len

	return n
}

pub fn (g GeneralString) encode(mut dst []u8, p Params) ! {
	if !g.value.is_ascii() {
		return error('GeneralString: contains non-ascii char')
	}
	if p.mode != .der && p.mode != .ber {
		return error('GeneralString: unsupported mode')
	}

	g.tag.encode(mut dst, p)!
	bytes := g.value.bytes()
	length := Length.from_i64(bytes.len)!
	length.encode(mut dst, p)!
	dst << bytes
}

pub fn GeneralString.decode(src []u8, loc i64, p Params) !(GeneralString, i64) {
	raw, next := RawElement.decode(src, loc, p)!
	if raw.tag.tag_class() != .universal || raw.tag.is_constructed()
		|| raw.tag.tag_number() != int(TagType.generalstring) {
		return error('GeneralString: bad tag of universal class type')
	}
	// no bytes
	if raw.length(p)! == 0 {
		// empty content
		return GeneralString{}, next
	}
	// check for ASCII charset
	if raw.payload.any(it < u8(` `) || it > u8(`~`)) {
		return error('GeneralString: bytes contains non-ascii chars')
	}
	ret := GeneralString{
		value: raw.payload.bytestr()
	}
	return ret, next
}

// Utility function
fn validate_general_string(s string) bool {
	if !s.is_ascii() {
		return false
	}
	return true
}
