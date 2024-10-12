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
@[heap; noinit]
pub struct GeneralString {
pub:
	value string
}

// TODO: proper check GeneralString validation
// from_string creates GeneralString from string s
pub fn GeneralString.new(s string) !GeneralString {
	if !s.is_ascii() {
		return error('GeneralString: contains non-ascii chars')
	}
	return GeneralString{
		value: s
	}
}

fn (gst GeneralString) str() string {
	if gst.value.len == 0 {
		return 'GeneralString: (<empty>)'
	}
	return 'GeneralString: (${gst.value})'
}

pub fn (gst GeneralString) tag() Tag {
	return Tag{.universal, false, u32(TagType.generalstring)}
}

pub fn (gst GeneralString) payload() ![]u8 {
	return gst.payload_with_rule(.der)!
}

fn (gst GeneralString) payload_with_rule(rule EncodingRule) ![]u8 {
	if rule != .der && rule != .ber {
		return error('GeneralString: not supported rule')
	}
	if !gst.value.is_ascii() {
		return error('GeneralString: contains non-ascii chars')
	}
	return g.value.bytes()
}

// from_bytes creates GeneralString from bytes b
fn GeneralString.from_bytes(b []u8) !GeneralString {
	if b.any(it < u8(` `) || it > u8(`~`)) {
		return error('GeneralString: bytes contains non-ascii chars')
	}
	return GeneralString{
		value: b.bytestr()
	}
}

fn GeneralString.decode(src []u8, loc i64, p Params) !(GeneralString, i64) {
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
