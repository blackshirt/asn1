module main

import asn1

const data = [u8(0x30), 0x15, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x0e, 0x30, 0x0c, 0x1b, 0x0a,
	0x62, 0x6f, 0x62, 0x62, 0x61, 0x2d, 0x66, 0x65, 0x74, 0x74]

/*
 KDC-REQ         ::= SEQUENCE {
        -- NOTE: first tag is [1], not [0]
        pvno            [1] INTEGER (5) ,
        msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
        padata          [3] SEQUENCE OF PA-DATA OPTIONAL
                            -- NOTE: not empty --,
        req-body        [4] KDC-REQ-BODY
}
*/
struct KdcReq {
	pvno     int
	msg_type int
	padata   []PaData
	req_body KdcReqBody
}

// PA-DATA         ::= SEQUENCE {
//     -- NOTE: first tag is [1], not [0]
//     padata-type     [1] Int32,
//     padata-value    [2] OCTET STRING -- might be encoded AP-REQ
// }

struct PaData {
	pd_type  int
	pd_value asn1.OctetString
}

// validate
fn (p PaData) valid() bool {
	return true
}

fn (p PaData) tag() asn1.Tag {
	return p.tag
}

fn (p PaData) packed_length() int {
	mut n := 0

	n += p.tag().packed_length()

	return n
}

fn (p PaData) pack(mut out []u8) ! {
	if !p.valid() {
		return error('not valid')
	}
	tt0 := TaggedType.explicit_context(p.pd_type, 1)!
	tt1 := TaggedType.explicit_context(p.pd_value, 2)!
	el0 := tt0.to_element()!
	el1 := tt1.to_element()!

	mut els := []Element{}
	mut seq := Sequence.new(new_tag(.universal, true, int(TagType.sequence))!, false,
		els)!

	seq.add_element(el0)!
	seq.add_element(el1)!

	mut pa_length := 0
	pa_length += el0.packed_length()
	pa_length += el1.packed_length()
}

fn PaData.unpack(src []u8) !PaData {
	if src.len < 2 {
		return error('src underflow')
	}
	seq, n := Sequence.decode(src, 0)!
	assert seq.elements.len == 2
}

struct KdcReqBody {
	kdc_options KDCOptions
	cname       PrincipalName
	realm       Realm
	sname       PrincipalName
	from        KerberosTime
	till        KerberosTime
	rtime       KerberosTime
	nonce       u32
	etype       []u32
	addresses   []HostAddress
	eauth_data  EncryptedData
	add_tickets []Ticket
}

// HostAddress     ::= SEQUENCE  {
//           addr-type       [0] Int32,
//           address         [1] OCTET STRING
//   }
struct HostAddress {
	addr_type int
	address   asn1.OctetString
}

fn (ha HostAddress) encode(mut out []u8) ! {
	mut seq := Sequence.new(false)!
	el1 := asn1.Integer.from_i64(ha.addr_type)!
	ctx1 := TaggedType.explicit_context(el1, 0)!
	ctx2 := TaggedType.explicit_context(ha.address, 1)!

	seq.add_element(ctx1)!
	seq.add_element(ctx2)!

	seq.encode(mut out)!
}

fn HostAddress.decode(src []u8) !(HostAddress, i64) {
	seq, n := Sequence.decode(src, 0)!
	els := seq.elements()!

	// el0 is rawelement of tagged type
	el0 := els[0] as RawElement
	el1 := els[1] as RawElement
	// should integer
	expected_inner0, _ := Integer.decode(el0.payload)!
	expected_inner1, _ := OctetString.decode(el1.payload)!
	return HostAddress{
		addr_type: expected_inner0.int()
		address: expected_inner1
	}, n
}

// EncryptedData   ::= SEQUENCE {
//           etype   [0] Int32 -- EncryptionType --,
//           kvno    [1] UInt32 OPTIONAL,
//           cipher  [2] OCTET STRING -- ciphertext
//   }
// minimal bytes to represent this structure, because etype and cipher should present
// explicit integer : 5 bytes + explicit octet cipher 4 + sequence header 2 = 11
struct EncryptedData {
	tag    asn1.Tag = asn1.new_tag(.universal, true, int(asn1.TagType.sequence)) or { panic(err) }
	etype  int
	kvno   ?u32 = none // OPTIONAL
	cipher asn1.OctetString
}

fn (e EncryptedData) tag() asn1.Tag {
	return e.tag
}

fn (e EncryptedData) length(p Params) int {
	mut n := 0
	el0 := TaggedType.explicit_context(asn1.Int.from_i64(e.etype), 0)!
	// el1 := TaggedType.explicit_context(asn1.Int.from_i64(e.kvno), 1)!
	el2 := TaggedType.explicit_context(e.cipher, 2)!

	n += el0.packed_length(p)
	if e.kvno != none {
		el1 := TaggedType.explicit_context(asn1.Int.from_i64(e.kvno), 1)!
		n += el1.packed_length(p)
	}
	n += el2.packed_length(p)

	return n
}

fn (e EncryptedData) payload(p Params) ![]u8 {
	mut out := []u8{}
	el0 := TaggedType.explicit_context(asn1.Int.from_i64(e.etype), 0)!
	el2 := TaggedType.explicit_context(e.cipher, 2)!
	el0.encode(mut out, p)!
	if e.kvno != none {
		el1 := TaggedType.explicit_context(asn1.Int.from_i64(e.kvno), 1)!
		el1.encode(mut out, p)!
	}
	el2.encode(mut out, p)!

	return out
}

fn (e EncryptedData) encode(mut out []u8, p Params) ! {
	e.tag().encode(mut out, p)!
	length := Length.from_i64(e.length(p))!
	length.encode(mut out, p)!
	out << e.payload(p)!
}

fn EncryptedData.decode(src []u8, loc i64, p Params) !(EncryptedData, i64) {
	if src.len < 11 {
		return error('EncryptedData: bytes underflow')
	}
	if loc > src.len {
		return error('EncryptedData: loc overflow')
	}
	tag, pos := Tag.decode(src, loc, p)!
	if tag.class() != .universal && !tag.is_constructed()
		&& tag.tag_number() != int(asn1.TagType.sequence) {
		return error('EncryptedData: check tag failed')
	}
	if pos > src.len {
		return error('EncryptedData: pos overflow')
	}
	length, idx := Length.decode(src, pos, p)!
	if length == 0 {
		return error('EncryptedData: length should != 0')
	}
	if idx > src.len || idx + length > src.len {
		return error('EncryptedData: overflow')
	}
	// sequence elements contents
	contents := unsafe { src[idx..idx + length] }
	els := asn1.ElementList.from_bytes(src)!
	if els.len < 2 {
		return error('ElementList < 2')
	}

	// check if optional element is present
	kvno_present := if els.len == 3 { true } else { false }
	els0 := els[0] as TaggedType // would panic if not hold TaggedType
	els1 := if kvno_present { els[1] as TaggedType } else { none }
	els2 := els[2] as asn1.OctetString
	// check the result
	ed := EncryptedData{
		etype: (els0.inner as Int64).value() // etype is int
		kvno: (els1 as Int64).value() //
		cipher: els2
	}
	return ed, idx + length
}

// Ticket          ::= [APPLICATION 1] SEQUENCE {
//    tkt-vno         [0] INTEGER (5),
//    realm           [1] Realm,
//    sname           [2] PrincipalName,
//    enc-part        [3] EncryptedData -- EncTicketPart
// }
struct Ticket {
	tkt_vno  int = 5
	realm    Realm
	sname    PrincipalName
	enc_part EncryptedData
}

type KerberosTime = asn1.GeneralizedTime // without fractional seconds

fn KerberosTime.from_string(s string) !KerberosTime {
	g := asn1.GeneralizedTime.from_string(s)!
	return KerberosTime(g)
}

// use KerberosString mechanism
type Realm = KerberosString

fn Realm.from_string(s string) !Realm {
	ret := KerberosString.from_string(s)
	return Realm(s)
}

fn (r Realm) tag() asn1.Tag {
	return asn1.new_tag(.universal, false, int(asn1.TagType.generalstring)) or { panic(err) }
}

// type KerberosString = GeneralString
struct KerberosString {
	tag   asn1.Tag = asn1.new_tag(.universal, false, int(asn1.TagType.generalstring))
	value string
}

fn valid_kerberos_string(s string) bool {
	if s.is_ascii() {
		return true
	}
	return false
}

fn KerberosString.from_string(s string) !KerberosString {
	if !valid_kerberos_string(s) {
		return error('not valid kerberos string')
	}
	return KerberosString{
		value: s
	}
}

fn KerberosString.from_bytes(b []bytes) !KerberosString {
	if !valid_kerberos_string(b.bytestr()) {
		return error('not valid kerberos string')
	}
	return KerberosString{
		value: b.bytestr()
	}
}

fn (k KerberosString) tag() asn1.Tag {
	return k.tag
}

// your validation logic here
fn (k KerberosString) valid() bool {
	if valid_kerberos_string(k.value) {
		return true
	}
	return false
}

fn (k KerberosString) encode(mut out []u8, p asn1.Params) ! {
	// do your validation check for KerberosString type
	if !k.valid() {
		return error('not valid KerberosString')
	}
	k.tag().encode(mut out, p)!
	bytes := k.value.bytes()
	length := Length.from_i64(bytes.len)!
	length.encode(mut out, p)!
	out << bytes
}

fn KerberosString.decode(src []u8, loc i64, p asn1.Params) !(KerberosString, i64) {
	if src.len < 2 {
		return error('src underflow')
	}
	tag, pos := Tag.decode(src, loc, p)!
	if tag.tag_number() != int(asn1.TagType.generalstring) {
		return error('bad tag')
	}
	if pos > src.len {
		return error('truncated input')
	}

	length, next := Length.decode(src, pos, p)!
	if length == 0 {
		return KerberosString.from_string('')!, next
	}
	if next > src.len || next + length > src.len {
		return error('truncated input')
	}
	out := unsafe { src[next..next + length] }
	// validates
	ks := KerberosString.from_bytes(out)!
	return ks, next + length
}

// KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
//                      -- minimum number of bits shall be sent,
//                      -- but no fewer than 32
const min_kerberosflags_size = 32

struct KerberosFlags {
	tag   asn1.Tag = asn1.new_tag(.universal, false, int(asn1.TagType.bitstring)) or { panic(err) }
	value asn1.BitString
}

fn KerberosFlags.new(value BitString) !KerberosFlags {
	return KerberosFlags{
		value: value
	}
}

fn (kf KerberosFlags) tag() asn1.Tag {
	return kf.tag
}

fn (kf KerberosFlags) payload(p Params) ![]u8 {
	return kf.value.payload(p)
}

fn (kf KerberosFlags) payload_length(p Params) int {
	return kf.value.payload_length(p)
}

fn (kf KerberosFlags) packed_length(p Params) int {
	return kf.value.packed_length(p)
}

fn (kf KerberosFlags) encode(mut out []u8, p asn1.Params) ! {
	kf.value.encode(mut out, p)!
}

fn KerberosFlags.decode(src []u8, loc i64, p Params) !(KerberosFlags, i64) {
	b, n := BitString.decode(src, loc, p)!
	return KerberosFlags.new(b), n
}

// PrincipalName   ::= SEQUENCE {
//    name-type       [0] Int32,
//    name-string     [1] SEQUENCE OF KerberosString
// }
struct PrincipalName {
	tag         asn1.Tag = asn1.new_tag(.universal, true, int(TagType.sequence)) or { panic(err) }
	name_type   int
	name_string []KerberosString
}

fn (pn PrincipalName) tag() asn1.Tag {
	return pn.tag
}

fn (pn PrincipalName) payload(p asn1.Params) ![]u8 {
	el0 := asn1.TaggedType.explicit_context(asn1.Int64.from_i64(pn.name_type), 0)!
	// second element is SEQUENCEOF
	mut seq2 := asn1.Sequence.new(true)
	for item in pn.name_string {
		ks := asn1.KerberosString.from_string(item)!
		seq2.add_element(obj)!
	}
	el1 := asn1.TaggedType.explicit_context(seq2, 1)

	mut out := []u8{}
	el0.encode(mut out, p)!
	el1.encode(mut out, p)!
	return out
}

fn (pn PrincipalName) length(p asn1.Params) int {
	mut n := 0

	n += pn.payload(p)!.len
	return n
}

fn (pn PrincipalName) packed_length(p asn1.Params) int {
	mut n := 0

	n += pn.tag().packed_length(p)
	payload := pn.payload(p)!
	len := Length.from_i64(payload.len) or { panic(err) }
	n += len.packed_length(p)
	n += payload.len

	return n
}

fn (pn PrincipalName) encode(mut dst []u8, p asn1.Params) ! {
	mut seq1 := asn1.Sequence.new(false)
	int1 := asn1.Int64.from_i64(pn.name_type)
	// explicit context of integer content
	exp1 := asn1.TaggedType.explicit_context(int1, 0)
	seq1.add_element(exp1)!

	// second element is SEQUENCEOF
	mut seq2 := asn1.Sequence.new(true)
	for item in pn.name_string {
		ks := asn1.KerberosString.from_string(item)!
		seq2.add_element(obj)!
	}
	exp2 := asn1.TaggedType.explicit_context(seq2, 1)
	seq1.add_element(exp2)!

	seq1.encode(mut dst, p)!
}

fn PrincipalName.decode(src []u8, loc i64, p asn1.Params) !(PrincipalName, i64) {
	// PrincipalName is sequence
	seq, pos := Sequence.decode(src, loc, p)!
	// when src.len is exact length of PrincipalName data, maybe stream one
	assert pos == src.len
	assert seq.elements.len == 2 
	// all sequence elements when parsed, if has not .universal class
	// is parsed as RawElement
	els := seq.elements()!

	// first element is exlicit context of integer
	re0 := els[0] as RawElement 
	re0 := els[1] as RawElement

	tag0 := asn1.new_tag(.universal, false, 2)!
	tt0 := re0.as_tagged(.explicit, tag0)!
	el0 := (tt0 as asn1.Int64).value()
}

fn main() {
	// Basically this is a Kerberos PrincipalName data you sent to me

	p := PrincipalName{
		name_type: asn1.AsnInteger(1)
		name_string: [KerberosString('bobba-fett')]
	}

	out := p.encode()!
	assert out == data // should assert to true
}
