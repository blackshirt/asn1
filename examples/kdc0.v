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
	Sequence
	pd_type  asn1.AsnInteger
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
	mut seq := Sequence.new(new_tag(.universal, true, int(TagType.sequence)!, false, els)!
	
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
	tag, pos := asn1.read_tag(src, 0)!
	if tag.number != int(asn1.TagType.sequence) {
		return error('bad tag')
	}
	if pos > src.len {
		return error('truncated input')
	}

	length, next := asn1.decode_length(src, pos)!
	if next > src.len || next + length > src.len {
		return error('truncated input')
	}
	bytes := unsafe { src[next..next + length] }
	// parse bytes contents
	// read first content, explicit integer
	// the all result process should be validated
	ttag, tpos := asn1.read_tag(bytes, 0)!
	tlength, tnext := asn1.decode_length(bytes, tpos)!
	sub1 := asn1.read_bytes(bytes, tnext, tlength)!
	// interpretes this as an integer
	ptype := AsnInteger.decode(sub1)!

	remaining_bytes := unsafe { bytes[tnext + tlength..bytes.len] }
	ttag1, tpos1 := asn1.read_tag(remaining_bytes, 0)!
	tlength1, tnext1 := asn1.decode_length(remaining_bytes, tpos1)!
	sub2 := asn1.read_bytes(remaining_bytes, tnext1, tlength1)!
	// as octet string 
	pvalue := OctetString.decode(sub2)

	ret := PaData{
		pd_type: ptype
		pd_value: pvalue
	}
	if !ret.valid() {
		return error('not valid PaData')
	}
	return ret
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
	addresses   HostAddresses
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

// EncryptedData   ::= SEQUENCE {
//           etype   [0] Int32 -- EncryptionType --,
//           kvno    [1] UInt32 OPTIONAL,
//           cipher  [2] OCTET STRING -- ciphertext
//   }
struct EncryptedData {
	etype  int
	kvno   u32
	cipher asn1.OctetString
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

type HostAddresses = []HostAddress
type KerberosTime = asn1.GeneralizedTime // without fractional seconds
type Realm = KerberosString

struct KerberosString {
	tag   asn1.Tag = asn1.new_tag(.universal, false, int(asn1.TagType.generalstring))
	value string
}

fn (k KerberosString) tag() asn1.Tag {
	return k.tag
}

// your validation logic here
fn (k KerberosString) valid() bool {
	return true
}

fn (k KerberosString) pack(mut out []u8, p asn1.Params) ! {
	// do your validation check for KerberosString type
	if !k.valid() {
		return error('not valid KerberosString')
	}
	k.tag().pack_to_asn1(mut out, p)!
	bytes := k.value.bytes()
	length := Length.from_i64(bytes.len)!
	length.pack_to_asn1(mut out, p)!
	out << bytes
}

fn KerberosString.unpack(src []u8, loc i64) !(KerberosString, i64) {
	if src.len < 2 {
		return error('src underflow')
	}
	tag, pos := asn1.read_tag(src, 0)!
	if tag.number != int(asn1.TagType.generalstring) {
		return error('bad tag')
	}
	if pos > src.len {
		return error('truncated input')
	}

	length, next := asn1.decode_length(src, pos)!

	if next > src.len || next + length > src.len {
		return error('truncated input')
	}
	out := unsafe { src[next..next + length] }
	// validates
	if !out.bytestr().is_ascii() {
		return error('contains invalid char')
	}
	ks := KerberosString{
		tag: tag
		value: out.bytestr()
	}
	if !ks.valid() {
		return error('not valid KerberosString')
	}
	return ks, next+length 
}

// KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
//                      -- minimum number of bits shall be sent,
//                      -- but no fewer than 32

// PrincipalName   ::= SEQUENCE {
//    name-type       [0] Int32,
//    name-string     [1] SEQUENCE OF KerberosString
// }
struct PrincipalName {
	name_type   asn1.AsnInteger
	name_string []KerberosString
}

fn (p PrincipalName) pack(mut dst []u8) ! {
	mut seq1 := asn1.new_sequence()
	int1 := asn1.new_integer(p.name_type)
	// explicit context of integer content
	exp1 := asn1.new_explicit_context(int1, 0)
	seq1.add(exp1)

	// second item
	mut seq2 := asn1.new_sequence()
	for item in p.name_string {
		obj := asn1.new_asn_object(asn1.Class.universal, false, 27, item.bytes())
		seq2.add(obj)
	}
	exp2 := asn1.new_explicit_context(seq2, 1)
	seq1.add(exp2)
	out := seq1.encode()!

	dst << out
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
