module main

import asn1

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

type KDCOptions = KerberosFlags

type KerberosTime = asn1.GeneralizedTime // without fractional seconds

fn KerberosTime.from_string(s string) !KerberosTime {
	g := asn1.GeneralizedTime.from_string(s)!
	return KerberosTime(g)
}

// use KerberosString mechanism
type Realm = KerberosString

fn Realm.from_string(s string) !Realm {
	ret := KerberosString.from_string(s)!
	return Realm(s)
}

fn (r Realm) tag() asn1.Tag {
	return asn1.new_tag(.universal, false, int(asn1.TagType.generalstring)) or { panic(err) }
}

// type KerberosString = GeneralString
struct KerberosString {
	tag   asn1.Tag = asn1.new_tag(.universal, false, int(asn1.TagType.generalstring)) or { panic(err) }
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

fn KerberosString.from_bytes(b []u8) !KerberosString {
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
	length := asn1.Length.from_i64(bytes.len)!
	length.encode(mut out, p)!
	out << bytes
}

fn KerberosString.decode(src []u8, loc i64, p asn1.Params) !(KerberosString, i64) {
	tlv, next := asn1.Tlv.read(src, loc, p)!
	if tlv.tag.tag_number() != int(asn1.TagType.generalstring) {
		return error('bad tag')
	}
	if tlv.length() == 0 {
		return KerberosString.from_string('')!, next
	}

	// validates
	ks := KerberosString.from_bytes(tlv.content())!
	return ks, next
}

