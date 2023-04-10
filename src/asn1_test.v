module asn1

import math.big
import encoding.hex

fn test_parse_der_match_length() ! {
	// from https://en.wikipedia.org/wiki/ASN.1#Example_encoded_in_DER
	data := [u8(0x30), 0x13, 0x02, 0x01, 0x05, 0x16, 0x0e, 0x41, 0x6e, 0x79, 0x62, 0x6f, 0x64,
		0x79, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x3f]

	out := der_decode(data)!
	assert out.length() == 19 // 0x13
	assert out.tag().class == .universal
	assert out.tag().constructed == true
	assert out.tag().number == 16

	seq := out.as_sequence()!
	assert seq.elements.len == 2
	el0 := seq.elements[0].as_integer()!
	el1 := seq.elements[1].as_ia5string()!

	assert el0.tag().number == int(TagType.integer)
	assert el1.tag().number == int(TagType.ia5string)
	assert el0.str() == 'INTEGER 5'
	assert el1 == 'Anybody there?'

	/*
	30 — type tag indicating SEQUENCE
		13 — length in octets of value that follows
  			02 — type tag indicating INTEGER
  				01 — length in octets of value that follows
    			05 — value (5)
 			16 — type tag indicating IA5String
     			(IA5 means the full 7-bit ISO 646 set, including variants,
      			but is generally US-ASCII)
  				0e — length in octets of value that follows
    			41 6e 79 62 6f 64 79 20 74 68 65 72 65 3f — value ("Anybody there?")
	*/
}

fn test_parse_der_contains_discarded_bytes() ! {
	// the length tell 0x13, but two last bytes was added and should trigger malformed bytes.
	data := [u8(0x30), 0x13, 0x02, 0x01, 0x05, 0x16, 0x0e, 0x41, 0x6e, 0x79, 0x62, 0x6f, 0x64,
		0x79, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x3f, 0xff, 0xff]

	out := der_decode(data) or {
		assert err == error('malformed bytes, contains discarded bytes')
		return
	}

	assert out.length() == 19 // 0x13
}

fn test_parse_x509_ed25519_certificate() ! {
	// blindly parse data
	// data from https://lapo.it/asn1js , with data X.509 certificate based Curve25519 (as per RFC 8410) loaded
	data := [u8(0x30), 0x82, 0x01, 0x7F, 0x30, 0x82, 0x01, 0x31, 0xA0, 0x03, 0x02, 0x01, 0x02,
		0x02, 0x14, 0x7C, 0x8E, 0x64, 0x49, 0xD7, 0x0E, 0xD9, 0x2D, 0x3E, 0x2E, 0x4A, 0x5D, 0x2F,
		0x76, 0xF6, 0x55, 0x42, 0x46, 0xD7, 0x46, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x30,
		0x35, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x49, 0x54, 0x31,
		0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x06, 0x4D, 0x69, 0x6C, 0x61, 0x6E,
		0x6F, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0C, 0x54, 0x65, 0x73,
		0x74, 0x20, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x30,
		0x30, 0x39, 0x30, 0x32, 0x31, 0x33, 0x32, 0x35, 0x32, 0x36, 0x5A, 0x17, 0x0D, 0x33, 0x30,
		0x30, 0x39, 0x30, 0x32, 0x31, 0x33, 0x32, 0x35, 0x32, 0x36, 0x5A, 0x30, 0x35, 0x31, 0x0B,
		0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x49, 0x54, 0x31, 0x0F, 0x30, 0x0D,
		0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x06, 0x4D, 0x69, 0x6C, 0x61, 0x6E, 0x6F, 0x31, 0x15,
		0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0C, 0x54, 0x65, 0x73, 0x74, 0x20, 0x65,
		0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
		0x03, 0x21, 0x00, 0x3B, 0xA9, 0x2F, 0xFD, 0xCB, 0x17, 0x66, 0xDE, 0x40, 0xA2, 0x92, 0xF7,
		0x93, 0xDE, 0x30, 0xF8, 0x0A, 0x23, 0xA8, 0x31, 0x21, 0x5D, 0xD0, 0x07, 0xD8, 0x63, 0x24,
		0x2E, 0xFF, 0x68, 0x21, 0x85, 0xA3, 0x53, 0x30, 0x51, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D,
		0x0E, 0x04, 0x16, 0x04, 0x14, 0x6B, 0xA5, 0xBD, 0xCF, 0x9D, 0xFA, 0x23, 0x59, 0x78, 0x12,
		0x64, 0x17, 0xAE, 0x1E, 0x72, 0xD8, 0x9A, 0x80, 0x4A, 0xE8, 0x30, 0x1F, 0x06, 0x03, 0x55,
		0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x6B, 0xA5, 0xBD, 0xCF, 0x9D, 0xFA, 0x23,
		0x59, 0x78, 0x12, 0x64, 0x17, 0xAE, 0x1E, 0x72, 0xD8, 0x9A, 0x80, 0x4A, 0xE8, 0x30, 0x0F,
		0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF,
		0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x41, 0x00, 0x6F, 0x73, 0x77, 0xBE, 0x28,
		0x96, 0x5A, 0x33, 0x36, 0xD7, 0xE5, 0x34, 0xFD, 0x90, 0xF3, 0xFD, 0x40, 0x7F, 0x1F, 0x02,
		0xF9, 0x00, 0x57, 0xF2, 0x16, 0x0F, 0x16, 0x6B, 0x04, 0xBF, 0x65, 0x84, 0xB6, 0x98, 0xD2,
		0xD0, 0xD2, 0xBF, 0x4C, 0xD6, 0x6F, 0x0E, 0xB6, 0xE2, 0xE8, 0x9D, 0x04, 0xA3, 0xE0, 0x99,
		0x50, 0xF9, 0xC2, 0x6D, 0xDE, 0x73, 0xAD, 0x1D, 0x35, 0x57, 0x85, 0x65, 0x86, 0x06]

	tag, pos := read_tag(data, 0)!
	length, next := decode_length(data, pos)!
	assert tag.number == 16
	assert length == 383
	assert next == 4

	out := der_decode(data)!
	seq := out.as_sequence()!

	assert seq.elements.len == 3
	el0 := seq.elements[0].as_sequence()!
	assert el0.elements.len == 8

	el1 := seq.elements[1].as_sequence()!
	assert el1.elements.len == 1

	el2 := seq.elements[2].as_bitstring()!
	assert el2.length() == 65
}

/*
Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

TBSCertificate  ::=  SEQUENCE  {
     version         [0]  EXPLICIT Version DEFAULT v1,
     serialNumber         CertificateSerialNumber,
     signature            AlgorithmIdentifier,
     issuer               Name,SubjectPublicKeyInfo
     validity             Validity,
     subject              Name,
     subjectPublicKeyInfo SubjectPublicKeyInfo,
     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                          -- If present, version MUST be v2 or v3
     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                          -- If present, version MUST be v2 or v3
     extensions      [3]  EXPLICIT Extensions OPTIONAL
                          -- If present, version MUST be v3 }

Validity ::= SEQUENCE {
     notBefore      Time,
     notAfter       Time }

AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm   OBJECT IDENTIFIER,
        parameters  ANY DEFINED BY algorithm OPTIONAL
      }
*/

fn test_x509_certificate_version() ! {
	// version         [0]  EXPLICIT Version DEFAULT v1,
	// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
	val := new_integer(2)
	version := new_explicit_context(val, 0)

	out := version.encode()!
	exp := [u8(0xA0), 0x03, 0x02, 0x01, 0x02]

	assert out == exp
}

fn test_x509_certificate_signature() ! {
	// signature            AlgorithmIdentifier,
	// AlgorithmIdentifier  ::=  SEQUENCE  {
	//    algorithm   OBJECT IDENTIFIER,
	//    parameters  ANY DEFINED BY algorithm OPTIONAL
	//  }
	oid := new_oid_from_string('1.3.101.112')!

	mut seq := new_sequence()
	seq.add(oid)

	out := seq.encode()!
	exp := [u8(0x30), 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70]

	assert out == exp
	back := der_decode(exp)!
	seqback := back.as_sequence()!
	assert seqback == seq
}

fn test_x509_certificate_serialnumber() ! {
	// serialNumber         CertificateSerialNumber,
	// CertificateSerialNumber  ::=  INTEGER
	sn := new_integer(big.integer_from_string('711090297755414526861352146244170174161660335942')!)

	out := sn.encode()!
	exp := [u8(0x02), 0x14, 0x7C, 0x8E, 0x64, 0x49, 0xD7, 0x0E, 0xD9, 0x2D, 0x3E, 0x2E, 0x4A, 0x5D,
		0x2F, 0x76, 0xF6, 0x55, 0x42, 0x46, 0xD7, 0x46]

	assert out == exp
}

fn test_x509_certificate_issuer() ! {
	/*
	Name ::= CHOICE { rdnSequence  RDNSequence }
	RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
	RelativeDistinguishedName ::=
     	SET SIZE (1..MAX) OF AttributeTypeAndValue
	*/

	/*
	AttributeTypeAndValue ::= SEQUENCE {
    type     AttributeType,
    value    AttributeValue }
	*/

	// AttributeType is an OID, while the AttributeValue is a DirectoryString
	// (specifically, a CHOICE between TeletexString, PrintableString, UniversalString, UTF8String and BMPString)

	// First AttributeTypeAndValue
	attrtype0 := new_oid_from_string('2.5.4.6')!
	assert attrtype0.encode()! == [u8(0x06), 0x03, 0x55, 0x04, 0x06]

	attrvalue0 := new_printable_string('IT')!
	assert attrvalue0.encode()! == [u8(0x13), 0x02, 0x49, 0x54]

	seq0 := new_sequence_from_multiencoder([attrtype0, attrvalue0])!
	assert seq0.encode()! == [u8(0x30), 0x09, u8(0x06), 0x03, 0x55, 0x04, 0x06, u8(0x13), 0x02,
		0x49, 0x54]

	set0 := new_set_from_multiencoder([seq0])!
	assert set0.encode()! == [u8(0x31), 0x0B, u8(0x30), 0x09, u8(0x06), 0x03, 0x55, 0x04, 0x06,
		u8(0x13), 0x02, 0x49, 0x54]

	// 2nd AttributeTypeAndValue
	attrtype1 := new_oid_from_string('2.5.4.7')!
	assert attrtype1.encode()! == [u8(0x06), 0x03, 0x55, 0x04, 0x07]

	attrvalue1 := new_utf8string('Milano')!
	assert attrvalue1.encode()! == [u8(0x0C), 0x06, 0x4D, 0x69, 0x6C, 0x61, 0x6E, 0x6F]

	seq1 := new_sequence_from_multiencoder([attrtype1, attrvalue1])!
	assert seq1.encode()! == [u8(0x30), 0x0d, u8(0x06), 0x03, 0x55, 0x04, 0x07, u8(0x0C), 0x06,
		0x4D, 0x69, 0x6C, 0x61, 0x6E, 0x6F]

	set1 := new_set_from_multiencoder([seq1])!
	assert set1.encode()! == [u8(0x31), 0x0F, u8(0x30), 0x0d, u8(0x06), 0x03, 0x55, 0x04, 0x07,
		u8(0x0C), 0x06, 0x4D, 0x69, 0x6C, 0x61, 0x6E, 0x6F]

	// 3rd AttributeTypeAndValue
	attrtype2 := new_oid_from_string('2.5.4.3')!
	assert attrtype2.encode()! == [u8(0x06), 0x03, 0x55, 0x04, 0x03]

	attrvalue2 := new_utf8string('Test ed25519')!
	assert attrvalue2.encode()! == [u8(0x0C), 0x0c, 0x54, 0x65, 0x73, 0x74, 0x20, 0x65, 0x64, 0x32,
		0x35, 0x35, 0x31, 0x39]

	seq2 := new_sequence_from_multiencoder([attrtype2, attrvalue2])!
	assert seq2.encode()! == [u8(0x30), 0x13, u8(0x06), 0x03, 0x55, 0x04, 0x03, u8(0x0C), 0x0c,
		0x54, 0x65, 0x73, 0x74, 0x20, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39]

	set2 := new_set_from_multiencoder([seq2])!
	assert set2.encode()! == [u8(0x31), 0x15, u8(0x30), 0x13, u8(0x06), 0x03, 0x55, 0x04, 0x03,
		u8(0x0C), 0x0c, 0x54, 0x65, 0x73, 0x74, 0x20, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39]

	issuerseq := new_sequence_from_multiencoder([set0, set1, set2])!
	expissuer := [u8(0x30), 0x35, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
		0x49, 0x54, 0x31, 0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x06, 0x4D, 0x69,
		0x6C, 0x61, 0x6E, 0x6F, u8(0x31), 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C,
		0x0C, 0x54, 0x65, 0x73, 0x74, 0x20, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39]

	assert issuerseq.encode()! == expissuer
}

fn test_x509_certificate_validity() ! {
	// Validity ::= SEQUENCE {
	// notBefore      Time,
	// notAfter       Time }

	notbefore := new_utctime('200902132526Z')!
	assert notbefore.encode()! == [u8(0x17), 0x0D, 0x32, 0x30, 0x30, 0x39, 0x30, 0x32, 0x31, 0x33,
		0x32, 0x35, 0x32, 0x36, 0x5A]

	notafter := new_utctime('300902132526Z')!
	assert notafter.encode()! == [u8(0x17), 0x0D, 0x33, 0x30, 0x30, 0x39, 0x30, 0x32, 0x31, 0x33,
		0x32, 0x35, 0x32, 0x36, 0x5A]

	validity := new_sequence_from_multiencoder([notbefore, notafter])!
	assert validity.encode()! == [u8(0x30), 0x1e, u8(0x17), 0x0D, 0x32, 0x30, 0x30, 0x39, 0x30,
		0x32, 0x31, 0x33, 0x32, 0x35, 0x32, 0x36, 0x5A, u8(0x17), 0x0D, 0x33, 0x30, 0x30, 0x39,
		0x30, 0x32, 0x31, 0x33, 0x32, 0x35, 0x32, 0x36, 0x5A]
}

fn test_x509_certificate_subject() ! {
	// subject and issuer helds the same values
	/*
	Name ::= CHOICE { rdnSequence  RDNSequence }
	RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
	RelativeDistinguishedName ::=
     	SET SIZE (1..MAX) OF AttributeTypeAndValue
	*/

	/*
	AttributeTypeAndValue ::= SEQUENCE {
    type     AttributeType,
    value    AttributeValue }
	*/

	// AttributeType is an OID, while the AttributeValue is a DirectoryString
	// (specifically, a CHOICE between TeletexString, PrintableString, UniversalString, UTF8String and BMPString)

	// First AttributeTypeAndValue
	attrtype0 := new_oid_from_string('2.5.4.6')!
	assert attrtype0.encode()! == [u8(0x06), 0x03, 0x55, 0x04, 0x06]

	attrvalue0 := new_printable_string('IT')!
	assert attrvalue0.encode()! == [u8(0x13), 0x02, 0x49, 0x54]

	seq0 := new_sequence_from_multiencoder([attrtype0, attrvalue0])!
	assert seq0.encode()! == [u8(0x30), 0x09, u8(0x06), 0x03, 0x55, 0x04, 0x06, u8(0x13), 0x02,
		0x49, 0x54]

	set0 := new_set_from_multiencoder([seq0])!
	assert set0.encode()! == [u8(0x31), 0x0B, u8(0x30), 0x09, u8(0x06), 0x03, 0x55, 0x04, 0x06,
		u8(0x13), 0x02, 0x49, 0x54]

	// 2nd AttributeTypeAndValue
	attrtype1 := new_oid_from_string('2.5.4.7')!
	assert attrtype1.encode()! == [u8(0x06), 0x03, 0x55, 0x04, 0x07]

	attrvalue1 := new_utf8string('Milano')!
	assert attrvalue1.encode()! == [u8(0x0C), 0x06, 0x4D, 0x69, 0x6C, 0x61, 0x6E, 0x6F]

	seq1 := new_sequence_from_multiencoder([attrtype1, attrvalue1])!
	assert seq1.encode()! == [u8(0x30), 0x0d, u8(0x06), 0x03, 0x55, 0x04, 0x07, u8(0x0C), 0x06,
		0x4D, 0x69, 0x6C, 0x61, 0x6E, 0x6F]

	set1 := new_set_from_multiencoder([seq1])!
	assert set1.encode()! == [u8(0x31), 0x0F, u8(0x30), 0x0d, u8(0x06), 0x03, 0x55, 0x04, 0x07,
		u8(0x0C), 0x06, 0x4D, 0x69, 0x6C, 0x61, 0x6E, 0x6F]

	// 3rd AttributeTypeAndValue
	attrtype2 := new_oid_from_string('2.5.4.3')!
	assert attrtype2.encode()! == [u8(0x06), 0x03, 0x55, 0x04, 0x03]

	attrvalue2 := new_utf8string('Test ed25519')!
	assert attrvalue2.encode()! == [u8(0x0C), 0x0c, 0x54, 0x65, 0x73, 0x74, 0x20, 0x65, 0x64, 0x32,
		0x35, 0x35, 0x31, 0x39]

	seq2 := new_sequence_from_multiencoder([attrtype2, attrvalue2])!
	assert seq2.encode()! == [u8(0x30), 0x13, u8(0x06), 0x03, 0x55, 0x04, 0x03, u8(0x0C), 0x0c,
		0x54, 0x65, 0x73, 0x74, 0x20, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39]

	set2 := new_set_from_multiencoder([seq2])!
	assert set2.encode()! == [u8(0x31), 0x15, u8(0x30), 0x13, u8(0x06), 0x03, 0x55, 0x04, 0x03,
		u8(0x0C), 0x0c, 0x54, 0x65, 0x73, 0x74, 0x20, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39]

	issuerseq := new_sequence_from_multiencoder([set0, set1, set2])!
	expissuer := [u8(0x30), 0x35, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
		0x49, 0x54, 0x31, 0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x06, 0x4D, 0x69,
		0x6C, 0x61, 0x6E, 0x6F, u8(0x31), 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C,
		0x0C, 0x54, 0x65, 0x73, 0x74, 0x20, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39]

	assert issuerseq.encode()! == expissuer

	backissuer := der_decode(expissuer)!

	issuer := backissuer.as_sequence()!

	assert issuer == issuerseq
}

fn test_x509_certificate_subjectpublickeyinfo() ! {
	/*
	SubjectPublicKeyInfo  ::=  SEQUENCE  {
    algorithm            AlgorithmIdentifier,
    subjectPublicKey     BIT STRING  }
	*/

	oid := new_oid_from_string('1.3.101.112')!
	algo := new_sequence_from_multiencoder([oid])!
	subpubkey := new_bitstring_from_bytes([u8(0x00), 0x3B, 0xA9, 0x2F, 0xFD, 0xCB, 0x17, 0x66,
		0xDE, 0x40, 0xA2, 0x92, 0xF7, 0x93, 0xDE, 0x30, 0xF8, 0x0A, 0x23, 0xA8, 0x31, 0x21, 0x5D,
		0xD0, 0x07, 0xD8, 0x63, 0x24, 0x2E, 0xFF, 0x68, 0x21, 0x85])!

	spkinfo := new_sequence_from_multiencoder([algo, subpubkey])!
	expskpinfo := [u8(0x30), 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
		0x3B, 0xA9, 0x2F, 0xFD, 0xCB, 0x17, 0x66, 0xDE, 0x40, 0xA2, 0x92, 0xF7, 0x93, 0xDE, 0x30,
		0xF8, 0x0A, 0x23, 0xA8, 0x31, 0x21, 0x5D, 0xD0, 0x07, 0xD8, 0x63, 0x24, 0x2E, 0xFF, 0x68,
		0x21, 0x85]

	assert spkinfo.encode()! == expskpinfo
}

fn test_x509_certificate_extensions() ! {
	// extensions      [3]  EXPLICIT Extensions OPTIONAL
	//                      -- If present, version MUST be v3 }
	// subjectKeyIdentifier OID
	// KeyIdentifier OCTETSTRING
	subkeyid := new_oid_from_string('2.5.29.14')!

	keyval := hex.decode('6BA5BDCF9DFA235978126417AE1E72D89A804AE8')! //[]u8
	oct := new_octetstring(keyval.bytestr())

	expoct := [u8(0x04), 0x14, 0x6B, 0xA5, 0xBD, 0xCF, 0x9D, 0xFA, 0x23, 0x59, 0x78, 0x12, 0x64,
		0x17, 0xAE, 0x1E, 0x72, 0xD8, 0x9A, 0x80, 0x4A, 0xE8]

	assert oct.encode()! == expoct
	// encapsulated keyval, preserve tag value
	extnkeyvalue := hex.decode('04146BA5BDCF9DFA235978126417AE1E72D89A804AE8')! //[]u8
	extoct := new_octetstring(extnkeyvalue.bytestr())
	assert extoct.encode()! == [u8(0x04), 0x16, u8(0x04), 0x14, 0x6B, 0xA5, 0xBD, 0xCF, 0x9D, 0xFA,
		0x23, 0x59, 0x78, 0x12, 0x64, 0x17, 0xAE, 0x1E, 0x72, 0xD8, 0x9A, 0x80, 0x4A, 0xE8]

	mut seq := new_sequence()
	seq.add_multi([oct, extoct])

	expseq := [u8(0x30), 0x14 + 2 + 0x16 + 2, u8(0x04), 0x14, 0x6B, 0xA5, 0xBD, 0xCF, 0x9D, 0xFA,
		0x23, 0x59, 0x78, 0x12, 0x64, 0x17, 0xAE, 0x1E, 0x72, 0xD8, 0x9A, 0x80, 0x4A, 0xE8, u8(0x04),
		0x16, u8(0x04), 0x14, 0x6B, 0xA5, 0xBD, 0xCF, 0x9D, 0xFA, 0x23, 0x59, 0x78, 0x12, 0x64,
		0x17, 0xAE, 0x1E, 0x72, 0xD8, 0x9A, 0x80, 0x4A, 0xE8]
	assert seq.encode()! == expseq

	// parsing back
	out := der_decode(expseq)!
	// cast encoder to seq
	cast := out.as_sequence()!

	assert cast == seq
}

fn test_encoder_casted_as_seq_and_boolean() ! {
	data := [u8(0x30), 0x06, 0x01, 0x01, 0x00, 0x01, 0x01, 0xff]
	out := der_decode(data)!

	seq := out.as_sequence()!
	assert typeof(seq).name == '${@MOD}.Sequence'
	assert seq.elements.len == 2

	el1 := seq.elements[0].as_boolean()!
	assert typeof(el1).name == '${@MOD}.Boolean'
	assert el1 == Boolean(false)

	el2 := seq.elements[1].as_boolean()!
	assert el2 == Boolean(true)
	assert typeof(el2).name == '${@MOD}.Boolean'

	// should error not bitstring type
	c := out.as_bitstring() or {
		assert err == error('not bitstring type')
		return
	}
}
