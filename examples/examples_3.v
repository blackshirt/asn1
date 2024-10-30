module main

// This examples is taken from ITU-T X.690 Information technology – ASN.1 encoding rules:
// Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and
// Distinguished Encoding Rules (DER) document.
//
// Especially from Annex A. Example of encodings of the document.

// from A.1 ASN.1 description of the record structure.
// The structure of the hypothetical personnel record is formally described below using ASN.1 specified in
// ITU-T Rec. X.680 | ISO/IEC 8824-1 for defining types.
//
// PersonnelRecord ::= [APPLICATION 0] IMPLICIT SET {
//      name            Name,
//      title           [0] VisibleString,
//      number          EmployeeNumber,
//      dateOfHire      [1] Date,
//      nameOfSpouse    [2] Name,
//      children        [3] IMPLICIT SEQUENCE OF ChildInformation DEFAULT {}
// }
//
// ChildInformation ::= SET {
//      name            Name,
//      dateOfBirth     [0] Date
// }
//
// Name ::= [APPLICATION 1] IMPLICIT SEQUENCE {
//      givenName       VisibleString,
//      initial         VisibleString,
//      familyName      VisibleString
// }
//
// EmployeeNumber ::= [APPLICATION 2] IMPLICIT INTEGER
// Date ::= [APPLICATION 3] IMPLICIT VisibleString -- YYYYMMDD
struct ChildInformation {
	name          Name
	date_of_birth Date @[context_specific;implicit;0]
}

fn (ci ChildInformation) tag() Tag {
	return asn1.default_set_tag 
}

fn (ci ChildInformation) payload() ![]u8 {
	mut out := []u8{}
	out << encode(ci.name)!
	out << encode_with_options(ci.date_of_birth, 'context_specific;implicit;0]')!

	return out 
}

type EmployeeNumber = asn1.Integer

fn (e EmployeeNumber) tag() asn1.Tag {
	return asn1.default_integer_tag
}

fn (e EmployeeNumber) payload() ![]u8 {
	v := e as asn1.Integer
	return v.payload()!
}

type Date = asn1.VisibleString

fn (d Date) tag() asn1.Tag {
	return asn1.default_visisblestring_tag
}

fn (d Date) payload() ![]u8 {
	v := d as asn1.VisibleString
	return v.payload()!
}

// You can write routine for encodes the Date or pass the options later.
fn encode_date(d Date) ![]u8 {
	// visiblestring tag = 26
	return asn1.encode_with_options(d, 'application:3;implicit;inner:26')
}

struct Name {
	given_name  asn1.VisibleString
	initial     asn1.VisibleString
	family_name asn1.VisibleString
}

fn (n Name) tag() asn1.Tag {
	return asn1.default_sequence_tag
}

fn (n Name) payload() ![]u8 {
	mut out := []u8{}
	out << asn1.encode(n.given_name)!
	out << asn1.encode(n.initial)!
	out << asn1.encode(n.family_name)!

	return out
}

// The value of John Smith's personnel record is formally described below using ASN.1.
// { name {givenName "John",initial "P",familyName "Smith"},
//		title 	"Director",
//		number 	51,
//		dateOfHire "19710917",
//		nameOfSpouse {givenName "Mary",initial "T",familyName "Smith"},
//		children {
//			{ name {givenName "Ralph",initial "T",familyName "Smith"},
//			  dateOfBirth "19571111"
//			},
//			{ name {givenName "Susan",initial "B",familyName "Jones"},
//			  dateOfBirth "19590717"
//			}
//		}
//	}

// Representation of this record value
// 60 8185
//		61 10 	1A 94 'John'
//				iA 01 'P'
//				1A 05 'Smith'
//		A0 0A	1A 08 'Director'
//		42 01	33
//		A1 0A	43 08 '19710917'
//		A2 12	61 10 	1A 	04 'Mary'
//						1A	01	'T'
//						1A	05	'Smith'
//		A3 42	31 1F	61	11	1A 05 'Ralph'
//								1A 01 'T'
//								1A 05 'Smith'
//						A0	0A	43 08 '19571111'	
//				31 1F	61	11	1A 05 'Susan'
//								1A 01 'B'
//								1A 05 'Jones'
//						A0	0A	45 08 '19590717'
