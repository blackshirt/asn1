module main

import asn1

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
struct PersonnelRecord {
	name           Name
	title          asn1.VisibleString // @[context_specific: 0; explicit; inner: 26]
	number         EmployeeNumber
	date_of_hire   Date
	name_of_spouse Name
	children       asn1.SequenceOf[ChildInformation]
}

fn (pr PersonnelRecord) payload() ![]u8 {
	mut out := []u8{}
	out << asn1.encode(pr.name)!
	out << asn1.encode_with_options(pr.title, 'context_specific;explicit;inner:26')!
	out << asn1.encode(pr.number)!
	out << asn1.encode_with_options(pr.date_of_hire, 'context_specific: 1; explicit; inner:application,false,3')!
	out << asn1.encode_with_options(pr.name_of_spouse, 'context_specific: 2; explicit; inner:application,true,1')!
	out << asn1.encode_with_options(pr.children, 'context_specific: 3; explicit; inner:16')!

	return out
}

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

// ChildInformation ::= SET {
//      name            Name,
//      dateOfBirth     [0] Date
// }
struct ChildInformation {
	name          Name
	date_of_birth Date
}

fn (ci ChildInformation) tag() asn1.Tag {
	return asn1.default_set_tag
}

fn (ci ChildInformation) payload() ![]u8 {
	mut out := []u8{}
	dump(ci.name.payload()!.hex())
	out << asn1.encode(ci.name)!
	//, 'context_specific: 0; explicit; inner:application,false,3'
	out << asn1.encode(ci.date_of_birth)!

	return out
}

// EmployeeNumber ::= [APPLICATION 2] IMPLICIT INTEGER
type EmployeeNumber = asn1.ApplicationElement

fn EmployeeNumber.new(val asn1.Integer) !asn1.ApplicationElement {
	return asn1.ApplicationElement.from_element(val, 2, .implicit)!
}

// // Date ::= [APPLICATION 3] IMPLICIT VisibleString -- YYYYMMDD
type Date = asn1.ApplicationElement

fn Date.new(val asn1.VisibleString) !asn1.ApplicationElement {
	return asn1.ApplicationElement.from_element(val, 3, .implicit)!
}

// Name ::= [APPLICATION 1] IMPLICIT SEQUENCE {
//      givenName       VisibleString,
//      initial         VisibleString,
//      familyName      VisibleString
// }
type Name = asn1.ApplicationElement

fn Name.new(el NameEntry) !asn1.ApplicationElement {
	return asn1.ApplicationElement.from_element(el, 1, .implicit)!
}

struct NameEntry {
	given_name  asn1.VisibleString
	initial     asn1.VisibleString
	family_name asn1.VisibleString
}

fn (n NameEntry) tag() asn1.Tag {
	return asn1.default_sequence_tag
}

fn (n NameEntry) payload() ![]u8 {
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
//
// 60 8185
//		61 10 	1A 94 'John'			// name
//				iA 01 'P'
//				1A 05 'Smith'
//		A0 0A	1A 08 'Director' 		// title
//		42 01	33						// number
//		A1 0A	43 08 '19710917'		// dateOfHire
//		A2 12	61 10 	1A 	04 'Mary' 	// nameOfSpouse
//						1A	01	'T'
//						1A	05	'Smith'
//		A3 42	31 1F	61	11	1A 05 'Ralph'	=> 52 61 6c 70 68 // children
//								1A 01 'T'  		=> 54
//								1A 05 'Smith'	=> 53 6d 69 74 68
//						A0	0A	43 08 '19571111'	
//				31 1F	61	11	1A 05 'Susan'
//								1A 01 'B'
//								1A 05 'Jones'
//						A0	0A	45 08 '19590717'

fn main() {
	// { name {givenName "Ralph",initial "T",familyName "Smith"},
	//			  dateOfBirth "19571111"
	//			},
	// (1a) 05 52 61 6c 70 68 (1a) 01 54 (1a) 05 53 6d 69 74 68
	n0 := NameEntry{
		given_name:  asn1.VisibleString.new('Ralph')!
		initial:     asn1.VisibleString.new('T')!
		family_name: asn1.VisibleString.new('Smith')!
	}
	childinfo0 := ChildInformation{
		name:          Name.new(n0)!
		date_of_birth: Date.new(asn1.VisibleString.new('19571111')!)!
	}
	dump(childinfo0.tag())
	dump(childinfo0.name.inner_tag()!)
	dump(childinfo0.payload()!)
}
