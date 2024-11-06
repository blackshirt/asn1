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
	out << asn1.encode(ci.name)!
	//, 'context_specific: 0; explicit; inner:application,false,3'
	out << asn1.encode_with_options(ci.date_of_birth, 'context_specific: 0; explicit; inner:application,false,3')!

	return out
}

// EmployeeNumber ::= [APPLICATION 2] IMPLICIT INTEGER
type EmployeeNumber = asn1.ApplicationElement

fn EmployeeNumber.new(val asn1.Integer) !asn1.ApplicationElement {
	return asn1.ApplicationElement.from_element(val, 2, .implicit)!
}

fn (e EmployeeNumber) tag() asn1.Tag {
	return e.RawElement.tag()
}

fn (e EmployeeNumber) payload() ![]u8 {
	return e.RawElement.payload()!
}

// // Date ::= [APPLICATION 3] IMPLICIT VisibleString -- YYYYMMDD
type Date = asn1.ApplicationElement

fn Date.new(val asn1.VisibleString) !asn1.ApplicationElement {
	return asn1.ApplicationElement.from_element(val, 3, .implicit)!
}

// Issues: without defines this required tag and payload, this leads into panic RUNTIME ERROR
// 0x00000000: at ???: RUNTIME ERROR: invalid memory access
// /tmp/v_33333/examples2.01JBZV5E8Q7159BDF4PWJXJ3QK.tmp.c:23109: by asn1__Element_encode_with_options
// /tmp/v_33333/examples2.01JBZV5E8Q7159BDF4PWJXJ3QK.tmp.c:23090: by asn1__encode_with_options
// /tmp/v_33333/examples2.01JBZV5E8Q7159BDF4PWJXJ3QK.tmp.c:23077: by asn1__encode
// /tmp/v_33333/examples2.01JBZV5E8Q7159BDF4PWJXJ3QK.tmp.c:29098: by main__main
// /tmp/v_33333/examples2.01JBZV5E8Q7159BDF4PWJXJ3QK.tmp.c:29396: by main
fn (d Date) tag() asn1.Tag {
	return d.RawElement.tag()
}

fn (d Date) payload() ![]u8 {
	return d.RawElement.payload()!
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

// Issues: without defines this required tag and payload, this leads into panic RUNTIME ERROR
fn (n Name) tag() asn1.Tag {
	return n.RawElement.tag()
}

fn (n Name) payload() ![]u8 {
	return n.RawElement.payload()!
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
//						A0	0A	43 08 '19571111' => 31 39 35 37 31 31 31 31
//				31 1F	61	11	1A 05 'Susan'	=> 53 75 73 61 6e
//								1A 01 'B'		=> 42
//								1A 05 'Jones'	=> 4a 6f 6e 65 73
//						A0	0A	43 08 '19590717' => 31 39 35 39 30 37 31 37

fn main() {
	//		61 10 	1A 94 'John'			// name
    //				iA 01 'P'
    //				1A 05 'Smith'
	// PersonelRecord.name 
	pr_nme := Name.new(NameEntry{
		given_name: asn1.VisibleString.new('John')!
		initial: asn1.VisibleString.new('P')!
		family_nams: asn1.VisibleString.new('Smith')!
	})!
	
	// { name {givenName "Ralph",initial "T",familyName "Smith"},
	//			  dateOfBirth "19571111"
	//			},
	n0 := NameEntry{
		given_name:  asn1.VisibleString.new('Ralph')!
		initial:     asn1.VisibleString.new('T')!
		family_name: asn1.VisibleString.new('Smith')!
	}
	childinfo0 := ChildInformation{
		name:          Name.new(n0)!
		date_of_birth: Date.new(asn1.VisibleString.new('19571111')!)!
	}
	// 31 1F	61	11	1A 05 'Ralph'	=> 52 61 6c 70 68
	//					1A 01 'T'  		=> 54
	//					1A 05 'Smith'	=> 53 6d 69 74 68
	//			A0	0A	43 08 '19571111' => 31 39 35 37 31 31 31 31
	ch0 := [u8(0x31), 0x1F, 0x61, 0x11, 0x1A, 0x05, 0x52, 0x61, 0x6c, 0x70, 0x68, 0x1A, 0x01, 0x54,
		0x1A, 0x05, 0x53, 0x6d, 0x69, 0x74, 0x68, 0xA0, 0x0A, 0x43, 0x08, 0x31, 0x39, 0x35, 0x37,
		0x31, 0x31, 0x31, 0x31]

	n1 := NameEntry{
		given_name:  asn1.VisibleString.new('Susan')!
		initial:     asn1.VisibleString.new('B')!
		family_name: asn1.VisibleString.new('Jones')!
	}
	childinfo1 := ChildInformation{
		name:          Name.new(n1)!
		date_of_birth: Date.new(asn1.VisibleString.new('19590717')!)!
	}
	//				31 1F	61	11	1A 05 'Susan'	=> 53 75 73 61 6e
	//								1A 01 'B'		=> 42
	//								1A 05 'Jones'	=> 4a 6f 6e 65 73
	//						A0	0A	43 08 '19590717' => 31 39 35 39 30 37 31 37
	ch1 := [u8(0x31), 0x1F, 0x61, 0x11, 0x1A, 0x05, 0x53, 0x75, 0x73, 0x61, 0x6e, 0x1A, 0x01, 0x42,
		0x1A, 0x05, 0x4a, 0x6f, 0x6e, 0x65, 0x73, 0xA0, 0x0A, 0x43, 0x08, 0x31, 0x39, 0x35, 0x39,
		0x30, 0x37, 0x31, 0x37]

	dump(asn1.encode(childinfo0)! == ch0)
	dump(asn1.encode(childinfo1)! == ch1)
}
