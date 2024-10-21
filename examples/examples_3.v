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
    name Name 
    date_of_birth Date 
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

