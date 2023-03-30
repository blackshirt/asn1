# asn1
`asn1` is a pure V Language module for X.690 Abstract Syntax Notation One (ASN.1)
Distinguished Encoding Rules (DER) encoding and decoding.


This module provides you with the ability to generate and parse ASN.1 encoded data. 
More precisely, it provides you with the ability to generate and parse data encoded with ASN.1’s DER (Distinguished Encoding Rules) encoding. 
It does not support other than DER.

## Supported ASN.1 Type
It's currently supports following basic ASN1 type:
- [x] Boolean
- [x] BitString
- [x] Integer (through i32, i64, and big.Integer)
- [x] ObjectIdentifier
- [x] NumericString
- [x] Null
- [x] Enumerated
- [x] IA5String (ascii string)
- [x] OctetString
- [x] PrintableString
- [x] UTF8String
- [x] UTCTime
- [x] GeneralizedTime
- [x] VisibleString
- [x] Sequence, 
- [x] SequenceOf
- [x] Set
- [x] SetOf

## **Features**
--------------
* Support mostly basic ASN.1 tag type, except for a few types.
* Supports single and multibyte (high form) tag format for tag number > 31
* Serializing and deserializing of ASN.1 objcet to bytes and vice versa.


## Code Examples

Here are some simple usage examples. 

### Encode

Encode a sequence containing a UTF-8 string, an integer
and an explicitly tagged object identifier, conforming to the following
ASN.1 specification:

```asn.1
Example ::= SEQUENCE {
    greeting    UTF8String,
    answer      INTEGER,
    type        [1] EXPLICIT OBJECT IDENTIFIER
}
```

```v
mut seq := new_sequence()

seq.add(new_utf8string('Hello')!) 
seq.add(new_integer(i64(42))) 
seq.add(new_explicit_context(new_oid_from_string('1.3.6.1.3')!, 1))

out := seq.encode()!
// dump(out) == [u8(0x30), 18, u8(12), 5, 72, 101, 108, 108, 111, u8(2), 1, 42, u8(0xA1), 6, 6, 4, 43, 6, 1, 3]
```

### Decode

Decode DER encoding from above.

```v
data := [u8(0x30), 18, u8(12), 5, 72, 101, 108, 108, 111, u8(2), 1, 42, u8(0xA1), 6, 6, 4, 43, 6, 1, 3]
seq := der_decode(data)!
// smart casting
if seq is Sequence {
    assert seq.elements[0] is UTF8String
	assert seq.elements[1] is AsnInteger
	assert seq.elements[2] is Tagged
}
```


## License

This project is licensed under the MIT License (see LICENSE file)