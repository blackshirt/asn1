# `asn1` module documentation.

## About `asn1` module
`asn1` is a pure V module for handling Abstract Syntax Notation One (ASN.1) [[X.680]](http://www.itu.int/rec/T-REC-X.680/en) objects encoded in Distinguished Encoding Rules (DER) [[X.690]](https://www.itu.int/rec/T-REC-X.690/en) encoding scheme.

## Table of Contents
- [About `asn1` module](#about-asn1-module)
- [What is ASN.1](#what-is-asn1)
- [ASN.1 Encoding](#encoding-of-asn1)
- [Basic ASN.1 Type System](#basic-of-asn1-type-system)
  - [Tag handling](#asn1-tag)
  - [Create tag](#create-new-tag)
  - [Length handling](#length-handling)
- [Supported ASN.1 type](#supported-basic-asn1-type)
- [Generic ASN.1 Object](#generic-asn1-object)
- [Basic ASN.1 Constructor](#create-basic-asn1-type)
- [Encoding of ASN.1 Object](#encoding-asn1-object)
  - [Encoder interface](#encoder-interface)
  - [Serializing ASN.1 Object to bytes](#serializing-asn1-object-to-bytes)
  - [Example #1](#example-1)
  - [Example #2](#example-2)
  - [Example #3](#example-3)
- [Decoding of ASN.1 Bytes](#decoding-asn1-bytes)
- [Module Index](#module-index)
- [Reference](#reference)
  
## What is ASN.1
From [Wikipedia](https://en.wikipedia.org/wiki/ASN.1) says, Abstract Syntax Notation One (ASN.1) is a standard interface description language for defining data structures that can be serialized and deserialized in a cross-platform way. It is broadly used in telecommunications and computer networking, and especially in cryptography.


## Encoding of ASN.1
Encoding of ASN.1 is a set of encoding rules that specify how to represent a data structure as a series of bytes. There are multiple rules available that describes way of serializing ASN.1 object. The standard ASN.1 encoding rules include:
- Basic Encoding Rules (BER)
- Distinguished Encoding Rules (DER)
- Canonical Encoding Rules (CER)
- Basic XML Encoding Rules (XER)
- many other encoding rules availables.

See [[X.690]](https://www.itu.int/rec/T-REC-X.690/en) for more information about ASN.1 encoding.
> **Note**
>
> This module only support the DER encoding

## Basic of ASN.1 Type System
Fundamentally, DER 
encoding of ASN.1 is serialization of a Tag, Length and Value (TLV) triplets. Every ASN.1 object has a tag that represents what is type of the object. The Tag part specifies the type of the data structure being sent, the Length part specifies the number of bytes of content being transferred, and the Value part contains the content. Note that the Value part can be a triplet if it contains a constructed data type.

### ASN.1 Tag
ASN.1 type has a tag which is byte or series of bytes that describing class of the ASN.1 object, constructed (contains other object) or primitive and a non negative tag number. In this v `asn1` module, its support short form tag for tag number below 31 and long form tag (multi byte tag) for representing tag number bigger than 31.
To represent tag, in this `asn1` module was using this structure:
```v
struct Tag {
mut:
	class       Class
	constructed bool
	number      int
}
```
Where `Class` represent class of ASN.1 type. There are four class of ASN.1 type represented in:
```v
enum Class {
	universal = 0x00
	application = 0x01
	context = 0x02
	private = 0x03
}
```

### Create new tag
Most of the time, you don't need create tag structure manually, all basic universal type constructor set it for you internally, but for convenience, you can create a new tag, with the following constructor:
```v
fn new_tag(c Class, constructed bool, number int) Tag
```
where `c` is the ASN.1 class this object belong to, `constructed` boolean flag tells if this object constructed or primitive, and provided tag `number`.

### Length handling 
ASN.1 length indicates how many bytes you should read to get values or contents part. It always represents the total number of bytes in the object including all sub-objects but does not include the lengths of the identifier or of the length field itself.

ASN.1 length comes in two form: short and long form, short form fits in single byte for length between 0 and 127, and the others is long form in multi byte form. This module support both of them, but, its only limited to DER encoding of length, ie, use definite length encoding and use the smallest possible length representation.

## Supported Basic ASN.1 Type
Basic ASN.1 type was a ASN.1 object which has universal class. It's currently supports following basic ASN1 type:
- [x] Boolean
- [x] BitString
- [x] Integer (through i32, i64, and `big.Integer`)
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



## Generic ASN.1 Object 
For the purposes of handling ASN.1 object in general way, we use `AsnObject` that defined as:
```v
struct AsnObject {
	tag    Tag 
	values []u8
}
```
where:
* `tag` is the tag of object, and 
* `values` is the raw bytes array (contents) of the object without tag and length part.

You can create  `AsnObject` object with  the constructor, provided with parameters :
* `Class` this object belong to,
* `constructed` boolean flag that tell this object constructed or primitive, 
* `tagnum` is the tag number, and, 
* `values` is bytes array of contents.


```v
fn new_asn_object(c Class, constructed bool, tagnum int, values []u8) AsnObject
```

> **Note**
>
> Most of the time, you don't need to use `AsnObject` directly, but, 
> the recommended way to create ASN.1 object was using most basic type constructor 
> described in [[Creating Basic ASN.1 Type]](#creating-asn1-object) below.


## Create Basic ASN.1 Type
You can use following function to create basic UNIVERSAL ASN.1 type. Most of the constructor return `Encoder` interfaces.
|No | Func Signature     		      			   	| ASN.1 Object 	| Description |
|:--:|---------------------------------------------------------------	|:-------------:|-------------|
| 1 | [new_boolean](#new_boolean)	   	| BOOLEAN	|  |
| 2 | [new_integer](#new_integer)		| INTEGER	|  |
| 3 | [new_bitstring](#new_bitstring)		| BITSTRING	| its accepts arbitrary v string, not a bit string |
| 4 | [new_octetstring](#new_octetstring)	| OCTET STRING	| |
| 5 | [new_null](#new_null)			| NULL		|  |
| 6 | [new_oid_from_string](#new_oid_from_string) | OBJECT IDENTIFIER | |
| 7 | [new_enumerated](#new_enumerated)		| ENUMERATED | |
| 8 | [new_utf8string](#new_utf8string) 	| UTF8STRING | |
| 9 | [new_sequence](#new_sequence)		| SEQUENCE, SEQUENCE OF | for sequence of, you should ensure you add the same object to sequence elements.|
| 10 | [new_set](#new_set) 			| SET, SET OF | likes a sequence of, ensure add the same object to set elements|
| 11 | [new_numeric_string](#new_numeric_string)| NUMERIC STRING | |
| 12 | [new_printable_string](#new_printable_string) | PRINTABLE STRING | |
| 13 | [new_ia5string](#new_ia5string) 		| IA5STRING | |
| 14 | [new_utctime](#new_utctime)		| UTCTIME | |
| 15 | [new_generalizedtime](#new_generalizedtime) | GENERALIZED TIME | | 
| 16 | [new_visiblestring](#new_visiblestring)| VISIBLESTRING | |
  
and for handling `EXPLICIT` or `IMPLICIT` tagged object, there are two availables constructor:
- [new_implicit_context](#new_implicit_context) for wraps ASN.1 object in implicit mode.
- [new_explicit_context](#new_explicit_context) for wraps ASN.1 object in explicit mode.
  
  
## Encoding ASN.1 Object
This section describes a way to do serializing ASN.1 to bytes array,
included serialized tag and length. 
The most important to facilitate encoding functionality of the ASN.1 object
we use `Encoder` interface.

### Encoder Interface
`Encoder` is a main interrface that wraps ASN.1 encoding functionality.  
Mostly all of basic types in this module implements this interface.  
`Encoder` interface defined as;
```v
interface Encoder {
	// tag of the underlying ASN.1 object
	tag() Tag
	// length of ASN.1 object (without tag and length part)
	length() int
	// length of encoded bytes of the object (included tag and length part)
	size() int
	// Serializes object to bytes array with DER encoding
	encode() ![]u8
}
```
### Serializing ASN.1 Object to Bytes
For serializing ASN.1 object to bytes array, do following step to get bytes:
* create desired ASN.1 object by calling desired constructor.
* call `encode()!` method of the created object in previous step.
* get the bytes array ready to transfer.

### Example #1
In the first example, we would create simple object identifier object from string and serializing it to bytes array.
For other object, see [Basic ASN.1 Constructor](#create-basic-asn1-type).
```v
input := '1.2.840.113549'

src := new_oid_from_string(input)!

out := src.encode()!
exp := [u8(0x06), 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d]
assert out == exp
```
### Example #2
In the second example, we would create more complex type, sequence contains other object.
```v
// create universal type sequence
mut seq := new_sequence()

// add three object to the sequence elements.
seq.add(new_utf8string('Hello')!) 
seq.add(new_integer(i64(42))) 
seq.add(new_explicit_context(new_oid_from_string('1.3.6.1.3')!, 1))

// lets serialize it to bytes
out := seq.encode()!
assert out == [u8(0x30), 18, u8(12), 5, 72, 101, 108, 108, 111, u8(2), 1, 42, u8(0xA1), 6, 6, 4, 43, 6, 1, 3]
```
### Example #3
In the third example, lets create more complex type where sequence contains another sequence.
```v
// lets create first sequence
mut seq1 := new_sequence()
// add two primitive elements to the sequence
seq1.add(new_boolean(true))
seq1.add(new_boolean(false))

// lets create another sequences, where it contains primitive element and first sequence created above.
mut seq2 := new_sequence()
seq2.add(new_boolean(false))
seq2.add(seq1)
seq2.add(new_boolean(true))

// lets serialize it to bytes
out := seq2.encode()!
expected := [u8(0x30), 14, u8(0x01), 0x01, 0x00, u8(0x30), 6, 0x01, 0x01, 0xff, 0x01, 0x01, 0x00,
		u8(0x01), 0x01, 0xff]
// assert for right value
assert seq2.length() == 14
assert seq2.size() == 16
assert out == expected
```

## Decoding ASN.1 Bytes
This section describes how to parse (decode) bytes of data encoded in ASN.1 DER encoding. This module export `der_decode` defined below as main routine to do parsing of DER encoded data. Its accepts bytes arrays encoded in DER in `src` params and returns `Encoder` interfaces object,
so, you should cast it to get underlying type.  By default, in context specific class, its try to read as tagged object, whether its explicit or implicit.  
```v
fn der_decode(src []u8) !Encoder
```

--Example--
-----------
We're going to use above data in [Example #3](#example-3) as an example for `der_decode` functionality.
```v
// the data we're going to decode, serialized in DER encoding.
data := [u8(0x30), 14, u8(0x01), 0x01, 0x00, u8(0x30), 6, 0x01, 0x01, 0xff, 0x01, 0x01,
		0x00, u8(0x01), 0x01, 0xff]

// lets call `der_decode` routine
out := der_decode(data)!
// lets cast it to sequence
seq := out.as_sequence()!
	

el0 := seq.elements[0].as_boolean()!
assert el0.value == false 

el1 := seq.elements[1].as_sequence()!
//dump(el1)
el2 := seq.elements[2].as_boolean()!
assert el2.value == true 
```
If we dump `el1` element, we exactly got the structure of sequence, with elements contains two bolean values, like we constructed in [Example #3](#example-3) above.
Similar like this output:
```bash
el1: asn1.Sequence{
    tag: asn1.Tag{
        class: universal
        constructed: true
        number: 16
    }
    elements: [asn1.Encoder(asn1.AsnBoolean{
        value: true
    }), asn1.Encoder(asn1.AsnBoolean{
        value: false
    })]
```

## Module Index
## new_oid_from_string
```v
fn new_oid_from_string(s string) !Encoder
```

new_oid_from_string creates Oid serializer from string

[[Return to contents]](#table-of-contents)

## new_visiblestring
```v
fn new_visiblestring(s string) !Encoder
```


[[Return to contents]](#table-of-contents)

## new_utf8string
```v
fn new_utf8string(s string) !Encoder
```


[[Return to contents]](#table-of-contents)

## new_utctime
```v
fn new_utctime(s string) !Encoder
```

new_utctime creates new UtcTime from string s.  

[[Return to contents]](#table-of-contents)

## new_tag
```v
fn new_tag(c Class, constructed bool, number int) Tag
```

`new_tag` creates new tag with class `c`, with constructed or primitive form
through `constructed` boolean flag, and tag `number`.  

[[Return to contents]](#table-of-contents)



## new_set_with_class
```v
fn new_set_with_class(c Class) Set
```

new_set_with_class creates new set with specific ASN.1 class.  

[[Return to contents]](#table-of-contents)

## new_set
```v
fn new_set() Set
```

new_set creates universal set.  

[[Return to contents]](#table-of-contents)

## new_sequence_with_class
```v
fn new_sequence_with_class(c Class) Sequence
```

new_sequence_with_class creates new empty sequence with specific ASN.1 class.  

[[Return to contents]](#table-of-contents)

## new_sequence
```v
fn new_sequence() Sequence
```

new_sequence creates empty universal class of sequence type.  
for other ASN.1 class, see `new_sequence_with_class`

[[Return to contents]](#table-of-contents)

## new_asn_object
```v
fn new_asn_object(cls Class, constructed bool, tagnum int, values []u8) AsnObject
```

`new_asn_object` creates new ASN.1 Object

[[Return to contents]](#table-of-contents)

## new_bitstring
```v
fn new_bitstring(s string) !Encoder
```


[[Return to contents]](#table-of-contents)

## new_boolean
```v
fn new_boolean(value bool) Encoder
```


[[Return to contents]](#table-of-contents)

## new_enumerated
```v
fn new_enumerated(val int) Encoder
```


[[Return to contents]](#table-of-contents)

## new_explicit_context
```v
fn new_explicit_context(asn Encoder, tagnum int) Tagged
```

new_explicit_context creates new explicit mode of context specific class of tagged object
from original ASN.1 object with tag number sets to tagnum.  

[[Return to contents]](#table-of-contents)

## new_generalizedtime
```v
fn new_generalizedtime(s string) !Encoder
```


[[Return to contents]](#table-of-contents)

## new_ia5string
```v
fn new_ia5string(s string) !Encoder
```


[[Return to contents]](#table-of-contents)

## new_implicit_context
```v
fn new_implicit_context(asn Encoder, tagnum int) Tagged
```

new_implicit_context creates new implicit mode of context specific class of tagged object from original
ASN.1 object with new tag number sets to tagnum.  

[[Return to contents]](#table-of-contents)

## new_integer
```v
fn new_integer(val AsnInteger) Encoder
```

new_integer creates asn.1 serializable integer object. Its supports arbitrary integer value, with support from `math.big` module for
integer bigger than 64 bit number.  

[[Return to contents]](#table-of-contents)

## new_null
```v
fn new_null() Encoder
```


[[Return to contents]](#table-of-contents)

## new_numeric_string
```v
fn new_numeric_string(s string) !Encoder
```

new_numeric_string creates new numeric string

[[Return to contents]](#table-of-contents)

## new_octetstring
```v
fn new_octetstring(s string) Encoder
```

new_octetstring creates new octet string

[[Return to contents]](#table-of-contents)

## new_printable_string
```v
fn new_printable_string(s string) !Encoder
```

new_printable_string creates PrintableString from the string s

[[Return to contents]](#table-of-contents)

## read_explicit_context
```v
fn read_explicit_context(tag Tag, contents []u8) !Tagged
```


[[Return to contents]](#table-of-contents)




[[Return to contents]](#table-of-contents)

## contents
```v
fn (enc Encoder) contents() ![]u8
```

contents gets the contents (values) part of ASN.1 object, that is,
bytes values of the object  without tag and length parts.  

[[Return to contents]](#table-of-contents)

## as_sequence
```v
fn (e Encoder) as_sequence() !Sequence
```

as_sequence cast encoder to sequence

[[Return to contents]](#table-of-contents)

## as_set
```v
fn (e Encoder) as_set() !Set
```

as_set cast encoder to set

[[Return to contents]](#table-of-contents)

## as_boolean
```v
fn (e Encoder) as_boolean() !AsnBoolean
```

as_boolean cast encoder to ASN.1 boolean

[[Return to contents]](#table-of-contents)

## as_integer
```v
fn (e Encoder) as_integer() !AsnInteger
```

as_integer cast encoder to ASN.1 integer

[[Return to contents]](#table-of-contents)

## as_bitstring
```v
fn (e Encoder) as_bitstring() !BitString
```

as_bitstring cast encoder to ASN.1 bitstring

[[Return to contents]](#table-of-contents)

## as_octetstring
```v
fn (e Encoder) as_octetstring() !OctetString
```

as_octetstring cast encoder to ASN.1 OctetString

[[Return to contents]](#table-of-contents)

## as_null
```v
fn (e Encoder) as_null() !Null
```

as_null cast encoder to ASN.1 null type

[[Return to contents]](#table-of-contents)

## as_oid
```v
fn (e Encoder) as_oid() !Oid
```

as_oid cast encoder to ASN.1 object identifier type.  

[[Return to contents]](#table-of-contents)

## as_utf8string
```v
fn (e Encoder) as_utf8string() !UTF8String
```

as_utf8string cast encoder to ASN.1 UTF8String.  

[[Return to contents]](#table-of-contents)

## as_numericstring
```v
fn (e Encoder) as_numericstring() !NumericString
```

as_numericstring cast encoder to ASN.1 NumericString.  

[[Return to contents]](#table-of-contents)

## as_printablestring
```v
fn (e Encoder) as_printablestring() !PrintableString
```

as_printablestring cast encoder to ASN.1 PrintableString.  

[[Return to contents]](#table-of-contents)

## as_ia5string
```v
fn (e Encoder) as_ia5string() !IA5String
```

as_ia5string cast encoder to ASN.1 IA5String.  

[[Return to contents]](#table-of-contents)

## as_visiblestring
```v
fn (e Encoder) as_visiblestring() !VisibleString
```

as_visiblestring cast encoder to ASN.1 VisibleString.  

[[Return to contents]](#table-of-contents)

## as_utctime
```v
fn (e Encoder) as_utctime() !UtcTime
```

as_utctime cast encoder to ASN.1 UtcTime.  

[[Return to contents]](#table-of-contents)

## as_generalizedtime
```v
fn (e Encoder) as_generalizedtime() !GeneralizedTime
```

as_generalizedtime cast encoder to ASN.1 GeneralizedTime.  

[[Return to contents]](#table-of-contents)

## Enumerated
```v
type Enumerated = int
```

ENUMERATED.  
Enumerated type treated as ordinary integer, only differs on tag value.  
The encoding of an enumerated value shall be that of the integer value with which it is associated.  
NOTE: It is primitive.  

[[Return to contents]](#table-of-contents)

## tag
```v
fn (en Enumerated) tag() Tag
```


[[Return to contents]](#Contents)

## length
```v
fn (en Enumerated) length() int
```


[[Return to contents]](#table-of-contents)

## size
```v
fn (en Enumerated) size() int
```


[[Return to contents]](#table-of-contents)

## encode
```v
fn (en Enumerated) encode() ![]u8
```


[[Return to contents]](#table-of-contents)

## GeneralizedTime
```v
type GeneralizedTime = string
```

GeneralizedTime.  

In DER Encoding scheme, GeneralizedTime should :
- The encoding shall terminate with a "Z"
- The seconds element shall always be present
- The fractional-seconds elements, if present, shall omit all trailing zeros;
- if the elements correspond to 0, they shall be wholly omitted, and the decimal point element also shall be omitted

GeneralizedTime values MUST be:
- expressed in Greenwich Mean Time (Zulu) and MUST include seconds
(i.e., times are `YYYYMMDDHHMMSSZ`), even where the number of seconds
is zero.  
- GeneralizedTime values MUST NOT include fractional seconds.

[[Return to contents]](#table-of-contents)

## tag
```v
fn (gt GeneralizedTime) tag() Tag
```


[[Return to contents]](#table-of-contents)

## length
```v
fn (gt GeneralizedTime) length() int
```


[[Return to contents]](#table-of-contents)

## size
```v
fn (gt GeneralizedTime) size() int
```


[[Return to contents]](#table-of-contents)

## encode
```v
fn (gt GeneralizedTime) encode() ![]u8
```


[[Return to contents]](#table-of-contents)

## IA5String
## tag
```v
fn (a5 IA5String) tag() Tag
```


[[Return to contents]](#table-of-contents)

## length
```v
fn (a5 IA5String) length() int
```


[[Return to contents]](#table-of-contents)

## size
```v
fn (a5 IA5String) size() int
```


[[Return to contents]](#table-of-contents)

## encode
```v
fn (a5 IA5String) encode() ![]u8
```


[[Return to contents]](#table-of-contents)

## UtcTime
```v
type UtcTime = string
```

UTCTime
-------
For this time, UTCTime represented by simple string with format "YYMMDDhhmmssZ"
- the six digits YYMMDD where YY is the two low-order digits of the Christian year,
(RFC 5280 defines it as a range from 1950 to 2049 for X.509), MM is the month
(counting January as 01), and DD is the day of the month (01 to 31).  
- the four digits hhmm where hh is hour (00 to 23) and mm is minutes (00 to 59); (SEE NOTE BELOW)
- the six digits hhmmss where hh and mm are as in above, and ss is seconds (00 to 59);
- the character Z;
- one of the characters + or -, followed by hhmm, where hh is hour and mm is minutes (NOT SUPPORTED)

NOTE
-----
- Restrictions employed by DER, the encoding shall terminate with "Z".
- The seconds element shall always be present, and DER (along with RFC 5280) specify that seconds must be present,
- Fractional seconds must not be present.

TODO:
- check for invalid representation of date and hhmmss part.
- represented UTCTime in time.Time

[[Return to contents]](#table-of-contents)

## tag
```v
fn (utc UtcTime) tag() Tag
```


[[Return to contents]](#table-of-contents)

## length
```v
fn (utc UtcTime) length() int
```


[[Return to contents]](#table-of-contents)

## size
```v
fn (utc UtcTime) size() int
```


[[Return to contents]](#table-of-contents)

## encode
```v
fn (utc UtcTime) encode() ![]u8
```


[[Return to contents]](#table-of-contents)

## BitString
## tag
```v
fn (bs BitString) tag() Tag
```


[[Return to contents]](#table-of-contents)

## length
```v
fn (bs BitString) length() int
```


[[Return to contents]](#table-of-contents)

## size
```v
fn (bs BitString) size() int
```


[[Return to contents]](#table-of-contents)

## encode
```v
fn (bs BitString) encode() ![]u8
```


[[Return to contents]](#table-of-contents)

## UTF8String
## tag
```v
fn (ut UTF8String) tag() Tag
```


[[Return to contents]](#table-of-contents)

## length
```v
fn (ut UTF8String) length() int
```


[[Return to contents]](#table-of-contents)

## size
```v
fn (ut UTF8String) size() int
```


[[Return to contents]](#table-of-contents)

## encode
```v
fn (ut UTF8String) encode() ![]u8
```


[[Return to contents]](#table-of-contents)

## AsnInteger
```v
type AsnInteger = big.Integer | i64 | int
```

INTEGER.  

ASN.1 Integer represented by AsnInteger sum type of `int`, `i64` and `big.Integer`.  
Its handles number arbitrary length of number with support of `math.big` module.  
The encoding of an integer value shall be primitive.  

[[Return to contents]](#table-of-contents)

## tag
```v
fn (n AsnInteger) tag() Tag
```


[[Return to contents]](#table-of-contents)

## length
```v
fn (n AsnInteger) length() int
```


[[Return to contents]](#table-of-contents)

## size
```v
fn (n AsnInteger) size() int
```


[[Return to contents]](#table-of-contents)

## encode
```v
fn (n AsnInteger) encode() ![]u8
```


[[Return to contents]](#table-of-contents)

## Null
## tag
```v
fn (n Null) tag() Tag
```


[[Return to contents]](#table-of-contents)

## length
```v
fn (n Null) length() int
```


[[Return to contents]](#table-of-contents)

## size
```v
fn (n Null) size() int
```


[[Return to contents]](#table-of-contents)

## encode
```v
fn (n Null) encode() ![]u8
```


[[Return to contents]](#table-of-contents)

## NumericString
## tag
```v
fn (ns NumericString) tag() Tag
```


[[Return to contents]](#table-of-contents)

## length
```v
fn (ns NumericString) length() int
```


[[Return to contents]](#table-of-contents)

## size
```v
fn (ns NumericString) size() int
```


[[Return to contents]](#table-of-contents)

## encode
```v
fn (ns NumericString) encode() ![]u8
```


[[Return to contents]](#table-of-contents)

## OctetString
## tag
```v
fn (os OctetString) tag() Tag
```


[[Return to contents]](#table-of-contents)

## length
```v
fn (os OctetString) length() int
```


[[Return to contents]](#table-of-contents)

## size
```v
fn (os OctetString) size() int
```


[[Return to contents]](#table-of-contents)

## encode
```v
fn (os OctetString) encode() ![]u8
```


[[Return to contents]](#table-of-contents)

## Oid
```v
type Oid = []int
```

ObjectIdentifier

[[Return to contents]](#table-of-contents)

## tag
```v
fn (oid Oid) tag() Tag
```


[[Return to contents]](#table-of-contents)

## length
```v
fn (oid Oid) length() int
```


[[Return to contents]](#table-of-contents)

## size
```v
fn (oid Oid) size() int
```


[[Return to contents]](#table-of-contents)

## encode
```v
fn (oid Oid) encode() ![]u8
```


[[Return to contents]](#Contents)

## PrintableString
## tag
```v
fn (ps PrintableString) tag() Tag
```


[[Return to contents]](#table-of-contents)

## length
```v
fn (ps PrintableString) length() int
```


[[Return to contents]](#table-of-contents)

## size
```v
fn (ps PrintableString) size() int
```


[[Return to contents]](#table-of-contents)

## encode
```v
fn (ps PrintableString) encode() ![]u8
```


[[Return to contents]](#table-of-contents)

## AsnBoolean
## tag
```v
fn (b AsnBoolean) tag() Tag
```


[[Return to contents]](#table-of-contents)

## length
```v
fn (b AsnBoolean) length() int
```


[[Return to contents]](#table-of-contents)

## size
```v
fn (b AsnBoolean) size() int
```


[[Return to contents]](#table-of-contents)

## encode
```v
fn (b AsnBoolean) encode() ![]u8
```


[[Return to contents]](#table-of-contents)

## Sequence
## length
```v
fn (seq Sequence) length() int
```


[[Return to contents]](#table-of-contents)

## size
```v
fn (seq Sequence) size() int
```


[[Return to contents]](#table-of-contents)

## encode
```v
fn (seq Sequence) encode() ![]u8
```


[[Return to contents]](#table-of-contents)

## Set
## add
```v
fn (mut set Set) add(obj Encoder) Set
```


[[Return to contents]](#table-of-contents)

## add_multi
```v
fn (mut set Set) add_multi(objs []Encoder) Set
```


[[Return to contents]](#table-of-contents)

## Tagged
## tag
```v
fn (ctx Tagged) tag() Tag
```

tag returns outer tag

[[Return to contents]](#table-of-contents)

## inner_tag
```v
fn (ctx Tagged) inner_tag() Tag
```

inner_tag return inner tag of the inner object being wrapped

[[Return to contents]](#table-of-contents)

## as_inner
```v
fn (ctx Tagged) as_inner() Encoder
```

as_inner returns inner object being wrapped

[[Return to contents]](#table-of-contents)

## length
```v
fn (ctx Tagged) length() int
```

length returns the length of the context tagged object

[[Return to contents]](#table-of-contents)

## size
```v
fn (ctx Tagged) size() int
```

size returns sizes of context specific tagged object.  
When in explicit mode, the size of object was sum of length of the outer tag,
length of the length part and inner size.  
and in implicit mode, the size was total (sum) of size of inner object,
and length of outer tag.  

[[Return to contents]](#table-of-contents)

## encode
```v
fn (ctx Tagged) encode() ![]u8
```

encode serializes context tagged object to array of bytes.  
Its different between tagged mode explicit and implicit.  

[[Return to contents]](#table-of-contents)

## VisibleString
## tag
```v
fn (vs VisibleString) tag() Tag
```


[[Return to contents]](#table-of-contents)

## length
```v
fn (vs VisibleString) length() int
```


[[Return to contents]](#table-of-contents)

## size
```v
fn (vs VisibleString) size() int
```


[[Return to contents]](#table-of-contents)

## encode
```v
fn (vs VisibleString) encode() ![]u8
```


[[Return to contents]](#table-of-contents)

## Class
```v
enum Class {
	universal = 0x00
	application = 0x01
	context = 0x02
	private = 0x03
}
```

Class is ASN.1 tag class.  
Currently most of universal class supported in this module, with limited support for other class.  

[[Return to contents]](#table-of-contents)

## TagType
```v
enum TagType {
	reserved = 0 //	reserved for BER
	boolean = 1 // BOOLEAN
	integer = 2 // INTEGER
	bitstring = 3 // BIT STRING
	octetstring = 4 // OCTET STRING
	null = 5 // NULL
	oid = 6 // OBJECT IDENTIFIER
	objdesc = 7 // ObjectDescriptor
	external = 8 //	INSTANCE OF, EXTERNAL
	real = 9 // REAL
	enumerated = 10 // ENUMERATED
	embedded = 11 // EMBEDDED PDV
	utf8string = 12 // UTF8String
	relativeoid = 13 // RELATIVE-OID
	sequence = 16 // SEQUENCE, SEQUENCE OF, Constructed
	set = 17 ///SET, SET OF, Constructed
	numericstring = 18 // NumericString
	printablestring = 19 // PrintableString
	t61string = 20 // eletexString, T61String
	videotexstring = 21 // VideotexString
	ia5string = 22 // IA5String
	utctime = 23 // UTCTime
	generalizedtime = 24 // GeneralizedTime
	graphicstring = 25 // GraphicString
	visiblestring = 26 // VisibleString, ISO646String
	generalstring = 27 // GeneralString
	universalstring = 28 // UniversalString
	characterstring = 29 // CHARACTER STRING
	bmpstring = 30 // BMPString
}
```

Standard universal tag number. some of them was
deprecated, so its not going to be supported in this module.  

[[Return to contents]](#table-of-contents)

## AsnObject
```v
struct AsnObject {
	tag    Tag  // tag of the ASN.1 object
	values []u8 // unencoded values of the object.
}
```

AsnObject is generic ASN.1 Object representation.  
Its implements Encoder, so it can be used to support other class of der encoded ASN.1 object
other than universal class supported in this module.  

[[Return to contents]](#table-of-contents)

## tag
```v
fn (obj AsnObject) tag() Tag
```


[[Return to contents]](#table-of-contents)

## length
```v
fn (obj AsnObject) length() int
```


[[Return to contents]](#table-of-contents)

## size
```v
fn (obj AsnObject) size() int
```


[[Return to contents]](#table-of-contents)

## encode
```v
fn (obj AsnObject) encode() ![]u8
```

encode serialize ASN.1 object to bytes array. its return error on fail.  

[[Return to contents]](#table-of-contents)

## Reference
1. [A Warm Welcome to ASN.1 and DER](https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/)
2. [A Layman's Guide to a Subset of ASN.1, BER, and DER](https://luca.ntop.org/Teaching/Appunti/asn1.html)
3. [ASN.1](https://en.wikipedia.org/wiki/ASN.1)

#### Powered by vdoc. Generated on: 30 Mar 2023 15:00:53
