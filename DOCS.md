# Vlang `asn1` documentation.

## About `asn1` module
`asn.1` is a pure V module for handling Abstract Syntax Notation One (ASN.1) [[X.680]](http://www.itu.int/rec/T-REC-X.680/en) objects encoded in Distinguished Encoding Rules (DER) [[X.690]](https://www.itu.int/rec/T-REC-X.690/en) encoding scheme.

## Table of Contents (ToC)
- [About `asn1` module](#about-asn1-module)
- [What is ASN.1](#what-is-asn1)
- [ASN.1 Encoding](#encoding-of-asn1)
- [Supported ASN.1 type](#supported-basic-asn1-type)
- [Tag handling](#asn1-tag)
  - [Create tag](#create-new-tag)
- [Generic ASN.1 Object](#generic-asn1-object)
- [Basic ASN.1 Constructor](#creating-basic-asn1-type)
  
## What is ASN.1
From [Wikipedia](https://en.wikipedia.org/wiki/ASN.1) says, Abstract Syntax Notation One (ASN.1) is a standard interface description language for defining data structures that can be serialized and deserialized in a cross-platform way. It is broadly used in telecommunications and computer networking, and especially in cryptography.

ASN.1 is a joint standard of the International Telecommunication Union Telecommunication Standardization Sector (ITU-T) in ITU-T Study Group 17 and ISO/IEC, originally defined in 1984 as part of CCITT X.409:1984.[2] In 1988, ASN.1 moved to its own standard, X.208, due to wide applicability. The substantially revised 1995 version is covered by the X.680 series.[3] The latest revision of the X.680 series of recommendations is the 6.0 Edition, published in 2021.

## Encoding of ASN.1
Encoding of ASN.1 is a set of encoding rules that specify how to represent a data structure as a series of bytes. There are multiple rules available that describes way of serializing ASN.1 object. The standard ASN.1 encoding rules include:
- Basic Encoding Rules (BER)
- Distinguished Encoding Rules (DER)
- Canonical Encoding Rules (CER)
- Basic XML Encoding Rules (XER)
- many other encoding rules availables.

See [X.690](https://www.itu.int/rec/T-REC-X.690/en) for more information about ASN.1 encoding.

## Basic of ASN.1 System
Fundamentally, DER 
encoding of ASN.1 is serialization of a Tag, Length and Value (TLV) triplets. Every ASN.1 object has a tag that represents what is type of the object. The Tag part specifies the type of the data structure being sent, the Length part specifies the number of bytes of content being transferred, and the Value part contains the content. Note that the Value part can be a triplet if it contains a constructed data type.

## Supported Basic ASN.1 Type
Basic ASN.1 type was a ASN.1 object which has universal class. It's currently supports following basic ASN1 type:
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


### ASN.1 Tag
ASN.1 type has a tag which is byte(s) components that describing class of the ASN.1 object, constructed (contains other object) or primitive and a non negative tag number. In this v `asn1` module, its support short form tag for tag number below 31 and long form tag (multi byte tag) for representing tag number bigger than 31.
To represent tag, in this `asn1` module was using this structure:
```v
struct Tag {
mut:
	class       Class
	constructed bool
	number      int
}
```
There are four class of ASN.1 type thats be represented in :
```v
enum Class {
	universal = 0x00
	application = 0x01
	context = 0x02
	private = 0x03
}
```

### Create new tag
You can create a new tag, with the following constructor:
```
fn new_tag(c Class, constructed bool, number int) Tag
```
where `c` is the ASN.1 class this object belong to, `constructed` boolean flag tells if this object constructed or primitive, and provided tag `number`.

## Generic ASN.1 Object 
For the purposes of handling ASN.1 object in general way, we use `AsnObject` that defined as:
```v
struct AsnObject {
	tag    Tag 
	values []u
}
```
where:
* `tag` is the tag of object, and 
* `values` is the raw bytess array (contents) of thr object without tag and length part.

You can create  `AsnObject` object with  the constructor, provided with parameters :
* `Class` this object belong to,
* `constructed` boolean flag that tell this object constructed or primitive, and
* `values` is bytes array of contents.


```v
fn new_asn_object(c Class, constructed bool, values []u8) AsnObject
```
--Note--
--------
Mostly you dont need to use `AsnObject` directly, but, the recommended way to create ASN.1 object was using most basic type constructor described in [Creating Basic ASN.1 Type](#creating-asn1-object) below.


## Creating Basic ASN.1 Type
You can use following function to create basic ASN.1 type
  - [new_oid_from_string](#new_oid_from_string)
  - [new_visiblestring](#new_visiblestring)
  - [new_utf8string](#new_utf8string)
  - [new_utctime](#new_utctime)
  - [new_bitstring](#new_bitstring)
  - [new_boolean](#new_boolean)
  - [new_enumerated](#new_enumerated)
  - [new_implicit_context](#new_implicit_context)
  - [new_integer](#new_integer)
  - [new_null](#new_null)
  - [new_numeric_string](#new_numeric_string)
  - [new_octetstring](#new_octetstring)
  - [new_generalizedtime](#new_generalizedtime)
  - [new_ia5string](#new_ia5string)
  - [new_printable_string](#new_printable_string)
  - [new_set_with_class](#new_set_with_class)
  - [new_set](#new_set)
  - [new_sequence_with_class](#new_sequence_with_class)
  - [new_sequence](#new_sequence)



## new_oid_from_string
```v
fn new_oid_from_string(s string) !Encoder
```

new_oid_from_string creates Oid serializer from string

[[Return to contents]](#Contents)

## new_visiblestring
```v
fn new_visiblestring(s string) !Encoder
```


[[Return to contents]](#Contents)

## new_utf8string
```v
fn new_utf8string(s string) !Encoder
```


[[Return to contents]](#Contents)

## new_utctime
```v
fn new_utctime(s string) !Encoder
```

new_utctime creates new UtcTime from string s.  

[[Return to contents]](#Contents)

## new_tag
```v
fn new_tag(c Class, constructed bool, number int) Tag
```

`new_tag` creates new tag with class `c`, with constructed or primitive form
through `constructed` boolean flag, and tag `number`.  

[[Return to contents]](#Contents)

## der_decode
```v
fn der_decode(src []u8) !Encoder
```

der_decode is main routine to do parsing of DER encoded data.  
Its accepts bytes arrays encoded in DER in `src` params and returns `Encoder` interfaces object,
so, you should cast it to get underlying type.  
By default, in context specific class, its try to read as tagged object, whether its explicit or implicit.  
TODO: more robust parsing function to handle specific use cases.  

[[Return to contents]](#Contents)

## new_set_with_class
```v
fn new_set_with_class(c Class) Set
```

new_set_with_class creates new set with specific ASN.1 class.  

[[Return to contents]](#Contents)

## new_set
```v
fn new_set() Set
```

new_set creates universal set.  

[[Return to contents]](#Contents)

## new_sequence_with_class
```v
fn new_sequence_with_class(c Class) Sequence
```

new_sequence_with_class creates new empty sequence with specific ASN.1 class.  

[[Return to contents]](#Contents)

## new_sequence
```v
fn new_sequence() Sequence
```

new_sequence creates empty universal class of sequence type.  
for other ASN.1 class, see `new_sequence_with_class`

[[Return to contents]](#Contents)

## new_asn_object
```v
fn new_asn_object(cls Class, constructed bool, tagnum int, values []u8) AsnObject
```

`new_asn_object` creates new ASN.1 Object

[[Return to contents]](#Contents)

## new_bitstring
```v
fn new_bitstring(s string) !Encoder
```


[[Return to contents]](#Contents)

## new_boolean
```v
fn new_boolean(value bool) Encoder
```


[[Return to contents]](#Contents)

## new_enumerated
```v
fn new_enumerated(val int) Encoder
```


[[Return to contents]](#Contents)

## new_explicit_context
```v
fn new_explicit_context(asn Encoder, tagnum int) Tagged
```

new_explicit_context creates new explicit mode of context specific class of tagged object
from original ASN.1 object with tag number sets to tagnum.  

[[Return to contents]](#Contents)

## new_generalizedtime
```v
fn new_generalizedtime(s string) !Encoder
```


[[Return to contents]](#Contents)

## new_ia5string
```v
fn new_ia5string(s string) !Encoder
```


[[Return to contents]](#Contents)

## new_implicit_context
```v
fn new_implicit_context(asn Encoder, tagnum int) Tagged
```

new_implicit_context creates new implicit mode of context specific class of tagged object from original
ASN.1 object with new tag number sets to tagnum.  

[[Return to contents]](#Contents)

## new_integer
```v
fn new_integer(val AsnInteger) Encoder
```

new_integer creates asn.1 serializable integer object. Its supports arbitrary integer value, with support from `math.big` module for
integer bigger than 64 bit number.  

[[Return to contents]](#Contents)

## new_null
```v
fn new_null() Encoder
```


[[Return to contents]](#Contents)

## new_numeric_string
```v
fn new_numeric_string(s string) !Encoder
```

new_numeric_string creates new numeric string

[[Return to contents]](#Contents)

## new_octetstring
```v
fn new_octetstring(s string) Encoder
```

new_octetstring creates new octet string

[[Return to contents]](#Contents)

## new_printable_string
```v
fn new_printable_string(s string) !Encoder
```

new_printable_string creates PrintableString from the string s

[[Return to contents]](#Contents)

## read_explicit_context
```v
fn read_explicit_context(tag Tag, contents []u8) !Tagged
```


[[Return to contents]](#Contents)

## Encoder
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

Encoder is a main interrface that wraps ASN.1 encoding functionality.  
Most of basic types in this module implements this interface.  

[[Return to contents]](#Contents)

## contents
```v
fn (enc Encoder) contents() ![]u8
```

contents gets the contents (values) part of ASN.1 object, that is,
bytes values of the object  without tag and length parts.  

[[Return to contents]](#Contents)

## as_sequence
```v
fn (e Encoder) as_sequence() !Sequence
```

as_sequence cast encoder to sequence

[[Return to contents]](#Contents)

## as_set
```v
fn (e Encoder) as_set() !Set
```

as_set cast encoder to set

[[Return to contents]](#Contents)

## as_boolean
```v
fn (e Encoder) as_boolean() !AsnBoolean
```

as_boolean cast encoder to ASN.1 boolean

[[Return to contents]](#Contents)

## as_integer
```v
fn (e Encoder) as_integer() !AsnInteger
```

as_integer cast encoder to ASN.1 integer

[[Return to contents]](#Contents)

## as_bitstring
```v
fn (e Encoder) as_bitstring() !BitString
```

as_bitstring cast encoder to ASN.1 bitstring

[[Return to contents]](#Contents)

## as_octetstring
```v
fn (e Encoder) as_octetstring() !OctetString
```

as_octetstring cast encoder to ASN.1 OctetString

[[Return to contents]](#Contents)

## as_null
```v
fn (e Encoder) as_null() !Null
```

as_null cast encoder to ASN.1 null type

[[Return to contents]](#Contents)

## as_oid
```v
fn (e Encoder) as_oid() !Oid
```

as_oid cast encoder to ASN.1 object identifier type.  

[[Return to contents]](#Contents)

## as_utf8string
```v
fn (e Encoder) as_utf8string() !UTF8String
```

as_utf8string cast encoder to ASN.1 UTF8String.  

[[Return to contents]](#Contents)

## as_numericstring
```v
fn (e Encoder) as_numericstring() !NumericString
```

as_numericstring cast encoder to ASN.1 NumericString.  

[[Return to contents]](#Contents)

## as_printablestring
```v
fn (e Encoder) as_printablestring() !PrintableString
```

as_printablestring cast encoder to ASN.1 PrintableString.  

[[Return to contents]](#Contents)

## as_ia5string
```v
fn (e Encoder) as_ia5string() !IA5String
```

as_ia5string cast encoder to ASN.1 IA5String.  

[[Return to contents]](#Contents)

## as_visiblestring
```v
fn (e Encoder) as_visiblestring() !VisibleString
```

as_visiblestring cast encoder to ASN.1 VisibleString.  

[[Return to contents]](#Contents)

## as_utctime
```v
fn (e Encoder) as_utctime() !UtcTime
```

as_utctime cast encoder to ASN.1 UtcTime.  

[[Return to contents]](#Contents)

## as_generalizedtime
```v
fn (e Encoder) as_generalizedtime() !GeneralizedTime
```

as_generalizedtime cast encoder to ASN.1 GeneralizedTime.  

[[Return to contents]](#Contents)

## Enumerated
```v
type Enumerated = int
```

ENUMERATED.  
Enumerated type treated as ordinary integer, only differs on tag value.  
The encoding of an enumerated value shall be that of the integer value with which it is associated.  
NOTE: It is primitive.  

[[Return to contents]](#Contents)

## tag
```v
fn (en Enumerated) tag() Tag
```


[[Return to contents]](#Contents)

## length
```v
fn (en Enumerated) length() int
```


[[Return to contents]](#Contents)

## size
```v
fn (en Enumerated) size() int
```


[[Return to contents]](#Contents)

## encode
```v
fn (en Enumerated) encode() ![]u8
```


[[Return to contents]](#Contents)

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

[[Return to contents]](#Contents)

## tag
```v
fn (gt GeneralizedTime) tag() Tag
```


[[Return to contents]](#Contents)

## length
```v
fn (gt GeneralizedTime) length() int
```


[[Return to contents]](#Contents)

## size
```v
fn (gt GeneralizedTime) size() int
```


[[Return to contents]](#Contents)

## encode
```v
fn (gt GeneralizedTime) encode() ![]u8
```


[[Return to contents]](#Contents)

## IA5String
## tag
```v
fn (a5 IA5String) tag() Tag
```


[[Return to contents]](#Contents)

## length
```v
fn (a5 IA5String) length() int
```


[[Return to contents]](#Contents)

## size
```v
fn (a5 IA5String) size() int
```


[[Return to contents]](#Contents)

## encode
```v
fn (a5 IA5String) encode() ![]u8
```


[[Return to contents]](#Contents)

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

[[Return to contents]](#Contents)

## tag
```v
fn (utc UtcTime) tag() Tag
```


[[Return to contents]](#Contents)

## length
```v
fn (utc UtcTime) length() int
```


[[Return to contents]](#Contents)

## size
```v
fn (utc UtcTime) size() int
```


[[Return to contents]](#Contents)

## encode
```v
fn (utc UtcTime) encode() ![]u8
```


[[Return to contents]](#Contents)

## BitString
## tag
```v
fn (bs BitString) tag() Tag
```


[[Return to contents]](#Contents)

## length
```v
fn (bs BitString) length() int
```


[[Return to contents]](#Contents)

## size
```v
fn (bs BitString) size() int
```


[[Return to contents]](#Contents)

## encode
```v
fn (bs BitString) encode() ![]u8
```


[[Return to contents]](#Contents)

## UTF8String
## tag
```v
fn (ut UTF8String) tag() Tag
```


[[Return to contents]](#Contents)

## length
```v
fn (ut UTF8String) length() int
```


[[Return to contents]](#Contents)

## size
```v
fn (ut UTF8String) size() int
```


[[Return to contents]](#Contents)

## encode
```v
fn (ut UTF8String) encode() ![]u8
```


[[Return to contents]](#Contents)

## AsnInteger
```v
type AsnInteger = big.Integer | i64 | int
```

INTEGER.  

ASN.1 Integer represented by AsnInteger sum type of `int`, `i64` and `big.Integer`.  
Its handles number arbitrary length of number with support of `math.big` module.  
The encoding of an integer value shall be primitive.  

[[Return to contents]](#Contents)

## tag
```v
fn (n AsnInteger) tag() Tag
```


[[Return to contents]](#Contents)

## length
```v
fn (n AsnInteger) length() int
```


[[Return to contents]](#Contents)

## size
```v
fn (n AsnInteger) size() int
```


[[Return to contents]](#Contents)

## encode
```v
fn (n AsnInteger) encode() ![]u8
```


[[Return to contents]](#Contents)

## Null
## tag
```v
fn (n Null) tag() Tag
```


[[Return to contents]](#Contents)

## length
```v
fn (n Null) length() int
```


[[Return to contents]](#Contents)

## size
```v
fn (n Null) size() int
```


[[Return to contents]](#Contents)

## encode
```v
fn (n Null) encode() ![]u8
```


[[Return to contents]](#Contents)

## NumericString
## tag
```v
fn (ns NumericString) tag() Tag
```


[[Return to contents]](#Contents)

## length
```v
fn (ns NumericString) length() int
```


[[Return to contents]](#Contents)

## size
```v
fn (ns NumericString) size() int
```


[[Return to contents]](#Contents)

## encode
```v
fn (ns NumericString) encode() ![]u8
```


[[Return to contents]](#Contents)

## OctetString
## tag
```v
fn (os OctetString) tag() Tag
```


[[Return to contents]](#Contents)

## length
```v
fn (os OctetString) length() int
```


[[Return to contents]](#Contents)

## size
```v
fn (os OctetString) size() int
```


[[Return to contents]](#Contents)

## encode
```v
fn (os OctetString) encode() ![]u8
```


[[Return to contents]](#Contents)

## Oid
```v
type Oid = []int
```

ObjectIdentifier

[[Return to contents]](#Contents)

## tag
```v
fn (oid Oid) tag() Tag
```


[[Return to contents]](#Contents)

## length
```v
fn (oid Oid) length() int
```


[[Return to contents]](#Contents)

## size
```v
fn (oid Oid) size() int
```


[[Return to contents]](#Contents)

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


[[Return to contents]](#Contents)

## length
```v
fn (ps PrintableString) length() int
```


[[Return to contents]](#Contents)

## size
```v
fn (ps PrintableString) size() int
```


[[Return to contents]](#Contents)

## encode
```v
fn (ps PrintableString) encode() ![]u8
```


[[Return to contents]](#Contents)

## AsnBoolean
## tag
```v
fn (b AsnBoolean) tag() Tag
```


[[Return to contents]](#Contents)

## length
```v
fn (b AsnBoolean) length() int
```


[[Return to contents]](#Contents)

## size
```v
fn (b AsnBoolean) size() int
```


[[Return to contents]](#Contents)

## encode
```v
fn (b AsnBoolean) encode() ![]u8
```


[[Return to contents]](#Contents)

## Sequence
## length
```v
fn (seq Sequence) length() int
```


[[Return to contents]](#Contents)

## size
```v
fn (seq Sequence) size() int
```


[[Return to contents]](#Contents)

## encode
```v
fn (seq Sequence) encode() ![]u8
```


[[Return to contents]](#Contents)

## Set
## add
```v
fn (mut set Set) add(obj Encoder) Set
```


[[Return to contents]](#Contents)

## add_multi
```v
fn (mut set Set) add_multi(objs []Encoder) Set
```


[[Return to contents]](#Contents)

## Tagged
## tag
```v
fn (ctx Tagged) tag() Tag
```

tag returns outer tag

[[Return to contents]](#Contents)

## inner_tag
```v
fn (ctx Tagged) inner_tag() Tag
```

inner_tag return inner tag of the inner object being wrapped

[[Return to contents]](#Contents)

## as_inner
```v
fn (ctx Tagged) as_inner() Encoder
```

as_inner returns inner object being wrapped

[[Return to contents]](#Contents)

## length
```v
fn (ctx Tagged) length() int
```

length returns the length of the context tagged object

[[Return to contents]](#Contents)

## size
```v
fn (ctx Tagged) size() int
```

size returns sizes of context specific tagged object.  
When in explicit mode, the size of object was sum of length of the outer tag,
length of the length part and inner size.  
and in implicit mode, the size was total (sum) of size of inner object,
and length of outer tag.  

[[Return to contents]](#Contents)

## encode
```v
fn (ctx Tagged) encode() ![]u8
```

encode serializes context tagged object to array of bytes.  
Its different between tagged mode explicit and implicit.  

[[Return to contents]](#Contents)

## VisibleString
## tag
```v
fn (vs VisibleString) tag() Tag
```


[[Return to contents]](#Contents)

## length
```v
fn (vs VisibleString) length() int
```


[[Return to contents]](#Contents)

## size
```v
fn (vs VisibleString) size() int
```


[[Return to contents]](#Contents)

## encode
```v
fn (vs VisibleString) encode() ![]u8
```


[[Return to contents]](#Contents)

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

[[Return to contents]](#Contents)

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

[[Return to contents]](#Contents)

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

[[Return to contents]](#Contents)

## tag
```v
fn (obj AsnObject) tag() Tag
```


[[Return to contents]](#Contents)

## length
```v
fn (obj AsnObject) length() int
```


[[Return to contents]](#Contents)

## size
```v
fn (obj AsnObject) size() int
```


[[Return to contents]](#Contents)

## encode
```v
fn (obj AsnObject) encode() ![]u8
```

encode serialize ASN.1 object to bytes array. its return error on fail.  

[[Return to contents]](#Contents)

#### Powered by vdoc. Generated on: 30 Mar 2023 15:00:53