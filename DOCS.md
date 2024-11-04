# `asn1` module documentation.

## About `asn1` module

`asn1` is a `experimental` pure V module for handling Abstract Syntax Notation One (ASN.1) [[X.680]](http://www.itu.int/rec/T-REC-X.680/en) objects encoded in Distinguished Encoding Rules (DER) [[X.690]](https://www.itu.int/rec/T-REC-X.690/en) encoding scheme.

## About this document

This document is intended to serve as documentation of internal details of this asn1 module.
Its describes some parts of the module in the way is implemented, the lack and also issues or limitation we have found around it.

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
  - [Decoding function](#der_decode-function)
  - [Example](#example)
- [Module Index](#module-index)
  - [ASN.1 Class](#class)
  - [Tag Type](#tagtype)
  - [NULL](#null)
  - [BOOLEAN](#boolean)
  - [INTEGER](#integer)
  - [ENUMERATED](#enumerated)
  - [BIT STRING](#bitstring)
  - [OCTET STRING](#octetstring)
  - [OBJECT IDENTIFIER](#oid)
  - [UTF8STRING](#utf8string)
  - [IA5STRING](#ia5string)
  - [PRINTABLE STRING](#printablestring)
  - [VISIBLE STRING](#visiblestring)
  - [UTCTIME](#utctime)
  - [GENERALIZED TIME](#generalizedtime)
  - [Sequence Type](#sequence)
  - [Set Type](#set)
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

Every ASN.1 type has a tag which acts as an identifier of some ASN.1 element. The tag is byte or series of bytes that describing class of the ASN.1 object, constructed (contains other object) or primitive and a non negative tag number.

ASN.1 Tag identifier was represented by this compact structure, ie,

```v
struct Tag {
mut:
	class       TagClass
	constructed bool
	number      int
}
```

Where `TagClass` represent class of ASN.1 type. There are four class of ASN.1 type represented in:

```v
enum TagClass {
	universal = 0x00
	application = 0x01
	context = 0x02
	private = 0x03
}
```

### Limitation of the Tag in this module.

There are two form how the ASN.1 tag was represented, ie, short form tag for tag number below 31 and long form tag (multi byte tag) for representing tag number bigger than 31.

This module support both of form, but the size (length) is limited to `max_tag_length` constant, currently set to 3 bytes length.
This effectively limits the tag number supported by this module to be in 0..16.383 number ranges.
See comment on `core.v` file for the background on this

When your tag has a class of `universal` type, your tag nunber also be limited to be under 255, hopefully if your tag is universal type, just use universal type supported by this module.

### Create ASN.1 Tag

Most of the time, you don't need create tag structure manually, all basic universal type constructor set it for you internally, but for convenience, you can create a new tag, with the following constructor:

```v
fn Tag.new(c TagClass, constructed bool, number int) !Tag
```

where `c` is the ASN.1 class this object belong to, `constructed` boolean flag tells if this object constructed or primitive, and provided tag `number`.

### Serializing tag into bytes

You can serialize (encode) your tga with method defined in this module,

```v
fn (t Tag) encode(mut dst []u8) !
```

By default, `encode` would try to serialize tag in DER rule into destination buffer provided in `dst`, or returns error on fails.

### Read ASN.1 Tag from bytes

This module provides routine for reading tag from bytes. You can use

```v
fn Tag.from_bytes(bytes []u8) !(Tag, []u8)
```

It would create a tag from bytes, and return a tag and remaining bytes (bytes after tag) on success, or returns error on fails.

### ASN.1 Length handling

ASN.1 length indicates how many bytes you should read to get values or contents part. It always represents the total number of bytes in the object including all sub-objects but does not include the lengths of the identifier or of the length field itself.

The standard of X.690 ITU document defines two length types

- definite length, and
- indefinite length.

ASN.1 definite length comes in two form: short and long form. The short form fits in single byte for length between 0 and 127, and the others is long form in multi byte form.

> **Note**
> This module only support definite length but its only limited to DER encoding of length.
> Theoretically, definite length support for very big number for length value, ie, value between 0 and 2^1008-1, but in this module, this limited to pre-defined constant, `max_definite_length_count` set to 6 bytes currently, and `max_definite_length_value` set to builtin `max_int`.

ASN.1 length was represented in a simple type, ie,

```v
type Length = int
```

You can create a length from regular integer with

```v
fn Length.new(v int) !Length
```

and, you can read a length from bytes with

```v
fn Length.from_bytes(bytes []u8) !(Length, []u8)
```

It would return a length and remaining bytes on succes or error on fails.

### Serializing ASN.1 Length

This module provides method to serialize the length into destination buffer,

```v
fn (v Length) encode(mut dst []u8) !
```

## ASN.1 Element

At the core for support handling element in generic and concise way, a fundamental and abstracted way provided in this module is an `Element` interface, dedined as

```v
interface Element {
    tag()     Tag
    payload() ![]u8
}
```

where the `tag` acts as an identifier of the element and `payload` tells the value's part of the element.
The `payload` methods of the `Element` does not dictates on how your element generates payload. Its up to specific encoding rules or other constraints.

> **Note**
> Most of the functions or methods defined in this module was accept or return an `Element`.
> Most of them is implemented with DER encoding in mind, so, your custom element hopefylly would be supported by this functions (methods) if your element correctly implemented required constraints in this module.

### Serializing ASN.1 Element

This modules provides several functions for serializing ASN.1 Element, in three forms, ie:

```v
fn encode(el Element) ![]u8
fn encode_with_options(el Element, opt string) ![]u8
fn encode_with_field_options(el Element, fo FieldOptions) ![]u8
```
All of three's functions produces bytes result on success or error on fails. The two latest form is serialization routines intended for
serializing element with wrapping, optional or default semantic to existing element, gives you a extra flexibility to the serialization
(deserialization) process.
For more information in detail, see [FieldOptions](#flexible-asn1-element-serialization-with-fieldoptions)

### Example 
A PrintableString containing “hi” was serialized into 13 02 68 69.
```v
obj := asn1.PrintableString.new('hi')!
output := asn1.encode(obj)!

assert output == [u8(0x13), 0x02, 0x68, 0x69]
```
When your element is tagged type element, defined with `[5] IMPLICIT PrintableString`, you can pass
a string option into `encode`, ie:
```v
output := encode_with_options(obj, 'context_specific:5;implicit;inner:19')!
assert output == [u8(0x85), 0x02, 0x68, 0x69]
```
Or when its a explicit tagged element defined as `[5] EXPLICIT PrintableString`
```v
output := encode_with_options(obj, 'context_specific:5;explicit;inner:0x13')!
assert output == [u8(0xA5), 0x04, 0x13, 0x02, 0x68, 0x69]
```

### Deserializing ASN.1 DER bytes into Element
For deserialization purposes, this module provides functions with similar in serialization parts, ie, in the form:
```v
fn decode(src []u8) !Element
fn decode_with_options(bytes []u8, opt string) !Element
fn decode_with_field_options(bytes []u8, fo FieldOptions) !Element
```
Technically, the deserialization mechanism is reverse of serialization process. When you pass an options to decode routine,
you should ensure its a same options used for serialization in `encode` part, or the decode would result in undefined behaviour
if its differs.

The `decode` function families, accepts DER serialized bytes, and an options (if its should be) and return some `Element`, 
or return error on fails. When you get result an `Element` from `decode` routine, you can get underlying object by calling `into_object` 
method on the element.
```v
fn (el Element) into_object[T]() !T
```
Examples:
```v
el := asn1.decode([u8(0x13), 0x02, 0x68, 0x69])!
ps := el.into_object[asn1.PrintableString]()!
```
So, its also happens to pass an options string when this bytes comes from serialized tagged type element,
```v
obj := asn1.decode_with_options([u8(0xA5), 0x04, 0x13, 0x02, 0x68, 0x69], 'context_specific:5;explicit;inner:0x13')!
```

## Flexible ASN.1 Element Serialization (Deserialization) with FieldOptions.
For supporting more complex scenarios, inspired by the same options used in go version of `asn1` module, this module comes with
support configures serialization (deserialization) process through configuration options stored in `FieldOptions` structure.

Consider some Certificate structure represents more complex ASN.1 schemas from [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2),
```asn1
 Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  
	}

   TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL
   }
```
This schema required support for other machinery in the form of tagged element (we call it wrapping semantic), 
OPTIONAL keyword handling, and DEFAULT keyword handling, through the `FieldOptions` structures defined as:
```v
struct FieldOptions {
mut:
	// For wrapping purposes
	cls           string
	tagnum        int = -1
	mode          string
	inner         string

	// for OPTIONAL handling
	optional      bool
	present       bool
	
	// FOR DEFAULT handling
	has_default   bool
	default_value ?Element
}
```
The main purpose of this options structures is used for:
- handling of wrapping some element, turn some element into another element.
- handling of OPTIONAL element.
- handling of element with DEFAULT keywoard.

### Wrapping an Element through FieldOptions
There are two constructor for construct a `FieldOptions`, ie 
```v
fn FieldOptions.from_string(s string) !FieldOptions
fn FieldOptions.from_attrs(attrs []string) !FieldOptions
```
The first function allowing you pass a string as an options, likes an examples above.
Examples:
```v
fo := FieldOptions.from_string('context_specific:5;explicit;inner:0x13')!
fo := FieldOptions.from_string('context_specific:5;explicit;inner:0x13;optional')!
```

The second form, is gives more controllable options, and its allowing tag your field of struct
with the supported options,
Examples :
```v
struct PersonnelRecord {
mut:
	name     asn1.OctetString @[context_specific: 0; implicit; inner: 4]
	location asn1.Integer     @[context_specific: 1; implicit; inner: 2]
	age      asn1.Integer     @[context_specific: 2; implicit; inner: 2]
}

attrs := ['context_specific: 0', 'implicit', 'inner: 4']
fo := FieldOptions.from_attrs(attrs)!
// and then you can pass the options to serialization phase
out := asn1.encode(p.name, fo)!
```

### Handling optional with FieldOptions
The field `optional` and `present` of the `FieldOptions` was used for handling OPTINAL semantic of the element.
The mean of the flags:
- when `optional` bit was set into `true`, thats mean, the element treated as element with OPTIONAL semantic.
- when `present` bit was set into `true`, this optional element mean was present in the encoding data, by default optional was not included in the encoding phase (not present)

### Handling element with DEFAULT keyword
Element with DEFAULT keyword, by DER encoding rule, when the element is equal with default value provided, its not present 
in the serialized bytes. For this purposes, before serialization, you should call 
```v
fn (el Element) set_default_value(mut fo FieldOptions, value Element) !
``` 
to setup default value within the options for the current element, or would be error if `has_default` flag is set but default value
is not availables.

## Supported basic UNIVERSAL ASN.1 Type

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

## Support for non-universal class of ASN.1 Element
When your element is non-universal class, this module has a limited support for this type of element.
Its represented in several structures, defined as :
```v
pub struct RawElement {
mut:
	// The tag is the (outer) tag of the TLV, if this a wrpper.
	tag Tag
	// `content` is the value of a TLV. Its depends on the context.
	content []u8
	// optional fields
	inner_tag     ?Tag
	mode          ?TaggedMode
	default_value ?Element
}

pub struct ContextElement {
	RawElement
}

pub struct ApplicationElement {
	RawElement
}

pub struct PrivateELement {
	RawElement
}
```

## Create Basic ASN.1 Type

You can use following function to create basic UNIVERSAL ASN.1 type. Most of the constructor return `Encoder` interfaces.

> **Note**
>
> By default, all basic constructor has ASN.1 UNIVERSAL class tag, and the tag number is universal tag number defined in [`TagType`](#tagtype) enum, where
> constructed flag set to `true` value by default on SEQUENCE (SEQUENCE OF) and SET (SET OF) type.
> Some of the tag number was not supported in this module.

| No  | Function                                      |     ASN.1 Object      | Description                                                                      |
| :-: | --------------------------------------------- | :-------------------: | -------------------------------------------------------------------------------- |
|  1  | [new_boolean](#new_boolean)                   |        BOOLEAN        |                                                                                  |
|  2  | [new_integer](#new_integer)                   |        INTEGER        |                                                                                  |
|  3  | [new_bitstring](#new_bitstring)               |       BITSTRING       | its accepts arbitrary v string, not a bit string                                 |
|  4  | [new_octetstring](#new_octetstring)           |     OCTET STRING      |                                                                                  |
|  5  | [new_null](#new_null)                         |         NULL          |                                                                                  |
|  6  | [new_oid_from_string](#new_oid_from_string)   |   OBJECT IDENTIFIER   |                                                                                  |
|  7  | [new_enumerated](#new_enumerated)             |      ENUMERATED       |                                                                                  |
|  8  | [new_utf8string](#new_utf8string)             |      UTF8STRING       |                                                                                  |
|  9  | [new_sequence](#new_sequence)                 | SEQUENCE, SEQUENCE OF | for sequence of, you should ensure you add the same object to sequence elements. |
| 10  | [new_set](#new_set)                           |      SET, SET OF      | likes a sequence of, ensure add the same object to set elements                  |
| 11  | [new_numeric_string](#new_numeric_string)     |    NUMERIC STRING     |                                                                                  |
| 12  | [new_printable_string](#new_printable_string) |   PRINTABLE STRING    |                                                                                  |
| 13  | [new_ia5string](#new_ia5string)               |       IA5STRING       |                                                                                  |
| 14  | [new_utctime](#new_utctime)                   |        UTCTIME        |                                                                                  |
| 15  | [new_generalizedtime](#new_generalizedtime)   |   GENERALIZED TIME    |                                                                                  |
| 16  | [new_visiblestring](#new_visiblestring)       |     VISIBLESTRING     |                                                                                  |

[[Return to contents]](#table-of-contents)

## Reference

1. [ASN.1](https://en.wikipedia.org/wiki/ASN.1)
2. [A Warm Welcome to ASN.1 and DER](https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/)
3. [A Layman's Guide to a Subset of ASN.1, BER, and DER](https://luca.ntop.org/Teaching/Appunti/asn1.html)
4. [X.690 PDF](https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf)
5. [X.680 PDF](https://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf)
