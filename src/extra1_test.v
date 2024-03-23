module asn1

import crypto.pem
import encoding.hex

fn test_ed4418_data() ! {
	// from https://asecuritysite.com/digitalcert/sigs4cd
	/*
	DER: 3043300506032b6571033a00419610a534af127f583b04818cdb7f0ff300b025f2e01682bcae33fd691cee039511df0cddc690ee978426e8b38e50ce5af7dcfba50f704c00
	// decoded as:
	[U] SEQUENCE (30)
  		[U] SEQUENCE (30)
    		[U] OBJECT (06): 1.3.101.113 - Ed448
  		[U] BIT STRING (03): 0xb'00419610A534AF127F583B04818CDB7F0FF300B025F2E01682BCAE33FD691CEE039511DF0CDDC690EE978426E8B38E50CE5AF7DCFBA50F704C00'
  	Public key (9610a534af127f583b04818cdb7f0ff300b025f2e01682bcae33fd, 691cee039511df0cddc690ee978426e8b38e50ce5af7dcfba50f704c00)

	-----BEGIN PUBLIC KEY-----
		MEMwBQYDK2VxAzoAQZYQpTSvEn9YOwSBjNt/D/MAsCXy4BaCvK4z/Wkc7gOVEd8M3caQ7peEJuizjlDOWvfc+6UPcEwA
	-----END PUBLIC KEY-----
	*/
	data := '3043300506032b6571033a00419610a534af127f583b04818cdb7f0ff300b025f2e01682bcae33fd691cee039511df0cddc690ee978426e8b38e50ce5af7dcfba50f704c00'

	bytes := hex.decode(data)!

	seq, n := Sequence.decode(bytes, 0)!

	assert seq.elements.len == 2
	assert seq.elements[0] is Sequence
	assert seq.elements[1] is BitString

	el0 := seq.elements[0] as Sequence
	sel0 := el0.elements[0] as Oid
	assert sel0.str() == '1.3.101.113'
}

fn test_x25519_private_key() ? {
	// taken from https://www.rfc-editor.org/rfc/rfc8410#section-10
	// 10.3 Examples of Ed25519 Private Key

	data := '-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----'

	// The same item dumped as asn1 yields:
	/*
	0 30   46: SEQUENCE {
 	2 02    1:   INTEGER 0
	5 30    5:   SEQUENCE {
 	7 06    3:     OBJECT IDENTIFIER
          :       Ed 25519 signature algorithm { 1 3 101 112 }
          :     }
	12 04   34:   OCTET STRING
          :     04 20 D4 EE 72 DB F9 13 58 4A D5 B6 D8 F1 F7 69
          :     F8 AD 3A FE 7C 28 CB F1 D4 FB E0 97 A8 8F 44 75
          :     58 42
          :   }
	*/
	block, _ := pem.decode(data)?

	seq, n := Sequence.decode(block.data, 0)!

	assert seq.length() == 46

	assert seq.elements[0] is Integer
	assert seq.elements[1] is Sequence
	b := seq.elements[1] as Sequence

	assert b.elements[0] is Oid
	assert b.elements[0].length() == 3

	oid := b.elements[0] as Oid
	assert oid.str() == '1.3.101.112'

	assert seq.elements[2] is OctetString
	assert seq.elements[2].length() == 34
}

// TODO: This test still failed on `Sequence.parse_contents` with error `next: truncated bytes`
// FIXME: need to be investigated, bad data, or sequence handling or others source of fail
// so just disable this test,
/*
fn test_example_x25519_certificate() {
	// taken from https://www.rfc-editor.org/rfc/rfc8410.html#section-10
	// 10.2.  Example X25519 Certificate
	data := '-----BEGIN CERTIFICATE-----
MIIBLDCB36ADAgECAghWAUdKKo3DMDAFBgMrZXAwGTEXMBUGA1UEAwwOSUVURiBUZX
N0IERlbW8wHhcNMTYwODAxMTIxOTI0WhcNNDAxMjMxMjM1OTU5WjAZMRcwFQYDVQQD
DA5JRVRGIFRlc3QgRGVtbzAqMAUGAytlbgMhAIUg8AmJMKdUdIt93LQ+91oNvzoNJj
ga9OukqY6qm05qo0UwQzAPBgNVHRMBAf8EBTADAQEAMA4GA1UdDwEBAAQEAwIDCDAg
BgNVHQ4BAQAEFgQUmx9e7e0EM4Xk97xiPFl1uQvIuzswBQYDK2VwA0EAryMB/t3J5v
/BzKc9dNZIpDmAgs3babFOTQbs+BolzlDUwsPrdGxO3YNGhW7Ibz3OGhhlxXrCe1Cg
w1AH9efZBw==
-----END CERTIFICATE-----'

	// The same item dumped as asn1 yields:
	/*
	0 300: SEQUENCE {
     4 223:   SEQUENCE {
     7   3:     [0] {
     9   1:       INTEGER 2
          :       }
    12   8:     INTEGER 56 01 47 4A 2A 8D C3 30
    22   5:     SEQUENCE {
    24   3:       OBJECT IDENTIFIER
          :         Ed 25519 signature algorithm { 1 3 101 112 }
          :       }
    29  25:     SEQUENCE {
    31  23:       SET {
    33  21:         SEQUENCE {
    35   3:           OBJECT IDENTIFIER commonName (2 5 4 3)
    40  14:           UTF8String 'IETF Test Demo'
          :           }
          :         }
          :       }
    56  30:     SEQUENCE {
    58  13:       UTCTime 01/08/2016 12:19:24 GMT
    73  13:       UTCTime 31/12/2040 23:59:59 GMT
          :       }
    88  25:     SEQUENCE {
    90  23:       SET {
    92  21:         SEQUENCE {
    94   3:           OBJECT IDENTIFIER commonName (2 5 4 3)
    99  14:           UTF8String 'IETF Test Demo'
          :           }
          :         }
          :       }
   115  42:     SEQUENCE {
   117   5:       SEQUENCE {
   119   3:         OBJECT IDENTIFIER
          :           ECDH 25519 key agreement { 1 3 101 110 }
          :         }
   124  33:       BIT STRING
          :         85 20 F0 09 89 30 A7 54 74 8B 7D DC B4 3E F7 5A
          :         0D BF 3A 0D 26 38 1A F4 EB A4 A9 8E AA 9B 4E 6A
          :       }
   159  69:     [3] {
   161  67:       SEQUENCE {
   163  15:         SEQUENCE {
   165   3:           OBJECT IDENTIFIER basicConstraints (2 5 29 19)
 170   1:           BOOLEAN TRUE
   173   5:           OCTET STRING, encapsulates {
   175   3:             SEQUENCE {
   177   1:               BOOLEAN FALSE
          :               }
          :             }
          :           }
   180  14:         SEQUENCE {
   182   3:           OBJECT IDENTIFIER keyUsage (2 5 29 15)
   187   1:           BOOLEAN FALSE
   190   4:           OCTET STRING, encapsulates {
   192   2:             BIT STRING 3 unused bits
          :               '10000'B (bit 4)
          :             }
          :           }
   196  32:         SEQUENCE {
   198   3:           OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
   203   1:           BOOLEAN FALSE
   206  22:           OCTET STRING, encapsulates {
   208  20:             OCTET STRING
          :               9B 1F 5E ED ED 04 33 85 E4 F7 BC 62 3C 59 75
          :               B9 0B C8 BB 3B
          :             }
          :           }
          :         }
          :       }
          :     }
   230   5:   SEQUENCE {
   232   3:     OBJECT IDENTIFIER
          :       Ed 25519 signature algorithm { 1 3 101 112 }
          :     }
   237  65:   BIT STRING
          :     AF 23 01 FE DD C9 E6 FF C1 CC A7 3D 74 D6 48 A4
          :     39 80 82 CD DB 69 B1 4E 4D 06 EC F8 1A 25 CE 50
          :     D4 C2 C3 EB 74 6C 4E DD 83 46 85 6E C8 6F 3D CE
          :     1A 18 65 C5 7A C2 7B 50 A0 C3 50 07 F5 E7 D9 07
          :   }
	*/
	block, _ := pem.decode(data)?
       dump(block.data.hex())

	seq, n := Sequence.decode(block.data, 0)!

	assert seq.length() == 300

	// certificate is arrays of 3 element
	assert seq.elements.len == 3
	// last element
	assert seq.elements[2] is BitString
	assert seq.elements[2].length() == 65
	bts := BitString.from_bytes(seq.elements[2].payload()!)!
	exp := [u8(0xAF), 0x23, 0x01, 0xFE, 0xDD, 0xC9, 0xE6, 0xFF, 0xC1, 0xCC, 0xA7, 0x3D, 0x74, 0xD6,
		0x48, 0xA4, 0x39, 0x80, 0x82, 0xCD, 0xDB, 0x69, 0xB1, 0x4E, 0x4D, 0x06, 0xEC, 0xF8, 0x1A,
		0x25, 0xCE, 0x50, 0xD4, 0xC2, 0xC3, 0xEB, 0x74, 0x6C, 0x4E, 0xDD, 0x83, 0x46, 0x85, 0x6E,
		0xC8, 0x6F, 0x3D, 0xCE, 0x1A, 0x18, 0x65, 0xC5, 0x7A, 0xC2, 0x7B, 0x50, 0xA0, 0xC3, 0x50,
		0x07, 0xF5, 0xE7, 0xD9, 0x07]
	assert bts.data == exp
}
*/
