module asn1

import io

interface Encoder {
	encoded_len() !Length
	encode(writer io.Writer) !
}

interface Decoder {
	decode(mut reader Asn1Reader) !Decoder
}

fn Decoder.from_bytes(bytes []u8) !Decoder {
	return error('not implemented')
}

struct Header {
	tag    Tag
	length Length
}

interface Asn1Reader {
	// Get the length of the input.
	input_len() Length
	// Peek at the next byte of input without modifying the cursor.
	peek_byte() ?u8
	// Peek forward in the input data, attempting to decode a Header from the data at the current position in the decoder.
	// Does not modify the decoder’s state.
	peek_header() !Header
	// Get the position within the buffer.
	position() Length
	// Attempt to read data borrowed directly from the input as a slice, updating the internal cursor position.
	// Returns
	// Ok(slice) on success
	// Err(ErrorKind::Incomplete) if there is not enough data
	// Err(ErrorKind::Reader) if the reader can’t borrow from the input
	read_slice(lenght Length) ![]u8
}

interface ValueDecoder {
	decode_value(mut reader Asn1Reader, header Header) !ValueDecoder
}

struct BytesReader {
	// Byte slice being decoded.
	bytes  []u8
	failed bool
	/// Position within the decoded slice.
	position Length
}

fn BytesReader.new(bytes []u8) !&BytesReader {
	return &BytesReader{
		bytes:    bytes
		position: Length(0)
	}
}
