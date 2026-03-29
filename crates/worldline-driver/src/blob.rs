//! EIP-4844 blob encoding for ZK proof batch data.
//!
//! Encodes proof batch bytes into the 4096-field-element blob format required
//! by EIP-4844. Each 32-byte field element holds 31 bytes of data with the
//! high byte set to 0x00 to guarantee values below the BLS12-381 field modulus.

use crate::error::BlobError;

/// EIP-4844 constants
pub const BYTES_PER_FIELD_ELEMENT: usize = 32;
pub const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
pub const BYTES_PER_BLOB: usize = BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB;
pub const USABLE_BYTES_PER_ELEMENT: usize = 31;
pub const MAX_BLOB_DATA_BYTES: usize = FIELD_ELEMENTS_PER_BLOB * USABLE_BYTES_PER_ELEMENT;

/// Encodes arbitrary bytes into EIP-4844 blob format.
///
/// Each 32-byte field element stores 31 bytes of data. The high byte (index 0
/// within each element) is always 0x00, ensuring all field elements are below
/// the BLS12-381 field modulus.
///
/// # Errors
/// Returns an error if `data.len() > MAX_BLOB_DATA_BYTES`.
pub fn encode_as_blob(data: &[u8]) -> Result<Vec<u8>, BlobError> {
    if data.len() > MAX_BLOB_DATA_BYTES {
        return Err(BlobError::TooLarge {
            size: data.len(),
            max: MAX_BLOB_DATA_BYTES,
        });
    }

    let mut blob = vec![0u8; BYTES_PER_BLOB];

    for (i, &byte) in data.iter().enumerate() {
        let element_index = i / USABLE_BYTES_PER_ELEMENT;
        let byte_offset = (i % USABLE_BYTES_PER_ELEMENT) + 1; // +1 keeps high byte 0x00
        blob[element_index * BYTES_PER_FIELD_ELEMENT + byte_offset] = byte;
    }

    Ok(blob)
}

/// Decodes a blob back into the original data bytes.
///
/// This is the inverse of `encode_as_blob`. Requires the original data length
/// to trim trailing zero-padding.
///
/// # Errors
/// Returns an error if `blob.len() != BYTES_PER_BLOB`.
pub fn decode_blob(blob: &[u8], data_length: usize) -> Result<Vec<u8>, BlobError> {
    if blob.len() != BYTES_PER_BLOB {
        return Err(BlobError::InvalidBlobSize {
            expected: BYTES_PER_BLOB,
            actual: blob.len(),
        });
    }

    let mut data = vec![0u8; data_length];
    for (i, byte) in data.iter_mut().enumerate() {
        let element_index = i / USABLE_BYTES_PER_ELEMENT;
        let byte_offset = (i % USABLE_BYTES_PER_ELEMENT) + 1;
        *byte = blob[element_index * BYTES_PER_FIELD_ELEMENT + byte_offset];
    }

    Ok(data)
}

/// Validates that all field elements in a blob are below the BLS12-381 modulus.
///
/// The modulus is:
/// 52435875175126190479447740508185965837690552500527637822603658699938581184513
///
/// Since our encoding always sets the high byte to 0x00, this check should always
/// pass for blobs created by `encode_as_blob`. Use this to validate externally
/// produced blobs.
pub fn validate_blob_field_elements(blob: &[u8]) -> Result<(), BlobError> {
    if blob.len() != BYTES_PER_BLOB {
        return Err(BlobError::InvalidBlobSize {
            expected: BYTES_PER_BLOB,
            actual: blob.len(),
        });
    }

    // BLS modulus high byte check: the high byte of each field element must be 0x00
    // for values to be guaranteed in-field (since BLS_MODULUS < 2^255)
    for i in 0..FIELD_ELEMENTS_PER_BLOB {
        let high_byte = blob[i * BYTES_PER_FIELD_ELEMENT];
        if high_byte != 0x00 {
            return Err(BlobError::InvalidFieldElement {
                index: i,
                byte: high_byte,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = b"Hello, Worldline blob encoding test!";
        let blob = encode_as_blob(original).expect("encode failed");
        assert_eq!(blob.len(), BYTES_PER_BLOB);

        let decoded = decode_blob(&blob, original.len()).expect("decode failed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_encode_max_size() {
        let data = vec![0xABu8; MAX_BLOB_DATA_BYTES];
        let blob = encode_as_blob(&data).expect("encode failed");
        assert_eq!(blob.len(), BYTES_PER_BLOB);

        let decoded = decode_blob(&blob, MAX_BLOB_DATA_BYTES).expect("decode failed");
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_too_large() {
        let data = vec![0u8; MAX_BLOB_DATA_BYTES + 1];
        assert!(encode_as_blob(&data).is_err());
    }

    #[test]
    fn test_high_bytes_are_zero() {
        let data = vec![0xFFu8; 1024];
        let blob = encode_as_blob(&data).expect("encode failed");
        validate_blob_field_elements(&blob).expect("field element validation failed");
    }

    #[test]
    fn test_empty_data() {
        let blob = encode_as_blob(&[]).expect("encode failed");
        let decoded = decode_blob(&blob, 0).expect("decode failed");
        assert!(decoded.is_empty());
    }
}
