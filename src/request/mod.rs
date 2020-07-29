use serde::{Deserialize, Serialize};
use std::convert::TryInto;

lazy_static! {
    static ref REQUEST_HEADER_SIZE: u64 = bincode::serialized_size(&RequestHeader::default())
        .expect("Unable to get size of default RequestHeader.");
}

/// All possible algorithms that can be requested.
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary, Debug))]
#[repr(C)]
pub enum Algorithm {
    NoAlgorithm,
    FRODO640__ECDHp256,
    FRODO640,
    FRODO976__ECDHp384,
    FRODO976,
    FRODO1344__ECDHp521,
    FRODO1344,
    NTRU_HRSS_701,
    NTRU_HRSS_701__ECDHp256,
    NTRU_HPS_2048509,
    NTRU_HPS_2048509__ECDHp256,
    RND5_1CCA_5D,
    RND5_1CCA_5D__ECDHp256,
    RND5_3CCA_5D,
    RND5_3CCA_5D__ECDHp384,
    RND5_5CCA_5D,
    RND5_5CCA_5D__ECDHp521,
    KYBER_512,
    KYBER_512__ECDHp256,
    KYBER_768,
    KYBER_768__ECDHp384,
    KYBER_1024,
    KYBER_1024__ECDHp521,
    SABER_LIGHT,
    SABER_LIGHT__ECDHp256,
    SABER,
    SABER__ECDHp384,
    SABER_FIRE,
    SABER_FIRE__ECDHp521,
}

/// All possible operations that can be requested.
#[derive(Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary, Debug))]
#[repr(C)]
pub enum Operation {
    NoOperation,
    KeypairGeneration,
    Encapsulation,
    Decapsulation,
}

// Necessary so we can get a default size of RequestHeader at run-time so C knows
// what size buffer to allocate.
impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::NoAlgorithm
    }
}

impl Default for Operation {
    fn default() -> Self {
        Operation::NoOperation
    }
}

// Ensure that RequestHeader always has a fixed size! If this size changes then change version number!
/// Header that describes the request sent.
/// # Explanation of the header
/// - version is used for compatibility reasons. Typically there is no need to do anything with this
///   as pq_message_lib deals with version internally.
/// - identifier is used so that the receiver of the `RequestHeader` can link it back to the original request.
/// - data_len describes the length of the upcoming data that belongs to this `RequestHeader`. The data after that
///   will belong to a new `RequestHeader`.
/// - algorithm is the `Algorithm` that the request is about.
/// - operation is the `Operation` that the request is about.
#[derive(Serialize, Deserialize, Default, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary, Debug))]
pub struct RequestHeader {
    pub version: u8,
    pub identifier: u64,
    pub data_len: u32,
    pub algorithm: Algorithm,
    pub operation: Operation,
}

/// Convenience struct to allow request body to be stored together together with the header.
pub struct Request {
    pub header: RequestHeader,
    pub body: Vec<u8>,
}

/// Returns the size needed for the buffer where the serialized request header will be stored.
/// Will evaluate only when used for the first time.
#[no_mangle]
pub extern "C" fn get_serialized_request_header_size() -> u64 {
    *REQUEST_HEADER_SIZE
}

/// Receive a serialized header. Simply attach the raw bytes behind this serialized header when sending
/// over a channel.
/// # Returns
/// 0 on success, -1 on serialization failure.
/// # Safety
/// Ensure that `target_buffer` is large enough before executing this function.
#[no_mangle]
pub unsafe extern "C" fn serialize_request_header(
    target_buffer: *mut libc::c_uchar,
    target_buffer_len: libc::size_t,
    identifier: u64,
    data_len: u32,
    algorithm: Algorithm,
    operation: Operation,
) -> i16 {
    if target_buffer.is_null() || target_buffer_len < get_serialized_request_header_size() as usize
    {
        return -1;
    }

    let request_header = RequestHeader {
        version: crate::FORMAT_VERSION,
        identifier,
        data_len,
        algorithm,
        operation,
    };

    if let Ok(encoded) = bincode::serialize(&request_header) {
        std::ptr::copy_nonoverlapping(encoded.as_ptr(), target_buffer, encoded.len());
        0
    } else {
        // Unsure whether this is actually reachable but produce an error just in case so we don't crash.
        // Maybe in case of out-of-memory this can occur?
        -1
    }
}

/// Given a a buffer will return a `ResponseHeader`. This header can be used to determine how many bytes
/// of data are coming up.
/// # Returns
/// A RequestHeader for success. Anything else is a DeserializationError (e.g. when the provided buffer is too short)
pub fn deserialize_request_header(
    request_header: &[u8],
) -> Result<RequestHeader, crate::DeserializationError> {
    bincode::deserialize(&request_header).map_err(|_| crate::DeserializationError)
}

/// Function which will put a `RequestHeader` and data together in a `Request`.
/// This is purely a convenience function such that one can operate on a `Request` instead
/// of keeping the header and data separate.
pub fn deserialize_request(request_header: RequestHeader, request_data: Vec<u8>) -> Request {
    Request {
        header: request_header,
        body: request_data,
    }
}

/// Given the length of two entries returns the length of the buffer required to fit both entries including their lengths.
#[no_mangle]
pub extern "C" fn structure_two_entries_length(
    entry1_length: libc::size_t,
    entry2_length: libc::size_t,
) -> libc::size_t {
    entry1_length + entry2_length + 2 * std::mem::size_of::<usize>()
}

/// Given two entries and their length this function will put them back-to-back into data with length included.
/// # Returns
/// 0 on success.
/// -1 when data was a null pointer.
/// -2 when entry1 was a null pointer.
/// -3 when entry2 was a null pointer.
/// # Safety
/// If entry1_length or entry2_length are not appropriate (too long for example) then an out of bounds
/// access will occur; this is a bug introduced by the caller. When used in combination with the
/// `structure_two_entries_length` function this will never occur.
#[no_mangle]
pub unsafe extern "C" fn structure_two_entries(
    data: *mut libc::c_uchar,
    entry1_length: libc::size_t,
    entry2_length: libc::size_t,
    entry1: *const libc::c_uchar,
    entry2: *const libc::c_uchar,
) -> i16 {
    if data.is_null() {
        return -1;
    } else if entry1.is_null() {
        return -2;
    } else if entry2.is_null() {
        return -3;
    }

    let usize_size_in_bytes = std::mem::size_of::<usize>();
    std::ptr::copy_nonoverlapping(
        entry1_length.to_le_bytes().as_ptr(),
        data,
        usize_size_in_bytes,
    );

    let data = data.add(usize_size_in_bytes);
    std::ptr::copy(entry1, data, entry1_length);

    let data = data.add(entry1_length);
    std::ptr::copy_nonoverlapping(
        entry2_length.to_le_bytes().as_ptr(),
        data,
        usize_size_in_bytes,
    );

    let data = data.add(usize_size_in_bytes);
    std::ptr::copy(entry2, data, entry2_length);

    0
}

/// Given a buffer which was constructed using `structure_two_entries` this function will structure
/// it back into two separate slices. A `DestructureError` will be returned in case
/// this is not possible or would cause safety issues.
pub fn destructure_two_entries(data: &[u8]) -> Result<(&[u8], &[u8]), crate::DestructureError> {
    let usize_size_in_bytes = std::mem::size_of::<usize>();
    let entry1_length = data
        .get(..usize_size_in_bytes)
        .ok_or(crate::DestructureError)?;
    let rest = &data[usize_size_in_bytes..];

    let entry1_length = usize::from_le_bytes(
        entry1_length
            .try_into()
            .map_err(|_| crate::DestructureError)?,
    );
    let entry1 = rest.get(..entry1_length).ok_or(crate::DestructureError)?;
    let rest = &rest[entry1_length..];

    let entry2_length = rest
        .get(..usize_size_in_bytes)
        .ok_or(crate::DestructureError)?;
    let rest = &rest[usize_size_in_bytes..];

    let entry2_length = usize::from_le_bytes(
        entry2_length
            .try_into()
            .map_err(|_| crate::DestructureError)?,
    );
    let entry2 = rest.get(..entry2_length).ok_or(crate::DestructureError)?;

    Ok((entry1, entry2))
}
