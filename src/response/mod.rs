use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};

lazy_static! {
    static ref RESPONSE_HEADER_SIZE: u64 = bincode::serialized_size(&ResponseHeader::default())
        .expect("Unable to get size of default RequestHeader.");
}

// The actual data is appended after this header has been serialized since serde
// does not support deserializing dynamically sized structs.
/// Header that describes the response sent.
/// # Explanation of the header
/// - version is used for compatibility reasons. Typically there is no need to do anything with this
///   as pq_message_lib deals with version internally.
/// - identifier is used so that the receiver of the `ResponseHeader` can link it back to the original request.
/// - success indicates there was a failure or not. 0 means success while anything else is a failure.
///   Note that the data_len field will always be 0 when there was a failure.
/// - data_len describes the length of the upcoming data that belongs to this `ResponseHeader`. The data after that
///   will belong to a new `ResponseHeader`.
#[derive(Serialize, Deserialize, Default, PartialEq)]
#[repr(C)]
pub struct ResponseHeader {
    pub version: u8,
    pub identifier: u64,
    pub success: i8,
    pub data_len: u32,
}

/// Convenience struct to allow response body to be stored together together with the header.
#[repr(C)]
pub struct Response {
    pub header: ResponseHeader,
    pub body: *const libc::c_uchar,
}

/// Returns the size needed for the buffer where the serialized response header will be stored.
/// Will evaluate only when used for the first time.
#[no_mangle]
pub extern "C" fn get_serialized_response_header_size() -> u64 {
    *RESPONSE_HEADER_SIZE
}

/// The length of data can at most be 2^32 bytes!
/// In case of error (that is not a SerializationError) this will only return the header
/// with success status not set to 0.
pub fn serialize_response(
    identifier: u64,
    data: Option<&[u8]>,
) -> Result<Vec<u8>, crate::SerializationError> {
    let mut response_header = ResponseHeader {
        version: crate::FORMAT_VERSION,
        identifier,
        ..Default::default()
    };

    match data {
        Some(data) => {
            if let Ok(convert_data_len) = u32::try_from(data.len()) {
                response_header.success = 0;
                response_header.data_len = convert_data_len;
            } else {
                response_header.success = -1;
                response_header.data_len = 0;
            }
        }
        None => {
            response_header.success = -1;
            response_header.data_len = 0;
        }
    };

    let mut serialized =
        bincode::serialize(&response_header).map_err(|_| crate::SerializationError)?;
    if response_header.success == 0 {
        serialized.extend(data.unwrap());
    }

    Ok(serialized)
}

/// Given a pointer will return a `ResponseHeader`. This header can be used to determine how many bytes
/// of data are coming up.
/// # Returns
/// 0 on success.
/// -1 when a null pointer was passed in.
/// -2 for when the header will not fit in memory due to architecture.
/// -3 for deserialization failure.
/// -4 for mismatch of version in header.
/// # Safety
/// Unsafe because there is no absolute guarantee we don't get a pointer handed somewhere
/// in program space that happens to deserialize succesfully to a ResponseHeader.
/// When used in combination with `get_serialized_response_header_size` this function
/// will be able to safely and correctly deserialize a response header.
#[no_mangle]
pub unsafe extern "C" fn deserialize_response_header(
    response_data: *const libc::c_uchar,
    response_header: *mut ResponseHeader,
) -> i16 {
    if response_data.is_null() {
        return -1;
    }

    let response;
    if let Ok(header_size) = usize::try_from(get_serialized_response_header_size()) {
        response = std::slice::from_raw_parts(response_data, header_size);
    } else {
        return -2;
    }

    if let Ok(deserialized) = bincode::deserialize(response) {
        *response_header = deserialized;
    } else {
        return -3;
    }

    if (*response_header).version != crate::FORMAT_VERSION {
        -4
    } else {
        0
    }
}

/// Given two entries and their length this function will put them back-to-back into data with length included.
pub fn structure_two_entries(entry1: &[u8], entry2: &[u8]) -> Vec<u8> {
    let mut structured_data = Vec::new();
    structured_data.extend(&entry1.len().to_le_bytes());
    structured_data.extend_from_slice(entry1);
    structured_data.extend(&entry2.len().to_le_bytes());
    structured_data.extend_from_slice(entry2);

    structured_data
}

/// Given a pointer of a buffer which contains two data fields it will set entry1 and entry2 pointers to those locations
/// within the buffer. Additionally it will set the length appropriately.
/// # Returns
/// 0 on success.
/// -1 when data pointer was null.
/// -2 when entry1_length pointer was null.
/// -3 when entry2_length pointer was null.
/// -4 when entry1 pointer was null.
/// -5 when entry2 pointer was null.
/// -6 or -7 if parsing the lengths is unsuccessful
/// -8 if the provided data would cause an out of bounds access
/// # Safety
/// This function does extensive checking on null pointers and checks whether
/// the lengths provided in the structured data would write past the end of `data`.
/// Having said that, if the caller inputs an invalid `data_size` there is no way
/// for this function to ever realize this; this will not happen unless the caller
/// has a bug since the header will inform the caller how large the buffer should be.
#[no_mangle]
pub unsafe extern "C" fn destructure_two_entries(
    data: *const libc::c_uchar,
    data_size: libc::size_t,
    entry1_length: *mut libc::size_t,
    entry2_length: *mut libc::size_t,
    entry1: *mut *const libc::c_uchar,
    entry2: *mut *const libc::c_uchar,
) -> i16 {
    if data.is_null() {
        return -1;
    } else if entry1_length.is_null() {
        return -2;
    } else if entry2_length.is_null() {
        return -3;
    } else if entry1.is_null() {
        return -4;
    } else if entry2.is_null() {
        return -5;
    }

    let data_start = std::slice::from_raw_parts(data, data_size);
    let usize_size_in_bytes = std::mem::size_of::<usize>();

    // Retrieve and set lengths of entry1
    let unparsed_length = match data_start.get(..usize_size_in_bytes) {
        Some(data) => data,
        None => return -8,
    };
    let data_start = &data_start[usize_size_in_bytes..];

    let parsed_entry1_length = usize::from_le_bytes(match unparsed_length.try_into() {
        Ok(val) => val,
        Err(_) => return -6,
    });
    if parsed_entry1_length > data_start.len() {
        return -8;
    }
    *entry1_length = parsed_entry1_length;
    *entry1 = data_start.as_ptr();

    let data_start = &data_start[parsed_entry1_length..];

    // Retrieve and set lengths of entry2
    let unparsed_length = match data_start.get(..usize_size_in_bytes) {
        Some(data) => data,
        None => return -8,
    };
    let data_start = &data_start[usize_size_in_bytes..];

    let parsed_entry2_length = usize::from_le_bytes(match unparsed_length.try_into() {
        Ok(val) => val,
        Err(_) => return -7,
    });
    if parsed_entry2_length > data_start.len() {
        return -8;
    }
    *entry2_length = parsed_entry2_length;
    *entry2 = data_start.as_ptr();

    0
}
