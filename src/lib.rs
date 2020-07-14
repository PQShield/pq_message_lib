//! A crate used for IPC between two processes.
//! This crate allows one side to do a request for some post-quantum operation
//! and then the other side will perform this post-quantum operation and
//! send the result back.
//! One should take care that the IPC channel used is not readable by everyone
//! as cryptographically sensitive data will go over this channel.

#[macro_use]
extern crate lazy_static;

// Increase format version whenever the Request format is changed
const FORMAT_VERSION: u8 = 1;

/// Used to indicate that serialization failed.
#[derive(Debug)]
pub struct SerializationError;
/// Used to indicate that deserialization failed.
#[derive(Debug)]
pub struct DeserializationError;

/// Used to indicate that destructuring failed.
#[derive(Debug)]
pub struct DestructureError;

/// This module contains everything one needs for sending and receiving request headers.
pub mod request;
/// This module contains everything one needs for sending and receiving response headers.
pub mod response;

#[cfg(test)]
mod tests {
    // Emulates what the C side would do
    #[test]
    fn test_request_header_c() {
        let header_size = crate::request::get_serialized_request_header_size();

        unsafe {
            let buffer: *mut libc::c_uchar =
                libc::malloc(header_size as usize) as *mut libc::c_uchar;
            assert!(!buffer.is_null());

            let status = crate::request::serialize_request_header(
                buffer,
                header_size as usize,
                1234,
                1331,
                crate::request::Algorithm::FRODO976__ECDHp384,
                crate::request::Operation::Encapsulation,
            );
            assert!(status == 0);

            let slice: &[u8] = &*std::ptr::slice_from_raw_parts(buffer, header_size as usize);
            assert_eq!(
                slice,
                vec![crate::FORMAT_VERSION, 210, 4, 0, 0, 0, 0, 0, 0, 51, 5, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0].as_slice()
            );

            libc::free(buffer as *mut libc::c_void);
        }
    }

    #[test]
    fn test_request_header_rust() {
        let header_size = crate::request::get_serialized_request_header_size();

        // Pretend we've read these bytes from somewhere
        let buffer: Vec<u8> = vec![
            crate::FORMAT_VERSION, 210, 4, 0, 0, 0, 0, 0, 0, 51, 5, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0,
        ];
        assert_eq!(header_size as usize, buffer.len());

        let request_header = crate::request::deserialize_request_header(&buffer);
        assert!(request_header.is_ok());
        let equal = request_header.unwrap()
            == crate::request::RequestHeader {
                version: crate::FORMAT_VERSION,
                identifier: 1234,
                data_len: 1331,
                algorithm: crate::request::Algorithm::FRODO976__ECDHp384,
                operation: crate::request::Operation::Encapsulation,
            };
        assert!(equal);
    }

    #[test]
    fn test_response_header_c() {
        let header_size = crate::response::get_serialized_response_header_size();

        unsafe {
            let buffer: *mut libc::c_uchar =
                libc::malloc(header_size as usize) as *mut libc::c_uchar;
            assert!(!buffer.is_null());

            // Pretend we've read these bytes from somewhere
            let header = vec![crate::FORMAT_VERSION, 210, 4, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0];
            std::ptr::copy_nonoverlapping(header.as_ptr(), buffer, header_size as usize);

            let mut response_header: crate::response::ResponseHeader = Default::default();
            let status = crate::response::deserialize_response_header(buffer, &mut response_header);
            assert!(status == 0);
            let equal = response_header
                == crate::response::ResponseHeader {
                    version: crate::FORMAT_VERSION,
                    identifier: 1234,
                    success: 0,
                    data_len: 6,
                };
            assert!(equal);

            libc::free(buffer as *mut libc::c_void);
        }
    }

    #[test]
    fn test_response_header_rust() {
        let response = crate::response::serialize_response(1234, Some(&vec![0, 1, 2, 3, 4, 5]));
        assert!(response.is_ok());
        assert_eq!(
            response.unwrap(),
            vec![crate::FORMAT_VERSION, 210, 4, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 1, 2, 3, 4, 5]
        );
    }

    #[test]
    fn test_response_header_failure_rust() {
        let response = crate::response::serialize_response(1234, None);
        assert!(response.is_ok());
        assert_eq!(
            response.unwrap(),
            vec![
                crate::FORMAT_VERSION, 210, 4, 0, 0, 0, 0, 0, 0, 255, // -1 as u8
                0, 0, 0, 0,
            ]
        );
    }

    #[test]
    fn test_serialize_request_header_failure_c() {
        // Deliberately create a buffer that is too small
        let header_size = crate::request::get_serialized_request_header_size() - 10;

        unsafe {
            let buffer: *mut libc::c_uchar =
                libc::malloc(header_size as usize) as *mut libc::c_uchar;
            assert!(!buffer.is_null());

            let status = crate::request::serialize_request_header(
                buffer,
                header_size as usize,
                1234,
                1331,
                crate::request::Algorithm::FRODO976__ECDHp384,
                crate::request::Operation::Encapsulation,
            );
            assert!(status == -1);

            libc::free(buffer as *mut libc::c_void);
        }
    }

    #[test]
    fn test_deserialize_response_header_failure_c() {
        let header_size = crate::response::get_serialized_response_header_size();

        unsafe {
            let buffer: *mut libc::c_uchar =
                libc::malloc(header_size as usize) as *mut libc::c_uchar;
            assert!(!buffer.is_null());

            let mut response_header: crate::response::ResponseHeader = Default::default();
            let status = crate::response::deserialize_response_header(
                0 as *mut libc::c_uchar, // Pass in null pointer
                &mut response_header,
            );
            assert!(status == -1);

            // Pretend we've read these bytes from somewhere
            let header = vec![
                crate::FORMAT_VERSION + 1, // Deliberately get format version wrong
                210,
                4,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                6,
                0,
                0,
                0,
            ];
            std::ptr::copy_nonoverlapping(header.as_ptr(), buffer, header_size as usize);
            let status = crate::response::deserialize_response_header(buffer, &mut response_header);
            assert!(status == -4);

            libc::free(buffer as *mut libc::c_void);
        }
    }

    #[test]
    fn test_structuring_entries_rust() {
        let pub_key: Vec<u8> = vec![0, 1, 2, 4, 5, 6];
        let priv_key: Vec<u8> = vec![12, 13, 14];

        let structured_keys = crate::response::structure_two_entries(&pub_key, &priv_key);
        assert_eq!(
            structured_keys,
            vec![6, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 4, 5, 6, 3, 0, 0, 0, 0, 0, 0, 0, 12, 13, 14]
        );
    }

    #[test]
    fn test_destructuring_two_entries_c() {
        // Pretend this is the buffer we received in C
        let mut keys: Vec<u8> = vec![
            6, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 4, 5, 6, 3, 0, 0, 0, 0, 0, 0, 0, 12, 13, 14,
        ];
        let keys_buffer_len = keys.len();

        let mut pub_key_length: libc::size_t = 0;
        let mut priv_key_length: libc::size_t = 0;

        let mut pub_key: *const libc::c_uchar = std::ptr::null();
        let mut priv_key: *const libc::c_uchar = std::ptr::null();

        unsafe {
            let status = crate::response::destructure_two_entries(
                keys.as_ptr(),
                keys_buffer_len,
                &mut pub_key_length,
                &mut priv_key_length,
                &mut pub_key,
                &mut priv_key,
            );
            assert_eq!(status, 0);
        }

        assert_eq!(pub_key_length, 6);
        assert_eq!(priv_key_length, 3);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(pub_key, pub_key_length) },
            vec![0, 1, 2, 4, 5, 6].as_slice()
        );
        assert_eq!(
            unsafe { std::slice::from_raw_parts(priv_key, priv_key_length) },
            vec![12, 13, 14].as_slice()
        );

        keys[0] = 255;
        unsafe {
            let status = crate::response::destructure_two_entries(
                keys.as_ptr(),
                keys_buffer_len,
                &mut pub_key_length,
                &mut priv_key_length,
                &mut pub_key,
                &mut priv_key,
            );
            assert_ne!(status, 0);
        }
        keys[0] = 6;

        keys[14] = 255;
        unsafe {
            let status = crate::response::destructure_two_entries(
                keys.as_ptr(),
                keys_buffer_len,
                &mut pub_key_length,
                &mut priv_key_length,
                &mut pub_key,
                &mut priv_key,
            );
            assert_ne!(status, 0);
        }

        let buffer = vec![];
        unsafe {
            let status = crate::response::destructure_two_entries(
                buffer.as_ptr(),
                buffer.len(),
                &mut pub_key_length,
                &mut priv_key_length,
                &mut pub_key,
                &mut priv_key,
            );
            assert_ne!(status, 0);
        }
    }

    #[test]
    fn test_structuring_two_entries_c() {
        let priv_key = vec![13, 12, 18, 33];
        let ciphertext = vec![0, 0, 2, 3, 1];

        unsafe {
            let total_length =
                crate::request::structure_two_entries_length(priv_key.len(), ciphertext.len());

            let buffer_c: *mut libc::c_uchar = libc::malloc(total_length) as *mut libc::c_uchar;
            assert!(!buffer_c.is_null());

            crate::request::structure_two_entries(
                buffer_c,
                priv_key.len(),
                ciphertext.len(),
                priv_key.as_ptr(),
                ciphertext.as_ptr(),
            );

            let buffer = &*std::ptr::slice_from_raw_parts(buffer_c, total_length);
            assert_eq!(
                buffer,
                vec![4, 0, 0, 0, 0, 0, 0, 0, 13, 12, 18, 33, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 1]
                    .as_slice()
            );

            libc::free(buffer_c as *mut libc::c_void);
        }
    }

    #[test]
    fn test_destructuring_two_entries_rust() {
        let mut priv_key_ct: Vec<u8> = vec![
            4, 0, 0, 0, 0, 0, 0, 0, 13, 12, 18, 33, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 1,
        ];

        assert_eq!(
            crate::request::destructure_two_entries(&priv_key_ct).unwrap(),
            (
                vec![13, 12, 18, 33].as_slice(),
                vec![0, 0, 2, 3, 1].as_slice()
            )
        );

        // Test with an empty input
        assert!(crate::request::destructure_two_entries(&vec![]).is_err());

        // Tests where the length are modified but the body does not match those lengths
        priv_key_ct[0] = 255;
        assert!(crate::request::destructure_two_entries(&priv_key_ct).is_err());
        priv_key_ct[0] = 4;

        priv_key_ct[12] = 255;
        assert!(crate::request::destructure_two_entries(&priv_key_ct).is_err());
    }
}
