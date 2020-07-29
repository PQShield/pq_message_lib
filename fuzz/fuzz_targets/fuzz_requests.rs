#![no_main]
use libfuzzer_sys::fuzz_target;
use pq_message_lib::request::*;

// fuzz_target!(|data: (RequestHeader, Vec<u8>)| {
//     deserialize_request(data.0, data.1);
// });

fuzz_target!(|data: (usize, usize)| {
    structure_two_entries_length(data.0, data.1);
});
