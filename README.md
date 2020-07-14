# pq_message_lib

This Rust library is used internally by PQShield for inter-process communication (IPC). It allows processes to generate and process requests and responses for post-quantum cryptography.

This library is not entirely complete as in our case the process making requests is only available in `C` whereas the responder is in `Rust`. Hence, some functions are only available in unsafe form while others are only available in safe form.

Note that this library provides no guarantees about the IPC channel. The user of this library is responsible for ensuring reliability and security of the IPC channel.
