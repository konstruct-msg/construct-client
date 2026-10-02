//! gRPC length-prefix framing.
//!
//! Wire format (identical over H2 and H3):
//!   1 byte  — compression flag (0 = uncompressed)
//!   4 bytes — message length (big-endian u32)
//!   N bytes — protobuf body
//!
//! Shared gRPC message framing; the TUI transport currently carries it over HTTP/2.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::error::GrpcError;

pub fn encode_frame(proto_bytes: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(5 + proto_bytes.len());
    buf.put_u8(0);
    buf.put_u32(proto_bytes.len() as u32);
    buf.put_slice(proto_bytes);
    buf.freeze()
}

/// Decode one gRPC frame. Returns `(message, remainder)`.
pub fn decode_frame(mut data: Bytes) -> Result<(Bytes, Bytes), GrpcError> {
    if data.len() < 5 {
        return Err(GrpcError::transport(format!(
            "gRPC frame too short: {} bytes",
            data.len()
        )));
    }
    let compressed = data.get_u8();
    if compressed != 0 {
        return Err(GrpcError::transport("compressed gRPC frames not supported"));
    }
    let msg_len = data.get_u32() as usize;
    if data.len() < msg_len {
        return Err(GrpcError::transport(format!(
            "gRPC frame incomplete: need {msg_len} bytes, have {}",
            data.len()
        )));
    }
    let msg = data.split_to(msg_len);
    Ok((msg, data))
}
