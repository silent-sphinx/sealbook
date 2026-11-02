//! How a run of object writes is split into batch requests the server accepts.

use sealbook_crypto::aead::padded_len;
use sealbook_protocol::{MAX_BATCH_BYTES, MAX_BATCH_OBJECTS};

/// How many objects each consecutive batch takes, for writes whose plaintexts
/// are `payload_lengths` bytes long.
///
/// A batch closes at `MAX_BATCH_OBJECTS` objects, or before its padded bytes
/// would pass `MAX_BATCH_BYTES`. An object larger than that on its own is still
/// sent, alone, since one object has to go somewhere and the server accepts it.
pub fn write_batches(payload_lengths: &[u64]) -> Vec<u32> {
    let mut batches = Vec::new();
    let mut count = 0;
    let mut bytes = 0;
    for length in payload_lengths {
        let size = padded_len(usize::try_from(*length).unwrap_or(usize::MAX - 4));
        if count == MAX_BATCH_OBJECTS || (count > 0 && bytes + size > MAX_BATCH_BYTES) {
            batches.push(count as u32);
            count = 0;
            bytes = 0;
        }
        count += 1;
        bytes += size;
    }
    if count > 0 {
        batches.push(count as u32);
    }
    batches
}

#[cfg(feature = "uniffi")]
pub mod ffi {
    #[uniffi::export(name = "write_batches")]
    pub fn write_batches(payload_lengths: Vec<u64>) -> Vec<u32> {
        super::write_batches(&payload_lengths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealbook_protocol::MAX_PADDED_OBJECT_SIZE;

    #[test]
    fn nothing_to_write_is_no_batches() {
        assert!(write_batches(&[]).is_empty());
    }

    #[test]
    fn small_objects_close_a_batch_at_the_count_cap() {
        let lengths = vec![100; MAX_BATCH_OBJECTS * 2 + 1];
        assert_eq!(
            write_batches(&lengths),
            vec![MAX_BATCH_OBJECTS as u32, MAX_BATCH_OBJECTS as u32, 1]
        );
    }

    #[test]
    fn large_objects_close_a_batch_before_the_byte_cap() {
        // Each pads to a quarter of the cap, so four fill a batch exactly.
        let quarter = (MAX_BATCH_BYTES / 4 - 4) as u64;
        assert_eq!(write_batches(&[quarter; 9]), vec![4, 4, 1]);
        assert_eq!(
            write_batches(&[quarter, quarter, quarter, quarter, 1]),
            vec![4, 1]
        );
    }

    #[test]
    fn an_object_over_the_byte_cap_goes_alone() {
        let over = MAX_PADDED_OBJECT_SIZE as u64;
        assert_eq!(write_batches(&[10, over, 10]), vec![1, 1, 1]);
    }
}
