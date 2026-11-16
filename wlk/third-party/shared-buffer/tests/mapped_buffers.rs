use std::io::{Seek, SeekFrom, Write};

use bytes::Buf;
use shared_buffer::OwnedBuffer;

#[test]
fn mapped_clones_and_nested_slices_retain_mapping_after_file_and_parent_drop() {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(b"0123456789").unwrap();
    file.seek(SeekFrom::Start(4)).unwrap();
    let buffer = OwnedBuffer::from_file(&file).unwrap();
    assert_eq!(buffer.as_slice(), b"0123456789");
    assert!(buffer.is_mmapped());
    let original = buffer.as_slice().as_ptr();
    let cloned = buffer.clone();
    assert_eq!(cloned.as_slice().as_ptr(), original);
    let slice = cloned.slice(2..9).slice(3..6);
    assert_eq!(slice.as_slice().as_ptr(), original.wrapping_add(5));
    drop(file);
    drop(buffer);
    drop(cloned);
    assert!(slice.is_mmapped());
    assert_eq!(slice.as_slice(), b"567");
    assert_eq!(slice.clone().into_bytes().as_ref(), b"567");
}

#[test]
fn mapped_and_memory_buffers_preserve_relative_slice_offsets_and_advance() {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(b"0123456789").unwrap();
    let mapped = OwnedBuffer::from_file(&file).unwrap();
    let memory = OwnedBuffer::from_static(b"0123456789");
    for buffer in [mapped, memory] {
        let mut slice = buffer.slice(2..9);
        slice.advance(3);
        assert_eq!(slice.remaining(), 4);
        assert_eq!(slice.chunk(), b"5678");
        let nested = slice.slice(1..=2);
        assert_eq!(nested.as_slice(), b"67");
        let empty = slice.slice(4..4);
        assert!(empty.is_empty());
        let cloned = nested.clone();
        drop(buffer);
        drop(slice);
        drop(nested);
        assert_eq!(cloned.as_slice(), b"67");
    }
}
