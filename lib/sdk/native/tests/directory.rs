use std::sync::Arc;

use bytes::Bytes;
use wasmer_sdk::{Directory, FileOpenOptions, FileSystem, FsError, RelativePath};

fn path(value: &str) -> RelativePath {
    RelativePath::new(value).expect("valid provider-relative path")
}

fn open_options(read: bool, write: bool, append: bool) -> FileOpenOptions {
    FileOpenOptions {
        read,
        write,
        append,
        ..FileOpenOptions::default()
    }
}

async fn exercise_directory() {
    let directory = Directory::new();
    directory
        .write_text("nested/file.txt", "before")
        .await
        .unwrap();
    let file = directory
        .open(&path("nested/file.txt"), open_options(true, true, false))
        .await
        .unwrap();

    assert_eq!(
        file.write_at(6, Bytes::from_static(b"/after"))
            .await
            .unwrap(),
        6
    );
    assert_eq!(file.read_at(0, 32).await.unwrap().as_ref(), b"before/after");
    file.close().await.unwrap();
}

#[test]
fn standalone_directory_internal_driver_works_inside_futures_executor_without_tokio() {
    assert!(tokio::runtime::Handle::try_current().is_err());

    let contents = futures::executor::block_on(async {
        let directory = Directory::new();
        directory
            .write_text("nested/file.txt", "contents")
            .await
            .unwrap();
        directory.read_text("nested/file.txt").await.unwrap()
    });

    assert_eq!(contents, "contents");
    assert!(tokio::runtime::Handle::try_current().is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn standalone_directory_works_on_a_current_thread_runtime() {
    exercise_directory().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standalone_directory_works_on_a_multi_thread_runtime() {
    exercise_directory().await;
}

#[tokio::test(flavor = "current_thread")]
async fn append_open_distinguishes_append_from_positioned_writes() {
    let directory = Directory::new();
    directory.write_text("cursor.txt", "seed").await.unwrap();
    let append_file = directory
        .open(&path("cursor.txt"), open_options(true, true, true))
        .await
        .unwrap();

    assert_eq!(
        append_file
            .write_at(0, Bytes::from_static(b"!"))
            .await
            .unwrap(),
        1,
        "write_at on an append-open file appends despite the supplied offset"
    );
    assert_eq!(
        append_file
            .write_positioned_at(1, Bytes::from_static(b"?"))
            .await
            .unwrap(),
        1,
        "write_positioned_at honors its offset on an append-open file"
    );
    assert_eq!(
        append_file
            .try_atomic_append(Bytes::from_static(b"+"))
            .await
            .unwrap(),
        Some((5, 1))
    );

    let ordinary_file = directory
        .open(&path("cursor.txt"), open_options(true, true, false))
        .await
        .unwrap();
    assert_eq!(
        ordinary_file
            .try_atomic_append(Bytes::from_static(b"#"))
            .await
            .unwrap(),
        Some((6, 1)),
        "every writable handle supports atomic append, even without append mode"
    );
    assert_eq!(
        directory.read("cursor.txt").await.unwrap().as_ref(),
        b"s?ed!+#"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_append_handles_survive_concurrent_rename_and_report_actual_offsets() {
    const APPENDS_PER_HANDLE: usize = 24;

    let directory = Directory::new();
    directory
        .write_text("before/log.txt", "seed")
        .await
        .unwrap();
    directory.create_dir(&path("after")).await.unwrap();

    let old_path = path("before/log.txt");
    let new_path = path("after/log.txt");
    let first = directory
        .open(&old_path, open_options(true, true, true))
        .await
        .unwrap();
    let second = directory
        .open(&old_path, open_options(true, true, true))
        .await
        .unwrap();

    let start = Arc::new(tokio::sync::Barrier::new(4));
    let first_appender = {
        let file = Arc::clone(&first);
        let start = Arc::clone(&start);
        tokio::spawn(async move {
            start.wait().await;
            let mut offsets = Vec::with_capacity(APPENDS_PER_HANDLE);
            for _ in 0..APPENDS_PER_HANDLE {
                offsets.push(
                    file.try_atomic_append(Bytes::from_static(b"a"))
                        .await
                        .unwrap()
                        .unwrap(),
                );
                tokio::task::yield_now().await;
            }
            offsets
        })
    };
    let second_appender = {
        let file = Arc::clone(&second);
        let start = Arc::clone(&start);
        tokio::spawn(async move {
            start.wait().await;
            let mut offsets = Vec::with_capacity(APPENDS_PER_HANDLE);
            for _ in 0..APPENDS_PER_HANDLE {
                offsets.push(
                    file.try_atomic_append(Bytes::from_static(b"b"))
                        .await
                        .unwrap()
                        .unwrap(),
                );
                tokio::task::yield_now().await;
            }
            offsets
        })
    };
    let renamer = {
        let directory = directory.clone();
        let old_path = old_path.clone();
        let new_path = new_path.clone();
        let start = Arc::clone(&start);
        tokio::spawn(async move {
            start.wait().await;
            directory.rename(&old_path, &new_path).await.unwrap();
        })
    };
    start.wait().await;

    let mut offsets = first_appender.await.unwrap();
    offsets.extend(second_appender.await.unwrap());
    renamer.await.unwrap();

    // These writes begin after rename has completed, proving that both retained
    // handles still name the moved file.
    offsets.push(
        first
            .try_atomic_append(Bytes::from_static(b"x"))
            .await
            .unwrap()
            .unwrap(),
    );
    offsets.push(
        second
            .try_atomic_append(Bytes::from_static(b"y"))
            .await
            .unwrap()
            .unwrap(),
    );
    offsets.sort_unstable();

    let appended = APPENDS_PER_HANDLE * 2 + 2;
    assert_eq!(
        offsets,
        (4..4 + appended)
            .map(|offset| (offset as u64, 1))
            .collect::<Vec<_>>()
    );
    assert!(directory.stat(&old_path).await.is_err());
    assert!(directory.stat(&new_path).await.is_ok());

    let contents = directory.read("after/log.txt").await.unwrap();
    assert_eq!(&contents[..4], b"seed");
    assert_eq!(contents.len(), 4 + appended);
    assert_eq!(
        contents.iter().filter(|byte| **byte == b'a').count(),
        APPENDS_PER_HANDLE
    );
    assert_eq!(
        contents.iter().filter(|byte| **byte == b'b').count(),
        APPENDS_PER_HANDLE
    );
    assert_eq!(contents.iter().filter(|byte| **byte == b'x').count(), 1);
    assert_eq!(contents.iter().filter(|byte| **byte == b'y').count(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn retained_handle_keeps_timestamps_and_remains_usable_after_unlink() {
    let directory = Directory::new();
    directory.write_text("kept.txt", "before").await.unwrap();
    let original_path = path("kept.txt");
    let moved_path = path("renamed.txt");
    let writable = directory
        .open(&original_path, open_options(true, true, false))
        .await
        .unwrap();
    let readonly = directory
        .open(&original_path, open_options(true, false, false))
        .await
        .unwrap();

    assert_eq!(
        readonly
            .write_at(0, Bytes::from_static(b"!"))
            .await
            .unwrap_err(),
        FsError::PermissionDenied
    );

    let atime = 1_700_000_000_123_456_789;
    let mtime = 2_000_000_001;
    writable.set_times(Some(atime), Some(mtime)).await.unwrap();
    directory.rename(&original_path, &moved_path).await.unwrap();
    let updated_mtime = 3_000_000_002;
    writable.set_times(None, Some(updated_mtime)).await.unwrap();

    let metadata = writable.metadata().await.unwrap();
    assert_eq!(metadata.accessed, atime);
    assert_eq!(metadata.modified, updated_mtime);
    assert_eq!(
        directory.stat(&moved_path).await.unwrap().modified,
        updated_mtime
    );

    directory.remove(&moved_path, false).await.unwrap();
    assert!(directory.stat(&moved_path).await.is_err());
    assert_eq!(
        writable
            .write_positioned_at(0, Bytes::from_static(b"after!"))
            .await
            .unwrap(),
        6
    );
    assert_eq!(writable.read_at(0, 16).await.unwrap().as_ref(), b"after!");
    assert_eq!(readonly.read_at(0, 16).await.unwrap().as_ref(), b"after!");
}
