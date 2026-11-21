use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use stem::descriptor::Descriptor;
use stem::descriptor::export::export_csv;
use stem::descriptor::reader::{
    DescriptorReader, ProcessedFiles, SkipReason, load_processed_files,
    save_processed_files,
};

fn data() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/descriptor")
}

fn skips(reader: &mut DescriptorReader) -> Arc<Mutex<Vec<(PathBuf, SkipReason)>>> {
    let collected = Arc::new(Mutex::new(Vec::new()));
    let sink = collected.clone();
    reader.register_skip_listener(move |path, reason| {
        sink.lock()
            .unwrap()
            .push((path.to_path_buf(), reason.clone()))
    });
    collected
}

#[test]
fn loads_processed_file_listings() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("listing");
    std::fs::write(
        &path,
        "/dir/ 0\n/dir/file 12345\n/dir/file with spaces 7138743\n  /dir/with extra \
        space 12345   \n   \t   \n\n/dir/after empty line 12345",
    )
    .unwrap();
    let loaded = load_processed_files(&path).unwrap();
    let expected: ProcessedFiles = [
        ("/dir/", 0),
        ("/dir/file", 12345),
        ("/dir/file with spaces", 7138743),
        ("/dir/with extra space", 12345),
        ("/dir/after empty line", 12345),
    ]
    .into_iter()
    .map(|(path, timestamp)| (PathBuf::from(path), timestamp))
    .collect();
    assert_eq!(loaded, expected);

    std::fs::write(&path, "").unwrap();
    assert!(load_processed_files(&path).unwrap().is_empty());
    for malformed in [
        " 12345",
        "/dir/file ",
        "not_an_absolute_file 12345",
        "/dir/file 123a",
        "/dir/file -5",
    ] {
        std::fs::write(&path, malformed).unwrap();
        assert!(load_processed_files(&path).is_err(), "{malformed:?}");
    }
    assert!(load_processed_files(Path::new("/non-existant/path")).is_err());
}

#[test]
fn saves_processed_file_listings() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nested/listing");
    let listing: ProcessedFiles = [
        ("/tmp", 123),
        ("/bin/grep", 4567),
        ("/file with spaces/and \\ stuff", 890),
    ]
    .into_iter()
    .map(|(path, timestamp)| (PathBuf::from(path), timestamp))
    .collect();
    save_processed_files(&path, &listing).unwrap();
    assert_eq!(load_processed_files(&path).unwrap(), listing);

    for malformed in ["", "foobar", "/tmp/line\nbreak"] {
        let broken: ProcessedFiles =
            [(PathBuf::from(malformed), 123)].into_iter().collect();
        assert!(
            save_processed_files(&path, &broken).is_err(),
            "{malformed:?}"
        );
    }
}

#[test]
fn reads_a_single_file_and_remembers_it() {
    let path = data().join("example_descriptor");
    let mut reader = DescriptorReader::new(&[&path]);
    let read = Arc::new(Mutex::new(Vec::new()));
    let sink = read.clone();
    reader.register_read_listener(move |path| {
        sink.lock().unwrap().push(path.to_path_buf())
    });
    let skipped = skips(&mut reader);

    assert_eq!(reader.read_all().unwrap().len(), 1);
    assert_eq!(read.lock().unwrap().as_slice(), std::slice::from_ref(&path));
    assert!(skipped.lock().unwrap().is_empty());
    assert!(reader.processed_files().contains_key(&path));

    assert!(reader.read_all().unwrap().is_empty());
    assert!(matches!(
        skipped.lock().unwrap()[0].1,
        SkipReason::AlreadyRead { .. }
    ));

    reader.set_processed_files(ProcessedFiles::new());
    assert_eq!(reader.read_all().unwrap().len(), 1);
}

#[test]
fn persists_the_processed_listing() {
    let directory = tempfile::tempdir().unwrap();
    let listing = directory.path().join("processed");
    let path = data().join("example_descriptor");
    let mut reader = DescriptorReader::new(&[&path]).with_persistence(&listing);
    assert_eq!(reader.read_all().unwrap().len(), 1);
    assert!(
        std::fs::read_to_string(&listing)
            .unwrap()
            .starts_with(path.to_str().unwrap())
    );

    let mut again = DescriptorReader::new(&[&path]).with_persistence(&listing);
    assert!(again.read_all().unwrap().is_empty());
}

#[test]
fn reads_tar_archives_with_paths() {
    let expected = [
        "descriptor_archive/0/2/02c311d3d789f3f55c0880b5c85f3c196343552c",
        "descriptor_archive/1/b/1bb798cae15e21479db0bc700767eee4733e9d4a",
        "descriptor_archive/1/b/1ef75fef564180d8b3f72c6f8635ff0cd855f92c",
    ];
    for name in [
        "descriptor_archive.tar",
        "descriptor_archive.tar.gz",
        "descriptor_archive.tar.bz2",
    ] {
        let path = data().join(name);
        let files = DescriptorReader::new(&[&path]).read_all().unwrap();
        assert_eq!(files.len(), 3, "{name}");
        for file in files {
            assert_eq!(file.path.as_deref(), Some(path.as_path()));
            assert!(expected.contains(&file.archive_path.as_deref().unwrap()));
        }
    }
}

#[test]
fn walks_directories_and_reports_skipped_files() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(directory.path().join("nested/deeper")).unwrap();
    std::fs::copy(
        data().join("example_descriptor"),
        directory.path().join("a"),
    )
    .unwrap();
    std::fs::copy(
        data().join("server_descriptor_with_ed25519"),
        directory.path().join("nested/b"),
    )
    .unwrap();
    std::fs::write(
        directory.path().join("nested/deeper/garbage"),
        b"\x00\x01\x02 not a descriptor",
    )
    .unwrap();
    std::fs::write(
        directory.path().join("nested/broken"),
        "@type server-descriptor 1.0\nrouter nope\n",
    )
    .unwrap();

    let mut reader = DescriptorReader::new(&[directory.path()]).with_validation(true);
    let skipped = skips(&mut reader);
    let files = reader.read_all().unwrap();
    assert_eq!(files.len(), 2);

    let reasons = skipped.lock().unwrap();
    assert!(
        reasons
            .iter()
            .any(|(path, reason)| path.ends_with("garbage")
                && matches!(reason, SkipReason::UnrecognizedType(_)))
    );
    assert!(reasons.iter().any(|(path, reason)| path.ends_with("broken")
        && matches!(reason, SkipReason::ParsingFailure(_))));
}

#[test]
fn reports_missing_targets() {
    let mut reader = DescriptorReader::new(&[Path::new("/definitely/not/here")]);
    let skipped = skips(&mut reader);
    assert!(reader.read_all().unwrap().is_empty());
    assert_eq!(skipped.lock().unwrap()[0].1, SkipReason::FileMissing);
}

#[test]
fn does_not_follow_links_unless_asked() {
    let directory = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::copy(
        data().join("example_descriptor"),
        outside.path().join("linked"),
    )
    .unwrap();
    std::os::unix::fs::symlink(outside.path(), directory.path().join("shortcut"))
        .unwrap();
    std::os::unix::fs::symlink(directory.path(), outside.path().join("cycle")).unwrap();

    assert!(
        DescriptorReader::new(&[directory.path()])
            .read_all()
            .unwrap()
            .is_empty()
    );
    let followed = DescriptorReader::new(&[directory.path()])
        .following_links()
        .read_all()
        .unwrap();
    assert_eq!(followed.len(), 1);
}

#[test]
fn stops_early_when_asked() {
    let mut reader = DescriptorReader::new(&[data()]);
    let mut seen = 0;
    reader
        .read_each(|_| {
            seen += 1;
            ControlFlow::Break(())
        })
        .unwrap();
    assert_eq!(seen, 1);
    assert!(reader.processed_files().is_empty());
}

#[test]
fn exports_descriptors_as_csv() {
    let files = DescriptorReader::new(&[data().join("extrainfo_relay_descriptor")])
        .read_all()
        .unwrap();
    let descriptors: Vec<Descriptor> =
        files.into_iter().map(|file| file.descriptor).collect();

    let everything = export_csv(&descriptors, &[], &[], true).unwrap();
    let mut lines = everything.lines();
    let header = lines.next().unwrap();
    assert!(header.starts_with("bridge_ips,"));
    assert!(header.contains("nickname"));
    assert!(lines.next().unwrap().contains("NINJA"));

    let chosen =
        export_csv(&descriptors, &["nickname", "fingerprint"], &[], true).unwrap();
    assert_eq!(
        chosen,
        "nickname,fingerprint\nNINJA,B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48\n"
    );
    let excluded = export_csv(
        &descriptors,
        &["nickname", "fingerprint"],
        &["fingerprint"],
        false,
    )
    .unwrap();
    assert_eq!(excluded, "NINJA\n");

    assert!(export_csv(&descriptors, &["nonexistent"], &[], true).is_err());
    assert_eq!(export_csv(&[], &[], &[], true).unwrap(), "");
    let other = DescriptorReader::new(&[data().join("example_descriptor")])
        .read_all()
        .unwrap();
    let mixed: Vec<Descriptor> = descriptors
        .into_iter()
        .chain(other.into_iter().map(|file| file.descriptor))
        .collect();
    assert!(export_csv(&mixed, &[], &[], true).is_err());
}
