use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use rusty_nail::{parse_dif_file, apply_patches_from_dif};

#[test]
fn test_parse_dif_file() {
    let dif_content = "\
This difference file was created by IDA

Test.exe
00000000005CB6B6: 00 01
0000000000EC4608: 4D 4F
0000000000EC4609: 61 57
0000000000EC460A: 69 4E
0000000000EC460B: 6E 45
0000000000EC460C: 74 44
0000000000EC460D: 65 20
0000000000EC460E: 6E 62";
    let dif_path = "test.dif";
    let mut file = File::create(dif_path).unwrap();
    file.write_all(dif_content.as_bytes()).unwrap();

    let log = Arc::new(Mutex::new(String::new()));
    let patches = parse_dif_file(Path::new(dif_path), log).unwrap();
    assert_eq!(patches.len(), 8);
    assert_eq!(patches[0], (0x5CB6B6, 0x00, 0x01));
}

#[test]
fn test_apply_patches_from_dif() {
    let dif_content = "\
This difference file was created by IDA

Test.exe
00000000005CB201: FF B0
";
    let dif_path = "test.dif";
    let exe_path = "test.exe";
    let mut dif_file = File::create(dif_path).unwrap();
    let mut exe_file = File::create(exe_path).unwrap();
    exe_file.write_all(&[0xFF; 0x5CB202]).unwrap(); // Initialize with 0xFF up to 0x5CB202
    dif_file.write_all(dif_content.as_bytes()).unwrap();

    let log = Arc::new(Mutex::new(String::new()));
    let result = apply_patches_from_dif(Path::new(dif_path), Path::new(exe_path), log);
    assert!(result.is_ok());

    let mut exe_file = File::open(exe_path).unwrap();
    exe_file.seek(SeekFrom::Start(0x5CB201)).unwrap();
    let mut buffer = [0; 1];
    exe_file.read_exact(&mut buffer).unwrap();
    assert_eq!(buffer[0], 0xB0);
}
