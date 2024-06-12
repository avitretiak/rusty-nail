#[cfg(test)]
mod tests {
    use rusty_nail::{apply_patches_from_dif, parse_dif_file};
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::sync::{Arc, Mutex};
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_dif_file() {
        let dif_content = "\
This difference file was NOT created by IDA

Test.exe
00000000005CB6B6: 00 01
0000000000EC4608: 4D 4F
0000000000EC4609: 61 57
0000000000EC460A: 69 4E
0000000000EC460B: 6E 45
0000000000EC460C: 74 44
0000000000EC460D: 65 20
0000000000EC460E: 6E 62";

        let mut dif_file = NamedTempFile::new().unwrap();
        dif_file.write_all(dif_content.as_bytes()).unwrap();
        let dif_path = dif_file.path();

        let log = Arc::new(Mutex::new(String::new()));
        let patches = match parse_dif_file(dif_path, log.clone()) {
            Ok(p) => p,
            Err(e) => {
                println!("Failed to parse DIF file: {}", e);
                let log_content = log.lock().unwrap();
                println!("Log content: {}", *log_content);
                panic!("Test failed due to parsing error");
            }
        };

        println!("Parsed patches: {:?}", patches);
        assert_eq!(patches.len(), 8);
        assert_eq!(patches[0], (0x5CB6B6, 0x00, 0x01));
    }

    #[test]
    fn test_apply_patches_from_dif() {
        let dif_content = "\
This difference file was NOT created by IDA

Test.exe
00000000005CB201: FF B0
";
        let mut dif_file = NamedTempFile::new().unwrap();
        dif_file.write_all(dif_content.as_bytes()).unwrap();
        let dif_path = dif_file.path();

        let mut exe_file = NamedTempFile::new().unwrap();
        exe_file.write_all(&[0xFF; 0x5CB202]).unwrap(); // Initialize with 0xFF up to 0x5CB202
        let exe_path = exe_file.path();

        let log = Arc::new(Mutex::new(String::new()));
        let result = match apply_patches_from_dif(dif_path, exe_path, log.clone()) {
            Ok(_) => Ok(()),
            Err(e) => {
                println!("Failed to apply patches: {}", e);
                let log_content = log.lock().unwrap();
                println!("Log content: {}", *log_content);
                Err(e)
            }
        };
        assert!(result.is_ok());

        let mut exe_file = File::open(exe_path).unwrap();
        exe_file.seek(SeekFrom::Start(0x5CB201)).unwrap();
        let mut buffer = [0; 1];
        exe_file.read_exact(&mut buffer).unwrap();
        assert_eq!(buffer[0], 0xB0);
    }
}
