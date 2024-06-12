use std::fs::{File, OpenOptions};
use std::io::{copy, BufRead, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;
use std::sync::Arc;

pub fn apply_patches_from_dif(dif_path: &Path, exe_path: &Path, log: Arc<Mutex<String>>) -> std::io::Result<()> {
    let patches = parse_dif_file(dif_path, log.clone())?;
    let backup_path = exe_path.with_extension(format!("{}bk", exe_path.extension().unwrap_or_default().to_string_lossy()));
    create_backup(exe_path, &backup_path)?;
    
    // Log the backup creation
    {
        let mut log_lock = log.lock().unwrap();
        log_lock.push_str(&format!("Backup created at: {}\n", backup_path.display()));
    }

    patch_file(exe_path, patches, log)
}

// Function to create a backup of the file
fn create_backup(src_path: &Path, backup_path: &Path) -> std::io::Result<()> {
    let mut src_file = File::open(src_path)?;
    let mut backup_file = File::create(backup_path)?;
    copy(&mut src_file, &mut backup_file)?;
    Ok(())
}

pub fn parse_dif_file(dif_path: &Path, log: Arc<Mutex<String>>) -> std::io::Result<Vec<(u64, u8, u8)>> {
    let file = File::open(dif_path)?;
    let reader = std::io::BufReader::new(file);

    let mut patches = Vec::new();
    let mut exe_name = String::new();
    let mut log_lock = log.lock().unwrap();

    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with("//") {
            continue;
        }

        // Check for the executable name line
        if line.starts_with("This difference file was created by IDA") {
            continue;
        } else if exe_name.is_empty() {
            exe_name = line.to_string();
            continue;
        }

        let line_parts: Vec<&str> = line.split(':').collect();
        if line_parts.len() != 2 {
            log_lock.push_str(&format!("Invalid line format at line {}: {}\n", index + 1, line));
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid line format at line {}: {}", index + 1, line),
            ));
        }

        let address = u64::from_str_radix(&line_parts[0][2..], 16)
            .map_err(|e| {
                log_lock.push_str(&format!("Invalid address format at line {}: {}\n", index + 1, e));
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid address format at line {}: {}", index + 1, e),
                )
            })?;
        let bytes: Vec<&str> = line_parts[1].split_whitespace().collect();
        if bytes.len() != 2 {
            log_lock.push_str(&format!("Invalid byte format at line {}: {}\n", index + 1, line));
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid byte format at line {}: {}", index + 1, line),
            ));
        }
        let old_byte = u8::from_str_radix(bytes[0], 16)
            .map_err(|e| {
                log_lock.push_str(&format!("Invalid old byte format at line {}: {}\n", index + 1, e));
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid old byte format at line {}: {}", index + 1, e),
                )
            })?;
        let new_byte = u8::from_str_radix(bytes[1], 16)
            .map_err(|e| {
                log_lock.push_str(&format!("Invalid new byte format at line {}: {}\n", index + 1, e));
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid new byte format at line {}: {}", index + 1, e),
                )
            })?;

        patches.push((address, old_byte, new_byte));
    }

    Ok(patches)
}

pub fn patch_file(path: &Path, patches: Vec<(u64, u8, u8)>, log: Arc<Mutex<String>>) -> std::io::Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let mut log_lock = log.lock().unwrap();

    for (offset, old_byte, new_byte) in patches {
        // Seek to the offset
        file.seek(SeekFrom::Start(offset))?;
        let mut buffer = [0; 1];
        file.read_exact(&mut buffer)?;
        // Verify the old byte if necessary
        if buffer[0] != old_byte {
            let error_message = format!(
                "Old byte mismatch at offset {:X}: expected {:X}, found {:X}\n",
                offset, old_byte, buffer[0]
            );
            log_lock.push_str(&error_message);
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, error_message));
        }
        // Write the new byte
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&[new_byte])?;
        log_lock.push_str(&format!("Patched byte at offset {:X}: {:X} -> {:X}\n", offset, old_byte, new_byte));
    }

    Ok(())
}
