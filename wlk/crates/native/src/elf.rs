//! Bounded validation and interpreter discovery for Linux x86_64 ELF executables.

use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::Path;

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const MAX_PROGRAM_HEADERS: u16 = 4096;
const MAX_DYNAMIC_SIZE: u64 = 1024 * 1024;
const MAX_INTERPRETER_SIZE: u64 = 4096;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const DT_NULL: i64 = 0;

/// Validate that `path` is a bounded ELF64 little-endian x86_64 image.
pub fn validate(path: &Path) -> io::Result<()> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    validate_reader(&mut file, file_len)
}

/// Validate an in-memory ELF image using the same bounded header and segment checks as a file.
pub fn validate_bytes(bytes: &[u8]) -> io::Result<()> {
    let mut cursor = Cursor::new(bytes);
    validate_reader(&mut cursor, bytes.len() as u64)
}

/// Return the ELF interpreter path from a validated image, if it is dynamically linked.
pub fn interpreter(bytes: &[u8]) -> io::Result<Option<Vec<u8>>> {
    validate_bytes(bytes)?;
    let phoff = read_u64(bytes, 32) as usize;
    let phnum = read_u16(bytes, 56) as usize;
    let mut interpreter = None;
    for index in 0..phnum {
        let offset = phoff + index * PROGRAM_HEADER_SIZE;
        if read_u32(bytes, offset) != PT_INTERP {
            continue;
        }
        let file_offset = usize::try_from(read_u64(bytes, offset + 8))
            .map_err(|_| invalid("ELF interpreter offset is out of bounds"))?;
        let file_size = usize::try_from(read_u64(bytes, offset + 32))
            .map_err(|_| invalid("ELF interpreter size is out of bounds"))?;
        let end = file_offset
            .checked_add(file_size)
            .ok_or_else(|| invalid("ELF interpreter range overflows"))?;
        let path = bytes
            .get(file_offset..end)
            .ok_or_else(|| invalid("ELF interpreter is out of file bounds"))?;
        if path.last() != Some(&0) || path[..path.len().saturating_sub(1)].contains(&0) {
            return Err(invalid(
                "ELF interpreter path is not a single terminated string",
            ));
        }
        interpreter = Some(path[..path.len() - 1].to_vec());
    }
    Ok(interpreter)
}

/// Check the fields available in Linux's executable format probe buffer.
pub fn probe_header(header: &[u8]) -> io::Result<()> {
    if header.len() < 24 {
        return Err(invalid("ELF identification header is truncated"));
    }
    validate_identity(header)
}

fn validate_reader(reader: &mut (impl Read + Seek), file_len: u64) -> io::Result<()> {
    if file_len < ELF_HEADER_SIZE as u64 {
        return Err(invalid("ELF header is truncated"));
    }

    let mut header = [0u8; ELF_HEADER_SIZE];
    reader.seek(SeekFrom::Start(0))?;
    reader.read_exact(&mut header)?;
    validate_identity(&header)?;
    if read_u16(&header, 52) as usize != ELF_HEADER_SIZE {
        return Err(invalid("unexpected ELF header size"));
    }

    let phoff = read_u64(&header, 32);
    let phentsize = read_u16(&header, 54) as usize;
    let phnum = read_u16(&header, 56);
    if phentsize != PROGRAM_HEADER_SIZE {
        return Err(invalid("unexpected ELF program header size"));
    }
    if phnum == 0 || phnum > MAX_PROGRAM_HEADERS {
        return Err(invalid("ELF program header count is out of bounds"));
    }
    let table_size = (phnum as u64)
        .checked_mul(phentsize as u64)
        .ok_or_else(|| invalid("ELF program header table overflows"))?;
    let table_end = phoff
        .checked_add(table_size)
        .ok_or_else(|| invalid("ELF program header table overflows"))?;
    if phoff < ELF_HEADER_SIZE as u64 || table_end > file_len {
        return Err(invalid("ELF program header table is out of file bounds"));
    }

    let mut has_load_segment = false;
    let mut dynamic = None;
    let mut interpreter = false;
    let mut phdr = [0u8; PROGRAM_HEADER_SIZE];
    for index in 0..phnum as u64 {
        let offset = phoff + index * PROGRAM_HEADER_SIZE as u64;
        reader.seek(SeekFrom::Start(offset))?;
        reader.read_exact(&mut phdr)?;

        let kind = read_u32(&phdr, 0);
        let segment_offset = read_u64(&phdr, 8);
        let file_size = read_u64(&phdr, 32);
        let memory_size = read_u64(&phdr, 40);

        if file_size > 0 {
            let segment_end = segment_offset
                .checked_add(file_size)
                .ok_or_else(|| invalid("ELF segment range overflows"))?;
            if segment_end > file_len {
                return Err(invalid("ELF segment is out of file bounds"));
            }
        }

        match kind {
            PT_INTERP => {
                if interpreter {
                    return Err(invalid("ELF has multiple interpreter segments"));
                }
                interpreter = true;
                if !(2..=MAX_INTERPRETER_SIZE).contains(&file_size) {
                    return Err(invalid("ELF interpreter segment size is out of bounds"));
                }
            }
            PT_LOAD => {
                has_load_segment = true;
                if file_size > memory_size {
                    return Err(invalid("ELF load segment file size exceeds memory size"));
                }
            }
            PT_DYNAMIC if dynamic.is_some() => {
                return Err(invalid("ELF has multiple dynamic segments"));
            }
            PT_DYNAMIC => dynamic = Some((segment_offset, file_size)),
            _ => {}
        }
    }

    if !has_load_segment {
        return Err(invalid("ELF has no loadable segment"));
    }
    if let Some((offset, size)) = dynamic {
        validate_dynamic(reader, offset, size)?;
    }
    Ok(())
}

fn validate_identity(header: &[u8]) -> io::Result<()> {
    if header.len() < 24 {
        return Err(invalid("ELF identification header is truncated"));
    }
    if &header[..4] != b"\x7fELF" {
        return Err(invalid("not an ELF file"));
    }
    if header[4] != 2 {
        return Err(invalid("ELF class is not 64-bit"));
    }
    if header[5] != 1 {
        return Err(invalid("ELF byte order is not little-endian"));
    }
    if header[6] != 1 || read_u32(header, 20) != 1 {
        return Err(invalid("unsupported ELF version"));
    }

    let elf_type = read_u16(header, 16);
    if elf_type != ET_EXEC && elf_type != ET_DYN {
        return Err(invalid("ELF type is not ET_EXEC or ET_DYN"));
    }
    if read_u16(header, 18) != EM_X86_64 {
        return Err(invalid("ELF machine is not x86_64"));
    }
    Ok(())
}

fn validate_dynamic(reader: &mut (impl Read + Seek), offset: u64, size: u64) -> io::Result<()> {
    if size == 0 || size > MAX_DYNAMIC_SIZE || !size.is_multiple_of(16) {
        return Err(invalid("ELF dynamic segment size is out of bounds"));
    }

    let mut entry = [0u8; 16];
    let mut terminated = false;
    for index in 0..(size / 16) {
        let entry_offset = offset
            .checked_add(index * 16)
            .ok_or_else(|| invalid("ELF dynamic table overflows"))?;
        reader.seek(SeekFrom::Start(entry_offset))?;
        reader.read_exact(&mut entry)?;
        if read_i64(&entry, 0) == DT_NULL {
            terminated = true;
            break;
        }
    }
    if !terminated {
        return Err(invalid("ELF dynamic table is not terminated"));
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
