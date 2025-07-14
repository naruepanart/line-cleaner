use std::{
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    ptr,
};

const BATCH_SIZE: usize = 4096;
const LINE_BUF_SIZE: usize = 65536;

fn main() -> io::Result<()> {
    atomic_dedupe("data.txt")
}

fn atomic_dedupe(path: &str) -> io::Result<()> {
    // Validate path exists and is a file
    let path = Path::new(path);
    let metadata = path.metadata()?;
    if metadata.is_dir() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "is directory"));
    }
    if metadata.len() == 0 {
        return Ok(());
    }

    // Create temp file in same directory
    let tmp_path = temp_path(path)?;
    let mut tmp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)?;

    // Deduplicate content
    dedupe_to_writer(path, &mut tmp_file)?;
    tmp_file.sync_all()?;
    drop(tmp_file); // Close handle before rename

    // Atomic replacement
    replace_file(&tmp_path, path)?;
    Ok(())
}

#[inline(always)]
fn temp_path(original: &Path) -> io::Result<PathBuf> {
    let mut pb = original.to_path_buf();
    pb.set_extension("tmp");
    Ok(pb)
}

#[inline(always)]
fn replace_file(src: &Path, dst: &Path) -> io::Result<()> {
    std::fs::rename(src, dst)
}

fn dedupe_to_writer(src: &Path, dst: &mut File) -> io::Result<()> {
    let mut reader = BufReader::with_capacity(LINE_BUF_SIZE, File::open(src)?);
    let mut writer = BufWriter::with_capacity(BATCH_SIZE, dst);

    // Pre-allocate hash set with expected size
    let mut seen = FixedHashSet::with_capacity(1024);
    let mut batch = Vec::with_capacity(BATCH_SIZE);
    let mut line = String::with_capacity(256);

    while reader.read_line(&mut line)? > 0 {
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        // Use first 8 bytes as quick hash (FNV-1a inspired)
        let hash = fast_hash(trimmed.as_bytes());
        if !seen.insert(hash) {
            line.clear();
            continue;
        }

        // Batch write logic
        if batch.len() + trimmed.len() + 1 > batch.capacity() {
            writer.write_all(&batch)?;
            batch.clear();
        }

        if !batch.is_empty() {
            batch.push(b'\n');
        }
        batch.extend_from_slice(trimmed.as_bytes());
        line.clear();
    }

    // Flush remaining batch
    if !batch.is_empty() {
        writer.write_all(&batch)?;
    }

    Ok(())
}

// Ultra-fast fixed-size hash set
struct FixedHashSet {
    slots: Box<[u64]>,
    mask: usize,
}

impl FixedHashSet {
    fn with_capacity(capacity: usize) -> Self {
        let size = capacity.next_power_of_two();
        let mut slots = Vec::with_capacity(size);
        unsafe {
            slots.set_len(size);
            ptr::write_bytes(slots.as_mut_ptr(), 0, size);
        }
        Self {
            slots: slots.into_boxed_slice(),
            mask: size - 1,
        }
    }

    #[inline(always)]
    fn insert(&mut self, hash: u64) -> bool {
        let mut idx = hash as usize & self.mask;
        let empty = 0;

        unsafe {
            for _ in 0..self.slots.len() {
                let slot = self.slots.get_unchecked_mut(idx);
                if *slot == empty {
                    *slot = hash;
                    return true;
                } else if *slot == hash {
                    return false;
                }
                idx = (idx + 1) & self.mask;
            }
        }

        // Fallback: overwrite if full (shouldn't happen with proper sizing)
        self.slots[idx] = hash;
        true
    }
}

#[inline(always)]
fn fast_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325;
    for &b in bytes.iter().take(8) {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}