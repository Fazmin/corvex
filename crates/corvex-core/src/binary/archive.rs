//! Archive extraction support for binary scanning.
//!
//! Supports ZIP, TAR, TAR.GZ, and basic archive detection.

use std::io::Read;
use std::path::{Path, PathBuf};

/// Supported archive types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveType {
    Zip,
    TarGz,
    Tar,
}

/// Detect archive type from file extension and magic bytes.
pub fn detect_archive_type(path: &Path) -> Option<ArchiveType> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "zip" | "jar" | "war" | "ear" | "apk" => Some(ArchiveType::Zip),
        "gz" | "tgz" => Some(ArchiveType::TarGz),
        "tar" => Some(ArchiveType::Tar),
        _ => {
            // Try magic bytes
            if let Ok(mut f) = std::fs::File::open(path) {
                let mut magic = [0u8; 4];
                if f.read_exact(&mut magic).is_ok() {
                    if magic[0..2] == [0x50, 0x4B] {
                        return Some(ArchiveType::Zip);
                    }
                    if magic[0..2] == [0x1F, 0x8B] {
                        return Some(ArchiveType::TarGz);
                    }
                }
            }
            None
        }
    }
}

/// Extract an archive to a temporary directory. Returns the temp dir path.
pub fn extract_archive(path: &Path, archive_type: ArchiveType) -> Result<PathBuf, String> {
    let temp_dir = std::env::temp_dir().join(format!("corvex-extract-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir)
        .map_err(|e| format!("create temp dir: {e}"))?;

    match archive_type {
        ArchiveType::Zip => extract_zip(path, &temp_dir)?,
        ArchiveType::TarGz => extract_tar_gz(path, &temp_dir)?,
        ArchiveType::Tar => extract_tar(path, &temp_dir)?,
    }

    Ok(temp_dir)
}

fn extract_zip(path: &Path, dest: &Path) -> Result<(), String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| format!("zip open: {e}"))?;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("zip entry {i}: {e}"))?;

        let outpath = match entry.enclosed_name() {
            Some(name) => dest.join(name),
            None => continue,
        };

        if entry.is_dir() {
            let _ = std::fs::create_dir_all(&outpath);
        } else {
            if let Some(parent) = outpath.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let mut outfile = std::fs::File::create(&outpath)
                .map_err(|e| format!("create {}: {e}", outpath.display()))?;
            std::io::copy(&mut entry, &mut outfile)
                .map_err(|e| format!("extract {}: {e}", outpath.display()))?;
        }
    }
    Ok(())
}

fn extract_tar_gz(path: &Path, dest: &Path) -> Result<(), String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);

    archive
        .unpack(dest)
        .map_err(|e| format!("tar extract: {e}"))?;
    Ok(())
}

fn extract_tar(path: &Path, dest: &Path) -> Result<(), String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut archive = tar::Archive::new(file);

    archive
        .unpack(dest)
        .map_err(|e| format!("tar extract: {e}"))?;
    Ok(())
}

/// Clean up a temporary extraction directory.
pub fn cleanup_temp_dir(path: &Path) {
    let _ = std::fs::remove_dir_all(path);
}
