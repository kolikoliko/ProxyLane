//! Only our flat, versioned run directories may be removed. No recursive
//! deletion, junction traversal, PID guessing or age-based live-run deletion.
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

const MARKER: &[u8] = b"ProxyLaneProtocolCache/v1\n";

fn plain(path: &Path, directory: bool) -> std::io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(std::io::Error::other("cache path is a reparse point"));
        }
    }
    if meta.file_type().is_symlink() || meta.is_dir() != directory {
        return Err(std::io::Error::other("unexpected cache path type"));
    }
    Ok(())
}
fn lock(root: &Path) -> std::io::Result<File> {
    let path = root.join("manager.lock");
    if path.exists() {
        plain(&path, false)?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    file.lock_exclusive()?;
    Ok(file)
}
fn run_name(name: &str) -> bool {
    name.strip_prefix("run-")
        .is_some_and(|suffix| suffix.len() == 32 && suffix.bytes().all(|b| b.is_ascii_hexdigit()))
}
fn payload_name(name: &str) -> bool {
    [".request.body", ".response.body"].iter().any(|suffix| {
        name.strip_suffix(suffix).is_some_and(|prefix| {
            prefix.len() == 16 && prefix.bytes().all(|b| b.is_ascii_hexdigit())
        })
    })
}
fn inspect(root: &Path, run: &Path) -> std::io::Result<Vec<PathBuf>> {
    if run.parent() != Some(root)
        || !run
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(run_name)
    {
        return Err(std::io::Error::other(
            "cache cleanup target outside managed root",
        ));
    }
    plain(run, true)?;
    let mut files = Vec::new();
    let mut has_payload = false;
    let mut has_owner = false;
    let mut complete_marker = false;
    for item in fs::read_dir(run)? {
        let item = item?;
        let path = item.path();
        plain(&path, false)?;
        let name = item.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| std::io::Error::other("invalid cache filename"))?;
        if name != "owner.lock" && name != "format" && !payload_name(name) {
            return Err(std::io::Error::other("unrecognized file in cache run"));
        }
        has_payload |= payload_name(name);
        has_owner |= name == "owner.lock";
        if name == "format" {
            // A crash can interrupt marker creation. Only its exact prefix is
            // accepted, and the manager lock excludes a concurrent creator.
            if fs::metadata(&path)?.len() > MARKER.len() as u64
                || !MARKER.starts_with(&fs::read(&path)?)
            {
                return Err(std::io::Error::other("unrecognized cache format"));
            }
            complete_marker = fs::read(&path)? == MARKER;
        }
        files.push(path);
    }
    if has_payload && (!has_owner || !complete_marker) {
        return Err(std::io::Error::other(
            "payload directory has no complete ownership marker",
        ));
    }
    Ok(files)
}
fn remove_flat(root: &Path, run: &Path) -> std::io::Result<()> {
    let files = inspect(root, run)?;
    // Payloads first, so an interrupted cleanup leaves its ownership marker.
    for path in files
        .iter()
        .filter(|p| p.extension().is_some_and(|s| s == "body"))
    {
        fs::remove_file(path)?;
    }
    for path in files
        .iter()
        .filter(|p| !p.extension().is_some_and(|s| s == "body"))
    {
        fs::remove_file(path)?;
    }
    fs::remove_dir(run)
}

pub(crate) struct RunDirectory {
    pub root: PathBuf,
    pub path: PathBuf,
    owner: Option<File>,
    pub recovered: usize,
    pub warnings: Vec<String>,
}
impl RunDirectory {
    pub fn create(root: &Path) -> std::io::Result<Self> {
        let absolute = if root.is_absolute() {
            root.to_owned()
        } else {
            std::env::current_dir()?.join(root)
        };
        for parent in absolute.ancestors() {
            if parent.exists() {
                plain(parent, true)?;
            }
        }
        fs::create_dir_all(&absolute)?;
        let root = fs::canonicalize(absolute)?;
        let _manager = lock(&root)?;
        let mut recovered = 0;
        let mut warnings = Vec::new();
        for item in fs::read_dir(&root)? {
            let item = item?;
            if !item.file_name().to_str().is_some_and(run_name) {
                continue;
            }
            let run = item.path();
            let result = (|| -> std::io::Result<bool> {
                inspect(&root, &run)?;
                let owner_path = run.join("owner.lock");
                let owner = if owner_path.exists() {
                    let file = OpenOptions::new().read(true).write(true).open(owner_path)?;
                    if let Err(error) = file.try_lock_exclusive() {
                        if error.kind() == std::io::ErrorKind::WouldBlock {
                            return Ok(false);
                        }
                        // Windows may report lock contention as PermissionDenied.
                        if error.raw_os_error() == Some(33) {
                            return Ok(false);
                        }
                        return Err(error);
                    }
                    Some(file)
                } else {
                    None
                };
                drop(owner);
                remove_flat(&root, &run)?;
                Ok(true)
            })();
            match result {
                Ok(true) => recovered += 1,
                Ok(false) => {}
                Err(error) => {
                    if warnings.len() < 16 {
                        warnings.push(format!("skipped {}: {error}", run.display()));
                    }
                }
            }
        }
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).map_err(|e| std::io::Error::other(e.to_string()))?;
        let name: String = random
            .iter()
            .flat_map(|b| {
                let digits = b"0123456789abcdef";
                [
                    digits[(b >> 4) as usize] as char,
                    digits[(b & 15) as usize] as char,
                ]
            })
            .collect();
        let path = root.join(format!("run-{name}"));
        fs::create_dir(&path)?;
        let created = (|| {
            let owner = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(path.join("owner.lock"))?;
            owner.lock_exclusive()?;
            let mut marker = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path.join("format"))?;
            marker.write_all(MARKER)?;
            Ok::<_, std::io::Error>(owner)
        })();
        match created {
            Ok(owner) => Ok(Self {
                root,
                path,
                owner: Some(owner),
                recovered,
                warnings,
            }),
            Err(error) => {
                let _ = remove_flat(&root, &path);
                Err(error)
            }
        }
    }
    pub fn cleanup(&mut self) -> std::io::Result<()> {
        if self.owner.is_none() {
            return Ok(());
        }
        let _manager = lock(&self.root)?;
        self.owner.take();
        remove_flat(&self.root, &self.path)
    }
}
impl Drop for RunDirectory {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}
