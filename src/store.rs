use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn new() -> Self {
        let dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("kp-vault");
        Store {
            path: dir.join("vault.kpv"),
        }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn read(&self) -> anyhow::Result<Vec<u8>> {
        Ok(fs::read(&self.path)?)
    }

    /// Atomic write: temp file (0600) then rename, so a crash never truncates the vault.
    pub fn write(&self, data: &[u8]) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }

        let tmp = self.path.with_extension("kpv.tmp");
        {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(data)?;
            file.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600));
        Ok(())
    }

    /// Copy the encrypted blob to `dest` as-is, mode 0600.
    pub fn export_to(&self, dest: &Path) -> anyhow::Result<()> {
        let data = self.read()?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(dest)?;
        file.write_all(&data)?;
        file.sync_all()?;
        Ok(())
    }
}
