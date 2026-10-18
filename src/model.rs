use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// Secrets are wiped from memory when a record is dropped (e.g. on lock).
#[derive(Serialize, Deserialize, Clone)]
pub struct PasswordEntry {
    pub name: String,
    #[serde(default)]
    pub username: String,
    pub value: String,
    #[serde(skip)]
    pub revealed: bool,
}

impl PasswordEntry {
    pub fn blank() -> Self {
        Self {
            name: String::new(),
            username: String::new(),
            value: String::new(),
            revealed: true,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SecretRecord {
    pub id: u64,
    pub label: String,
    pub description: String,
    #[serde(default)]
    pub entries: Vec<PasswordEntry>,
    // One-off field from the pre-multi-password format; folded into `entries` on load.
    #[serde(default, rename = "password", skip_serializing_if = "String::is_empty")]
    pub legacy_password: String,
    pub notes: String,
}

impl Drop for SecretRecord {
    fn drop(&mut self) {
        self.description.zeroize();
        self.legacy_password.zeroize();
        self.notes.zeroize();
        for entry in &mut self.entries {
            entry.name.zeroize();
            entry.username.zeroize();
            entry.value.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EmailRecord {
    pub id: u64,
    pub label: String,
    pub name: String,
    pub email: String,
    pub phone: String,
    pub website: String,
    pub subject: String,
    pub message: String,
}

impl Drop for EmailRecord {
    fn drop(&mut self) {
        self.name.zeroize();
        self.email.zeroize();
        self.phone.zeroize();
        self.website.zeroize();
        self.subject.zeroize();
        self.message.zeroize();
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Record {
    Secret(SecretRecord),
    Email(EmailRecord),
}

impl Record {
    pub fn id(&self) -> u64 {
        match self {
            Record::Secret(r) => r.id,
            Record::Email(r) => r.id,
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Record::Secret(r) => &r.label,
            Record::Email(r) => &r.label,
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Record::Secret(_) => "🔑",
            Record::Email(_) => "✉",
        }
    }

    pub fn kind_label(&self) -> &'static str {
        match self {
            Record::Secret(_) => "Password / Note",
            Record::Email(_) => "Email",
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct Vault {
    pub records: Vec<Record>,
    pub next_id: u64,
}

impl Vault {
    fn take_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    pub fn add_secret(&mut self) -> u64 {
        let id = self.take_id();
        self.records.push(Record::Secret(SecretRecord {
            id,
            label: String::new(),
            description: String::new(),
            entries: vec![PasswordEntry::blank()],
            legacy_password: String::new(),
            notes: String::new(),
        }));
        id
    }

    pub fn add_email(&mut self) -> u64 {
        let id = self.take_id();
        self.records.push(Record::Email(EmailRecord {
            id,
            label: String::new(),
            name: String::new(),
            email: String::new(),
            phone: String::new(),
            website: String::new(),
            subject: String::new(),
            message: String::new(),
        }));
        id
    }

    pub fn get_mut(&mut self, id: u64) -> Option<&mut Record> {
        self.records.iter_mut().find(|r| r.id() == id)
    }

    pub fn remove(&mut self, id: u64) {
        self.records.retain(|r| r.id() != id);
    }

    /// Fold any legacy single-password field into the entries list.
    pub fn migrate(&mut self) {
        for record in &mut self.records {
            if let Record::Secret(srec) = record {
                if srec.entries.is_empty() && !srec.legacy_password.is_empty() {
                    let value = std::mem::take(&mut srec.legacy_password);
                    srec.entries.push(PasswordEntry {
                        name: "Password".into(),
                        username: String::new(),
                        value,
                        revealed: false,
                    });
                }
            }
        }
    }
}
