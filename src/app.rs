use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::{Duration, Instant};

use egui::{Align, Button, Color32, Context, Id, Key, Label, Layout, RichText, TextEdit, Ui};
use zeroize::Zeroize;

use crate::crypto::{self, EncKey};
use crate::icon::AppIcon;
use crate::model::{PasswordEntry, Record, Vault};
use crate::store::Store;
use crate::tray::{self, TrayMsg};

const CLIP_CLEAR_SECS: u64 = 30;
const NOTICE_SECS: u64 = 6;
const MIN_MASTER_LEN: usize = 8;
const LABEL_W: f32 = 120.0;
const ICON_W: f32 = 42.0;
const ROW_H: f32 = 36.0;

enum Stage {
    FirstRun,
    Locked,
    Unlocked,
}

pub struct VaultApp {
    store: Store,
    stage: Stage,
    pw1: String,
    pw2: String,
    error: Option<String>,
    status: Option<String>,
    notice: Option<(String, Instant)>,
    vault: Option<Vault>,
    enc: Option<EncKey>,
    selected: Option<u64>,
    filter: String,
    dirty: bool,
    pending_delete: Option<u64>,
    import_path: Option<PathBuf>,
    import_password: String,
    import_error: Option<String>,
    import_pending: Option<Vault>,
    clip_clear_at: Option<Instant>,
    tray_handle: Option<ksni::blocking::Handle<tray::KvTray>>,
    tray_rx: Receiver<TrayMsg>,
    quitting: Arc<AtomicBool>,
}

impl VaultApp {
    pub fn new(cc: &eframe::CreationContext<'_>, icon: AppIcon) -> Self {
        configure_style(&cc.egui_ctx);
        let store = Store::new();
        let stage = if store.exists() {
            Stage::Locked
        } else {
            Stage::FirstRun
        };
        let (tx, tray_rx) = std::sync::mpsc::channel();
        let quitting = Arc::new(AtomicBool::new(false));
        let tray_handle = tray::spawn(cc.egui_ctx.clone(), tx, quitting.clone(), &icon);
        Self {
            store,
            stage,
            pw1: String::new(),
            pw2: String::new(),
            error: None,
            status: None,
            notice: None,
            vault: None,
            enc: None,
            selected: None,
            filter: String::new(),
            dirty: false,
            pending_delete: None,
            import_path: None,
            import_password: String::new(),
            import_error: None,
            import_pending: None,
            clip_clear_at: None,
            tray_handle,
            tray_rx,
            quitting,
        }
    }

    fn vault_mut(&mut self) -> &mut Vault {
        self.vault.as_mut().expect("unlocked")
    }

    fn authenticate(&mut self, first_run: bool) {
        self.error = None;
        if first_run {
            if self.pw1.len() < MIN_MASTER_LEN {
                self.error = Some(format!("Use at least {MIN_MASTER_LEN} characters."));
                return;
            }
            if self.pw1 != self.pw2 {
                self.error = Some("The passwords do not match.".into());
                return;
            }
            let vault = Vault::default();
            let json = match serde_json::to_vec(&vault) {
                Ok(json) => json,
                Err(e) => {
                    self.error = Some(e.to_string());
                    return;
                }
            };
            match crypto::create(&self.pw1, &json) {
                Ok((blob, enc)) => {
                    if let Err(e) = self.store.write(&blob) {
                        self.error = Some(format!("Could not create vault file: {e}"));
                        return;
                    }
                    self.vault = Some(vault);
                    self.enc = Some(enc);
                    self.stage = Stage::Unlocked;
                    self.pw1.zeroize();
                    self.pw2.zeroize();
                    self.selected = None;
                    self.status = Some("Vault created. Add your first record on the left.".into());
                }
                Err(e) => self.error = Some(e.to_string()),
            }
        } else {
            let blob = match self.store.read() {
                Ok(blob) => blob,
                Err(e) => {
                    self.error = Some(format!("Could not read vault file: {e}"));
                    return;
                }
            };
            match crypto::unlock(&blob, &self.pw1) {
                Ok((plaintext, enc)) => match serde_json::from_slice::<Vault>(&plaintext) {
                    Ok(mut vault) => {
                        vault.migrate();
                        self.selected = vault.records.first().map(|r| r.id());
                        self.vault = Some(vault);
                        self.enc = Some(enc);
                        self.stage = Stage::Unlocked;
                        self.pw1.zeroize();
                        self.status = None;
                    }
                    Err(e) => self.error = Some(format!("Vault contents are unreadable: {e}")),
                },
                Err(_) => {
                    self.error = Some("Wrong master password, or the vault file is damaged.".into())
                }
            }
        }
    }

    fn tick_clipboard(&mut self, ctx: &Context) {
        if let Some(at) = self.clip_clear_at {
            let now = Instant::now();
            if now >= at {
                ctx.copy_text(String::new());
                self.clip_clear_at = None;
                self.status = Some("Clipboard cleared.".into());
            } else {
                ctx.request_repaint_after(at.saturating_duration_since(now));
            }
        }
    }

    fn handle_tray(&mut self) {
        while let Ok(msg) = self.tray_rx.try_recv() {
            match msg {
                TrayMsg::Lock => {
                    if matches!(self.stage, Stage::Unlocked) {
                        self.lock();
                    }
                }
            }
        }
    }

    fn hide_to_tray(&self, ctx: &Context) {
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
    }

    fn persist(&mut self) {
        let result = {
            let (Some(vault), Some(enc)) = (&self.vault, &self.enc) else {
                return;
            };
            serde_json::to_vec(vault)
                .map_err(|e| anyhow::anyhow!(e))
                .and_then(|json| crypto::reseal(enc, &json))
                .and_then(|blob| self.store.write(&blob))
        };
        self.dirty = false;
        self.status = Some(match result {
            Ok(()) => "Saved.".into(),
            Err(e) => format!("Save failed: {e}"),
        });
    }

    fn lock(&mut self) {
        if self.dirty {
            self.persist();
        }
        self.vault = None;
        self.enc = None;
        self.selected = None;
        self.filter.clear();
        self.dirty = false;
        self.clip_clear_at = None;
        self.notice = None;
        self.import_path = None;
        self.import_password.zeroize();
        self.import_error = None;
        self.import_pending = None;
        self.pw1.clear();
        self.pw2.clear();
        self.error = None;
        self.status = None;
        self.stage = Stage::Locked;
    }

    fn auth_screen(&mut self, ui: &mut Ui, first_run: bool) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(90.0);
                ui.heading(RichText::new("KP Vault").size(32.0));
                ui.add_space(8.0);
                if first_run {
                    ui.label("Choose a master password. It is never stored — if you lose it, the vault cannot be recovered.");
                } else {
                    ui.label("Enter your master password to unlock the vault.");
                }
                ui.add_space(20.0);

                let resp = ui.add(
                    TextEdit::singleline(&mut self.pw1)
                        .password(true)
                        .desired_width(400.0)
                        .margin(egui::Margin::symmetric(12, 10))
                        .hint_text("Master password"),
                );
                let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));

                if first_run {
                    ui.add_space(10.0);
                    ui.add(
                        TextEdit::singleline(&mut self.pw2)
                            .password(true)
                            .desired_width(400.0)
                            .margin(egui::Margin::symmetric(12, 10))
                            .hint_text("Confirm master password"),
                    );
                }

                ui.add_space(20.0);
                let label = if first_run { "Create vault" } else { "Unlock" };
                if ui.add_sized([200.0, 40.0], Button::new(label)).clicked() || enter {
                    self.authenticate(first_run);
                }

                if let Some(err) = &self.error {
                    ui.add_space(14.0);
                    ui.colored_label(Color32::from_rgb(255, 130, 130), err);
                }
                if let Some(msg) = &self.status {
                    ui.add_space(14.0);
                    ui.colored_label(Color32::from_rgb(140, 210, 140), msg);
                }
                if !first_run {
                    ui.add_space(26.0);
                    ui.label(RichText::new(format!("Vault: {}", self.store.path().display())).small().weak());
                }
            });
        });
    }

    fn side_panel(&mut self, ui: &mut Ui) {
        egui::Panel::left("records_panel")
            .resizable(true)
            .default_size(260.0)
            .min_size(200.0)
            .max_size(380.0)
            .show(ui, |ui| {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.heading("KP Vault");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .button("🔒 Lock")
                            .on_hover_text("Lock and wipe secrets from memory")
                            .clicked()
                        {
                            self.lock();
                        }
                        if self.tray_handle.is_some()
                            && ui
                                .button("⊟ Tray")
                                .on_hover_text("Minimise to the notification area")
                                .clicked()
                        {
                            self.hide_to_tray(ui.ctx());
                        }
                    });
                });
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("＋ Password").clicked() {
                        let id = self.vault_mut().add_secret();
                        self.selected = Some(id);
                        self.dirty = true;
                    }
                    if ui.button("＋ Email").clicked() {
                        let id = self.vault_mut().add_email();
                        self.selected = Some(id);
                        self.dirty = true;
                    }
                });
                ui.add_space(6.0);
                ui.add(
                    TextEdit::singleline(&mut self.filter)
                        .hint_text("Search…")
                        .desired_width(f32::INFINITY),
                );
                let count = self.vault.as_ref().map(|v| v.records.len()).unwrap_or(0);
                ui.add_space(4.0);
                ui.label(
                    RichText::new(format!("{count} record(s) · clipboard clears in {CLIP_CLEAR_SECS}s"))
                        .small()
                        .weak(),
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("⇪ Import…").clicked() {
                        self.begin_import();
                    }
                    if ui.button("⇩ Export…").clicked() {
                        self.export_vault();
                    }
                });
                ui.separator();

                // Snapshot rows so the list can render without borrowing the vault.
                let mut rows: Vec<(u64, String, &'static str)> = Vec::new();
                if let Some(vault) = &self.vault {
                    let needle = self.filter.to_lowercase();
                    for record in &vault.records {
                        if needle.is_empty() || record.label().to_lowercase().contains(&needle) {
                            let name = if record.label().trim().is_empty() {
                                "(untitled)".to_string()
                            } else {
                                record.label().to_string()
                            };
                            rows.push((record.id(), name, record.icon()));
                        }
                    }
                }

                let selected = self.selected;
                let mut pick: Option<u64> = None;
                let mut ask_delete: Option<u64> = None;

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for (id, name, icon) in &rows {
                            ui.horizontal(|ui| {
                                if ui
                                    .selectable_label(selected == Some(*id), format!("{icon}  {name}"))
                                    .clicked()
                                {
                                    pick = Some(*id);
                                }
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if ui.small_button("🗑").on_hover_text("Delete").clicked() {
                                        ask_delete = Some(*id);
                                    }
                                });
                            });
                        }
                    });

                if let Some(id) = pick {
                    self.selected = Some(id);
                }
                if let Some(id) = ask_delete {
                    self.pending_delete = Some(id);
                }

                if let Some(msg) = &self.status {
                    ui.add_space(6.0);
                    ui.separator();
                    ui.label(RichText::new(msg).small().color(Color32::from_rgb(150, 195, 150)));
                }
            });
    }

    fn detail_panel(&mut self, ui: &mut Ui) {
        egui::CentralPanel::default().show(ui, |ui| {
            self.detail_contents(ui);
        });
    }

    fn detail_contents(&mut self, ui: &mut Ui) {
        let Some(id) = self.selected else {
            ui.centered_and_justified(|ui| {
                ui.label(
                    RichText::new(
                        "Select a record on the left, or create one with ＋ Password / ＋ Email.",
                    )
                    .weak(),
                );
            });
            return;
        };

        let dirty = &mut self.dirty;
        let clip = &mut self.clip_clear_at;
        let notice = &mut self.notice;
        let mut ask_delete = false;

        let Some(vault) = self.vault.as_mut() else {
            return;
        };
        let Some(record) = vault.get_mut(id) else {
            ui.label("Record not found.");
            return;
        };

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new(record.kind_label()).strong().size(18.0));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("🗑 Delete").clicked() {
                    ask_delete = true;
                }
            });
        });
        ui.separator();
        ui.add_space(6.0);

        if let Some((msg, until)) = notice.clone() {
            if Instant::now() < until {
                ui.colored_label(Color32::from_rgb(255, 190, 120), msg);
                ui.add_space(4.0);
                ui.ctx()
                    .request_repaint_after(until.saturating_duration_since(Instant::now()));
            } else {
                *notice = None;
            }
        }

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| match record {
                Record::Secret(srec) => {
                    if title_row(ui, &mut srec.label, "e.g. Router admin") {
                        *dirty = true;
                    }
                    if field_row(ui, "Description", &mut srec.description, None, clip) {
                        *dirty = true;
                    }

                    let mut add_entry = false;
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Passwords").size(15.0).strong());
                        if ui.button("＋ Add field").clicked() {
                            add_entry = true;
                        }
                    });
                    ui.add_space(4.0);

                    let mut remove_entry: Option<usize> = None;
                    for (i, entry) in srec.entries.iter_mut().enumerate() {
                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                let w = (ui.available_width() - ICON_W - 8.0).max(120.0);
                                if ui
                                    .add(
                                        TextEdit::singleline(&mut entry.name)
                                            .desired_width(w)
                                            .margin(text_margin())
                                            .hint_text("Title"),
                                    )
                                    .changed()
                                {
                                    *dirty = true;
                                }
                                if icon_button(ui, "✕", "Remove this field") {
                                    remove_entry = Some(i);
                                }
                            });
                            ui.horizontal(|ui| {
                                if copy_button(ui, &entry.username) {
                                    *clip = Some(Instant::now() + Duration::from_secs(CLIP_CLEAR_SECS));
                                }
                                let width = ui.available_width();
                                if ui
                                    .add(
                                        TextEdit::singleline(&mut entry.username)
                                            .desired_width(width)
                                            .margin(text_margin())
                                            .hint_text("username"),
                                    )
                                    .changed()
                                {
                                    *dirty = true;
                                }
                            });
                            ui.horizontal(|ui| {
                                if copy_button(ui, &entry.value) {
                                    *clip = Some(Instant::now() + Duration::from_secs(CLIP_CLEAR_SECS));
                                }
                                let eye = if entry.revealed { "🙈" } else { "👁" };
                                if icon_button(ui, eye, "Show / hide") {
                                    entry.revealed = !entry.revealed;
                                }
                                if icon_button(ui, "🎲", "Generate a strong password") {
                                    if entry.value.is_empty() {
                                        entry.value = crypto::gen_password(20);
                                        entry.revealed = true;
                                        *dirty = true;
                                    } else {
                                        *notice = Some((
                                            "Field not empty — clear it before generating a new password."
                                                .into(),
                                            Instant::now() + Duration::from_secs(NOTICE_SECS),
                                        ));
                                    }
                                }
                                let width = ui.available_width();
                                if ui
                                    .add(
                                        TextEdit::singleline(&mut entry.value)
                                            .password(!entry.revealed)
                                            .desired_width(width)
                                            .margin(text_margin())
                                            .hint_text("password"),
                                    )
                                    .changed()
                                {
                                    *dirty = true;
                                }
                            });
                        });
                        ui.add_space(6.0);
                    }

                    if add_entry {
                        srec.entries.push(PasswordEntry::blank());
                        *dirty = true;
                    }
                    if let Some(i) = remove_entry {
                        srec.entries.remove(i);
                        *dirty = true;
                    }
                    if srec.entries.is_empty() {
                        ui.label(RichText::new("No fields — click ＋ Add field.").weak());
                    }

                    if multiline_row(ui, "Notes", &mut srec.notes, "Free-form notes…", 6, clip) {
                        *dirty = true;
                    }
                }
                Record::Email(erec) => {
                    if title_row(ui, &mut erec.label, "e.g. Support contact") {
                        *dirty = true;
                    }
                    if field_row(ui, "Name", &mut erec.name, Some(440.0), clip) {
                        *dirty = true;
                    }
                    if field_row(ui, "Email", &mut erec.email, Some(440.0), clip) {
                        *dirty = true;
                    }
                    if field_row(ui, "Phone", &mut erec.phone, Some(240.0), clip) {
                        *dirty = true;
                    }
                    if field_row(ui, "Website", &mut erec.website, Some(440.0), clip) {
                        *dirty = true;
                    }
                    if field_row(ui, "Subject", &mut erec.subject, Some(520.0), clip) {
                        *dirty = true;
                    }
                    if multiline_row(ui, "Message", &mut erec.message, "Message body…", 10, clip) {
                        *dirty = true;
                    }
                }
            });

        if ask_delete {
            self.pending_delete = Some(id);
        }
    }

    fn delete_modal(&mut self, ctx: &Context) {
        let Some(id) = self.pending_delete else {
            return;
        };
        let label = self
            .vault
            .as_ref()
            .and_then(|v| v.records.iter().find(|r| r.id() == id))
            .map(|r| r.label().to_string())
            .unwrap_or_default();
        let shown = if label.trim().is_empty() {
            "(untitled)".to_string()
        } else {
            label
        };

        let modal = egui::Modal::new(Id::unique("confirm_delete")).show(ctx, |ui| {
            ui.set_width(320.0);
            ui.heading("Delete record?");
            ui.add_space(6.0);
            ui.label(format!(
                "“{shown}” will be permanently removed from your vault."
            ));
            ui.add_space(14.0);
            let mut go = false;
            let mut cancel = false;
            ui.horizontal(|ui| {
                if ui.button("Delete").clicked() {
                    go = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
            (go, cancel)
        });

        let should_close = modal.should_close();
        let (go, cancel) = modal.inner;

        if go {
            if let Some(vault) = self.vault.as_mut() {
                vault.remove(id);
            }
            if self.selected == Some(id) {
                self.selected = None;
            }
            self.dirty = true;
            self.status = Some("Record deleted.".into());
            self.pending_delete = None;
        } else if cancel || should_close {
            self.pending_delete = None;
        }
    }

    fn export_vault(&mut self) {
        if self.vault.is_none() {
            return;
        }
        if self.dirty {
            self.persist();
        }
        let picked = rfd::FileDialog::new()
            .set_title("Export encrypted vault")
            .set_file_name("kp-vault-backup.kpv")
            .add_filter("KP Vault", &["kpv"])
            .save_file();
        let Some(path) = picked else {
            return;
        };
        self.status = Some(match self.store.export_to(&path) {
            Ok(()) => format!("Exported encrypted copy to {}", path.display()),
            Err(e) => format!("Export failed: {e}"),
        });
    }

    fn begin_import(&mut self) {
        let picked = rfd::FileDialog::new()
            .set_title("Import vault")
            .add_filter("KP Vault", &["kpv"])
            .pick_file();
        let Some(path) = picked else {
            return;
        };
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                self.status = Some(format!("Import failed: {e}"));
                return;
            }
        };
        // Own backups share this session's salt, so the cached key opens them.
        if self.open_imported(&bytes).is_err() {
            self.import_path = Some(path);
            self.import_password.clear();
            self.import_error = None;
        }
    }

    fn open_imported(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        let enc = self.enc.as_ref().ok_or_else(|| anyhow::anyhow!("locked"))?;
        let plain = crypto::open_with(enc, bytes)?;
        let mut vault: Vault = serde_json::from_slice(&plain)?;
        vault.migrate();
        self.import_pending = Some(vault);
        Ok(())
    }

    fn import_password_modal(&mut self, ctx: &Context) {
        let Some(path) = self.import_path.clone() else {
            return;
        };
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        let mut go = false;
        let mut cancel = false;
        let modal = egui::Modal::new(Id::unique("import_password")).show(ctx, |ui| {
            ui.set_width(380.0);
            ui.heading("Unlock imported file");
            ui.add_space(6.0);
            ui.label(format!("Enter the master password for “{name}”."));
            ui.add_space(8.0);
            let resp = ui.add(
                TextEdit::singleline(&mut self.import_password)
                    .password(true)
                    .desired_width(f32::INFINITY)
                    .hint_text("master password"),
            );
            if resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                go = true;
            }
            if let Some(err) = &self.import_error {
                ui.add_space(6.0);
                ui.colored_label(Color32::from_rgb(255, 130, 130), err);
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.button("Decrypt").clicked() {
                    go = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        let should_close = modal.should_close();
        if go {
            self.try_import_password(&path);
        } else if cancel || should_close {
            self.cancel_import();
        }
    }

    fn try_import_password(&mut self, path: &std::path::Path) {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                self.import_error = Some(format!("Could not read file: {e}"));
                return;
            }
        };
        match crypto::unlock(&bytes, &self.import_password) {
            Ok((plain, _)) => match serde_json::from_slice::<Vault>(&plain) {
                Ok(mut vault) => {
                    vault.migrate();
                    self.import_pending = Some(vault);
                    self.cancel_import();
                }
                Err(e) => self.import_error = Some(format!("Not a readable vault: {e}")),
            },
            Err(_) => self.import_error = Some("Wrong password, or not a KP Vault file.".into()),
        }
    }

    fn cancel_import(&mut self) {
        self.import_path = None;
        self.import_password.zeroize();
        self.import_error = None;
    }

    fn import_confirm_modal(&mut self, ctx: &Context) {
        if self.import_pending.is_none() {
            return;
        }
        let incoming = self
            .import_pending
            .as_ref()
            .map(|v| v.records.len())
            .unwrap_or(0);
        let current = self.vault.as_ref().map(|v| v.records.len()).unwrap_or(0);
        let modal = egui::Modal::new(Id::unique("confirm_import")).show(ctx, |ui| {
            ui.set_width(380.0);
            ui.heading("Replace vault contents?");
            ui.add_space(6.0);
            ui.label(format!(
                "The file holds {incoming} record(s). Importing replaces all {current} current \
                 record(s). Your current master password will still unlock the vault."
            ));
            ui.add_space(14.0);
            let mut go = false;
            let mut cancel = false;
            ui.horizontal(|ui| {
                if ui.button("Import").clicked() {
                    go = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
            (go, cancel)
        });
        let should_close = modal.should_close();
        let (go, cancel) = modal.inner;
        if go {
            if let Some(vault) = self.import_pending.take() {
                self.selected = vault.records.first().map(|r| r.id());
                self.vault = Some(vault);
                self.dirty = true;
                self.status = Some("Vault imported.".into());
            }
        } else if cancel || should_close {
            self.import_pending = None;
        }
    }
}

impl eframe::App for VaultApp {
    fn logic(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.handle_tray();
        self.tick_clipboard(ctx);
    }

    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        // Closing the window (X) hides to the tray instead of quitting.
        if ui.ctx().input(|i| i.viewport().close_requested())
            && !self.quitting.load(Ordering::SeqCst)
        {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.hide_to_tray(ui.ctx());
        }

        match self.stage {
            Stage::FirstRun => self.auth_screen(ui, true),
            Stage::Locked => self.auth_screen(ui, false),
            Stage::Unlocked => {
                self.side_panel(ui);
                self.detail_panel(ui);
                if self.dirty {
                    self.persist();
                }
            }
        }
        self.delete_modal(ui.ctx());
        self.import_password_modal(ui.ctx());
        self.import_confirm_modal(ui.ctx());
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Some(handle) = &self.tray_handle {
            handle.shutdown().wait();
        }
    }
}

fn icon_button(ui: &mut Ui, glyph: &str, tip: &str) -> bool {
    ui.add(
        Button::new(RichText::new(glyph).size(18.0))
            .min_size(egui::vec2(ICON_W, ROW_H)),
    )
    .on_hover_text(tip)
    .clicked()
}

fn copy_button(ui: &mut Ui, text: &str) -> bool {
    if icon_button(ui, "⧉", "Copy to clipboard") {
        ui.ctx().copy_text(text.to_owned());
        ui.ctx()
            .request_repaint_after(Duration::from_secs(CLIP_CLEAR_SECS));
        true
    } else {
        false
    }
}

fn text_margin() -> egui::Margin {
    egui::Margin::symmetric(10, 8)
}

fn title_row(ui: &mut Ui, value: &mut String, hint: &str) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.add_sized([LABEL_W, ROW_H], Label::new(RichText::new("Label").size(15.0)));
        ui.allocate_space(egui::vec2(ICON_W, ROW_H));
        let width = ui.available_width();
        if ui
            .add(
                TextEdit::singleline(value)
                    .desired_width(width)
                    .margin(text_margin())
                    .hint_text(hint.to_owned()),
            )
            .changed()
        {
            changed = true;
        }
    });
    changed
}

fn field_row(
    ui: &mut Ui,
    name: &str,
    value: &mut String,
    width: Option<f32>,
    clip: &mut Option<Instant>,
) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.add_sized([LABEL_W, ROW_H], Label::new(RichText::new(name).size(15.0)));
        if copy_button(ui, value.as_str()) {
            *clip = Some(Instant::now() + Duration::from_secs(CLIP_CLEAR_SECS));
        }
        let width = width.unwrap_or_else(|| ui.available_width());
        if ui
            .add(
                TextEdit::singleline(&mut *value)
                    .desired_width(width)
                    .margin(text_margin()),
            )
            .changed()
        {
            changed = true;
        }
    });
    changed
}

fn multiline_row(
    ui: &mut Ui,
    name: &str,
    value: &mut String,
    hint: &str,
    rows: usize,
    clip: &mut Option<Instant>,
) -> bool {
    let mut changed = false;
    ui.add_space(8.0);
    ui.label(RichText::new(name).size(15.0));
    ui.add_space(2.0);
    ui.horizontal_top(|ui| {
        if copy_button(ui, value.as_str()) {
            *clip = Some(Instant::now() + Duration::from_secs(CLIP_CLEAR_SECS));
        }
        let width = (ui.available_width() - 8.0).max(200.0);
        if ui
            .add(
                TextEdit::multiline(&mut *value)
                    .desired_rows(rows)
                    .desired_width(width)
                    .margin(text_margin())
                    .hint_text(hint.to_owned()),
            )
            .changed()
        {
            changed = true;
        }
    });
    changed
}

fn configure_style(ctx: &Context) {
    use egui::{FontFamily, FontId, TextStyle};
    ctx.all_styles_mut(|style| {
        style
            .text_styles
            .insert(TextStyle::Body, FontId::new(16.0, FontFamily::Proportional));
        style
            .text_styles
            .insert(TextStyle::Button, FontId::new(16.0, FontFamily::Proportional));
        style
            .text_styles
            .insert(TextStyle::Small, FontId::new(13.5, FontFamily::Proportional));
        style
            .text_styles
            .insert(TextStyle::Heading, FontId::new(24.0, FontFamily::Proportional));
        style
            .text_styles
            .insert(TextStyle::Monospace, FontId::new(16.0, FontFamily::Monospace));
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 7.0);
        style.spacing.interact_size.y = 32.0;
    });
}
