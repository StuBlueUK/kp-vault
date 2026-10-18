use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;

use egui::{Context, ViewportCommand};
use ksni::blocking::{Handle, TrayMethods};
use ksni::menu::StandardItem;
use ksni::{Icon, MenuItem, Tray};

use crate::icon::AppIcon;

pub enum TrayMsg {
    Lock,
}

pub struct KvTray {
    ctx: Context,
    tx: Sender<TrayMsg>,
    quitting: Arc<AtomicBool>,
    icon: Vec<Icon>,
}

impl KvTray {
    fn show(&self) {
        self.ctx.send_viewport_cmd(ViewportCommand::Visible(true));
        self.ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
        self.ctx.send_viewport_cmd(ViewportCommand::Focus);
        self.ctx.request_repaint();
    }

    fn lock(&self) {
        let _ = self.tx.send(TrayMsg::Lock);
        self.ctx.request_repaint();
    }

    fn quit(&self) {
        self.quitting.store(true, Ordering::SeqCst);
        self.ctx.send_viewport_cmd(ViewportCommand::Close);
    }
}

impl Tray for KvTray {
    fn id(&self) -> String {
        "kp-vault".into()
    }

    fn title(&self) -> String {
        "KP Vault".into()
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        self.icon.clone()
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.show();
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![
            StandardItem {
                label: "Show KP Vault".into(),
                activate: Box::new(|t: &mut KvTray| t.show()),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Lock vault".into(),
                activate: Box::new(|t: &mut KvTray| t.lock()),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit".into(),
                activate: Box::new(|t: &mut KvTray| t.quit()),
                ..Default::default()
            }
            .into(),
        ]
    }
}

pub fn spawn(
    ctx: Context,
    tx: Sender<TrayMsg>,
    quitting: Arc<AtomicBool>,
    icon: &AppIcon,
) -> Option<Handle<KvTray>> {
    let tray = KvTray {
        ctx,
        tx,
        quitting,
        icon: icon.ksni_pixmap(),
    };
    match tray.spawn() {
        Ok(handle) => Some(handle),
        Err(e) => {
            eprintln!("kp-vault: system tray unavailable: {e}");
            None
        }
    }
}
