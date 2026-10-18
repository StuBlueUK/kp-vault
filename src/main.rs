mod app;
mod crypto;
mod icon;
mod model;
mod store;
mod tray;

fn main() -> eframe::Result {
    let icon = icon::load();

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("KP Vault")
            .with_inner_size([1060.0, 760.0])
            .with_min_inner_size([820.0, 560.0])
            .with_icon(icon.egui()),
        ..Default::default()
    };

    eframe::run_native(
        "KP Vault",
        options,
        Box::new(move |cc| Ok(Box::new(app::VaultApp::new(cc, icon)))),
    )
}
