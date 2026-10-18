use egui::IconData;

const ICON_PNG: &[u8] = include_bytes!("../assets/icon.png");

pub struct AppIcon {
    pub rgba: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

pub fn load() -> AppIcon {
    match image::load_from_memory_with_format(ICON_PNG, image::ImageFormat::Png) {
        Ok(img) => {
            let buf = img.to_rgba8();
            let (width, height) = (buf.width(), buf.height());
            AppIcon {
                rgba: buf.into_raw(),
                width,
                height,
            }
        }
        Err(_) => fallback(),
    }
}

fn fallback() -> AppIcon {
    let (width, height) = (64u32, 64u32);
    let mut rgba = Vec::with_capacity((width * height * 4) as usize);
    for _ in 0..(width * height) {
        rgba.extend_from_slice(&[14, 165, 233, 255]);
    }
    AppIcon {
        rgba,
        width,
        height,
    }
}

impl AppIcon {
    pub fn egui(&self) -> IconData {
        IconData {
            rgba: self.rgba.clone(),
            width: self.width,
            height: self.height,
        }
    }

    /// StatusNotifierItem wants ARGB32 in network byte order.
    pub fn ksni_pixmap(&self) -> Vec<ksni::Icon> {
        let mut argb = Vec::with_capacity(self.rgba.len());
        for px in self.rgba.chunks_exact(4) {
            argb.extend_from_slice(&[px[3], px[0], px[1], px[2]]);
        }
        vec![ksni::Icon {
            width: self.width as i32,
            height: self.height as i32,
            data: argb,
        }]
    }
}
