//! Native window for Sigil — same jobs and layout as the green web lab.
//! Build: cargo build --release --features lab --bin sigil-lab

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Frame, Margin,
    RichText, Sense, Stroke, TextEdit, Ui, Vec2,
};
use sigil::{
    gather_pieces, hex32, inscribe_path, scatter_pieces, scry_path, sha256, sha256_path,
    suggested_output_name, unseal_path, verify, Mode,
};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const BG: Color32 = Color32::from_rgb(8, 23, 16);
const CARD: Color32 = Color32::from_rgb(12, 36, 24);
const SECONDARY: Color32 = Color32::from_rgb(14, 36, 24);
const GOLD: Color32 = Color32::from_rgb(194, 153, 101);
const CREAM: Color32 = Color32::from_rgb(232, 220, 200);
const MUTED: Color32 = Color32::from_rgb(138, 154, 136);
const BORDER: Color32 = Color32::from_rgb(26, 58, 42);
const OK: Color32 = Color32::from_rgb(93, 138, 106);
const BAD: Color32 = Color32::from_rgb(180, 90, 74);
const HEADER_H: f32 = 56.0;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Lab,
    Scry,
    Sky,
    Grimoire,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LabTab {
    Inscribe,
    Describe,
}

struct ModeCopy {
    mode: Mode,
    label: &'static str,
    metaphor: &'static str,
    layout: &'static str,
    loss: &'static str,
    cost: &'static str,
    blurb: &'static str,
    k: u8,
    n: u8,
}

const MODES: [ModeCopy; 3] = [
    ModeCopy {
        mode: Mode::Glyph,
        label: "Glyph",
        metaphor: "Fingerprint",
        layout: "16 data · 0 spare",
        loss: "detect only",
        cost: "smallest",
        blurb: "Checks that nothing changed. It cannot repair a damaged file.",
        k: 16,
        n: 16,
    },
    ModeCopy {
        mode: Mode::Reflection,
        label: "Reflection",
        metaphor: "QR code",
        layout: "12 data · 4 spare",
        loss: "25% repair",
        cost: "~1.3×",
        blurb: "Can rebuild the file if up to 4 of 16 pieces are lost or damaged.",
        k: 12,
        n: 16,
    },
    ModeCopy {
        mode: Mode::Seal,
        label: "Seal",
        metaphor: "Vault",
        layout: "8 data · 8 spare",
        loss: "50% repair",
        cost: "~2×",
        blurb: "Can rebuild the file if up to 8 of 16 pieces are lost. About twice the size.",
        k: 8,
        n: 16,
    },
];

fn mode_copy(m: Mode) -> &'static ModeCopy {
    MODES.iter().find(|c| c.mode == m).unwrap_or(&MODES[1])
}

fn main() -> eframe::Result<()> {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1080.0, 780.0])
            .with_min_inner_size([860.0, 620.0])
            .with_title("Sigil"),
        ..Default::default()
    };
    eframe::run_native(
        "Sigil",
        opts,
        Box::new(|cc| {
            install_fonts(&cc.egui_ctx);
            let mut vis = egui::Visuals::dark();
            vis.panel_fill = BG;
            vis.window_fill = CARD;
            vis.extreme_bg_color = SECONDARY;
            vis.faint_bg_color = SECONDARY;
            vis.override_text_color = Some(CREAM);
            vis.selection.bg_fill = GOLD;
            vis.selection.stroke = Stroke::new(1.0_f32, GOLD);
            vis.widgets.noninteractive.bg_fill = CARD;
            vis.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, CREAM);
            vis.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER);
            vis.widgets.inactive.bg_fill = SECONDARY;
            vis.widgets.inactive.weak_bg_fill = SECONDARY;
            vis.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, CREAM);
            vis.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER);
            vis.widgets.inactive.corner_radius = CornerRadius::same(8);
            vis.widgets.hovered.bg_fill = Color32::from_rgb(26, 58, 42);
            vis.widgets.hovered.weak_bg_fill = Color32::from_rgb(26, 58, 42);
            vis.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, GOLD);
            vis.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, CREAM);
            vis.widgets.hovered.corner_radius = CornerRadius::same(8);
            vis.widgets.active.bg_fill = GOLD;
            vis.widgets.active.fg_stroke = Stroke::new(1.0_f32, BG);
            vis.widgets.active.corner_radius = CornerRadius::same(8);
            vis.widgets.open.bg_fill = SECONDARY;
            vis.widgets.open.bg_stroke = Stroke::new(1.0_f32, GOLD);
            vis.hyperlink_color = GOLD;
            vis.window_stroke = Stroke::new(1.0_f32, BORDER);
            vis.window_corner_radius = CornerRadius::same(12);
            vis.menu_corner_radius = CornerRadius::same(8);
            cc.egui_ctx.set_visuals(vis);
            let mut style = (*cc.egui_ctx.style()).clone();
            style.spacing.item_spacing = Vec2::new(10.0, 10.0);
            style.spacing.button_padding = Vec2::new(14.0, 8.0);
            style.spacing.window_margin = Margin::same(0);
            style.text_styles.insert(
                egui::TextStyle::Body,
                FontId::new(14.5, FontFamily::Proportional),
            );
            style.text_styles.insert(
                egui::TextStyle::Button,
                FontId::new(14.0, FontFamily::Proportional),
            );
            style.text_styles.insert(
                egui::TextStyle::Small,
                FontId::new(12.0, FontFamily::Proportional),
            );
            style
                .text_styles
                .insert(egui::TextStyle::Heading, FontId::new(28.0, serif_family()));
            style.text_styles.insert(
                egui::TextStyle::Monospace,
                FontId::new(12.5, FontFamily::Monospace),
            );
            cc.egui_ctx.set_style(style);
            Ok(Box::new(Lab::default()))
        }),
    )
}

fn serif_family() -> FontFamily {
    FontFamily::Name("serif".into())
}

fn stroke(c: Color32) -> Stroke {
    Stroke::new(1.0_f32, c)
}

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let serif = load_first(&[
        "/usr/share/fonts/truetype/liberation/LiberationSerif-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSerif.ttf",
        r"C:\Windows\Fonts\times.ttf",
        r"C:\Windows\Fonts\georgia.ttf",
    ]);
    let sans = load_first(&[
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        r"C:\Windows\Fonts\segoeui.ttf",
        r"C:\Windows\Fonts\arial.ttf",
    ]);
    let mono = load_first(&[
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        r"C:\Windows\Fonts\consola.ttf",
    ]);
    if let Some(b) = serif {
        fonts
            .font_data
            .insert("serif".into(), Arc::new(FontData::from_owned(b)));
        fonts.families.insert(serif_family(), vec!["serif".into()]);
    }
    if let Some(b) = sans {
        fonts
            .font_data
            .insert("sans".into(), Arc::new(FontData::from_owned(b)));
        fonts
            .families
            .get_mut(&FontFamily::Proportional)
            .unwrap()
            .insert(0, "sans".into());
    }
    if let Some(b) = mono {
        fonts
            .font_data
            .insert("mono".into(), Arc::new(FontData::from_owned(b)));
        fonts
            .families
            .get_mut(&FontFamily::Monospace)
            .unwrap()
            .insert(0, "mono".into());
    }
    ctx.set_fonts(fonts);
}

fn load_first(paths: &[&str]) -> Option<Vec<u8>> {
    for p in paths {
        if let Ok(b) = std::fs::read(p) {
            if !b.is_empty() {
                return Some(b);
            }
        }
    }
    None
}

#[derive(Clone)]
struct Probe {
    name: String,
    mode: Mode,
    live: usize,
    n: usize,
    k: usize,
    merkle_ok: bool,
    recovered: bool,
    orig: u64,
    true_name: String,
    envelope: String,
}

struct Lab {
    page: Page,
    tab: LabTab,
    mode: Mode,
    ward: String,
    covenant: String,
    input: String,
    input_len: u64,
    mark: String,
    geas: Vec<PathBuf>,
    companions: Vec<PathBuf>,
    hex_pct: u8,
    status: String,
    status_ok: bool,
    probe: Option<Probe>,
    described_to: String,
    scry_expected: String,
    sky_dir: String,
    sky_log: String,
}

impl Default for Lab {
    fn default() -> Self {
        Self {
            page: Page::Lab,
            tab: LabTab::Inscribe,
            mode: Mode::Reflection,
            ward: String::new(),
            covenant: String::new(),
            input: String::new(),
            input_len: 0,
            mark: String::new(),
            geas: Vec::new(),
            companions: Vec::new(),
            hex_pct: 25,
            status: String::new(),
            status_ok: true,
            probe: None,
            described_to: String::new(),
            scry_expected: String::new(),
            sky_dir: String::new(),
            sky_log: String::new(),
        }
    }
}

impl Lab {
    fn pass(&self) -> Option<&str> {
        let t = self.ward.trim();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    }

    fn geas_hashes(&self) -> Vec<[u8; 32]> {
        self.geas
            .iter()
            .filter_map(|p| sha256_path(p).ok())
            .collect()
    }

    fn companion_bytes(&self) -> Vec<Vec<u8>> {
        self.companions
            .iter()
            .filter_map(|p| std::fs::read(p).ok())
            .collect()
    }

    fn set_status(&mut self, ok: bool, msg: impl Into<String>) {
        self.status_ok = ok;
        self.status = msg.into();
    }

    fn pick_in(&mut self) {
        if let Some(p) = rfd::FileDialog::new().pick_file() {
            self.input_len = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            self.input = p.display().to_string();
            self.probe = None;
            self.described_to.clear();
        }
    }

    fn pick_mark(&mut self) {
        if let Some(p) = rfd::FileDialog::new()
            .add_filter("Sigil", &["sg1"])
            .pick_file()
        {
            self.mark = p.display().to_string();
            self.described_to.clear();
            self.refresh_probe();
        }
    }

    fn pick_folder(&mut self) {
        if let Some(p) = rfd::FileDialog::new().pick_folder() {
            self.sky_dir = p.display().to_string();
        }
    }

    fn pick_geas(&mut self) {
        if let Some(p) = rfd::FileDialog::new().pick_file() {
            if self.geas.len() >= 2 {
                self.geas.remove(0);
            }
            self.geas.push(p);
        }
    }

    fn pick_companions(&mut self) {
        if let Some(p) = rfd::FileDialog::new().pick_file() {
            if self.companions.len() >= 2 {
                self.companions.remove(0);
            }
            self.companions.push(p);
        }
    }

    fn refresh_probe(&mut self) {
        let p = PathBuf::from(self.mark.trim());
        match read_probe(&p) {
            Ok(pr) => {
                self.probe = Some(pr);
                self.set_status(true, String::new());
            }
            Err(e) => {
                self.probe = None;
                if p.is_file() {
                    self.set_status(false, e);
                }
            }
        }
    }

    fn inscribe(&mut self) {
        let src = PathBuf::from(self.input.trim());
        if !src.is_file() {
            self.set_status(false, "Choose a file first.");
            return;
        }
        let out = src.with_extension("sg1");
        let geas = self.geas_hashes();
        match inscribe_path(
            &src,
            &out,
            self.mode,
            self.pass(),
            self.covenant.trim(),
            &geas,
            4 * 1024 * 1024,
            None,
            0,
            64,
            None,
        ) {
            Ok((orig, stars, work)) => {
                self.mark = out.display().to_string();
                let note = if work {
                    format!(
                        "Inscribed {stars} stars → {}  ({})",
                        out.display(),
                        fmt_bytes(orig)
                    )
                } else {
                    format!("Inscribed → {}  ({})", out.display(), fmt_bytes(orig))
                };
                self.set_status(true, note);
                self.refresh_probe();
            }
            Err(e) => self.set_status(false, format!("Inscribe failed: {e}")),
        }
    }

    fn scry_current(&mut self) {
        let p = PathBuf::from(self.mark.trim());
        match scry_path(&p) {
            Ok(s) => {
                self.refresh_probe();
                self.set_status(true, s);
            }
            Err(e) => self.set_status(false, format!("Scry failed: {e}")),
        }
    }

    fn hex(&mut self) {
        let p = PathBuf::from(self.mark.trim());
        match punch(&p, self.hex_pct) {
            Ok(n) => {
                self.set_status(
                    true,
                    format!("Hex: wrote {n} bad bytes into {}", p.display()),
                );
                self.refresh_probe();
            }
            Err(e) => self.set_status(false, format!("Hex failed: {e}")),
        }
    }

    fn describe(&mut self) {
        let src = PathBuf::from(self.mark.trim());
        if !src.is_file() {
            self.set_status(false, "Choose a .sg1 first (or Inscribe).");
            return;
        }
        let suggested = restore_name(&src, self.input.trim());
        let mut dlg = rfd::FileDialog::new().set_file_name(&suggested);
        if let Some(parent) = src.parent() {
            dlg = dlg.set_directory(parent);
        }
        let dest = match dlg.save_file() {
            Some(p) => p,
            None => return,
        };
        let companions = self.companion_bytes();
        match unseal_path(&src, &dest, self.pass(), &companions) {
            Ok(_) => {
                self.described_to = dest.display().to_string();
                self.set_status(true, format!("De-scribed → {}", dest.display()));
            }
            Err(e) => self.set_status(false, format!("De-scribe failed: {e}")),
        }
    }

    fn scatter(&mut self) {
        let src = PathBuf::from(self.mark.trim());
        let dir = PathBuf::from(self.sky_dir.trim());
        if !src.is_file() {
            self.sky_log = "Choose a .sg1 first.".into();
            return;
        }
        if self.sky_dir.trim().is_empty() {
            self.pick_folder();
        }
        let dir = if dir.is_dir() {
            dir
        } else {
            PathBuf::from(self.sky_dir.trim())
        };
        if !dir.is_dir() {
            self.sky_log = "Choose a folder for the pieces.".into();
            return;
        }
        match std::fs::read(&src) {
            Ok(bytes) => match scatter_pieces(&bytes, &dir) {
                Ok(n) => {
                    self.sky_log = format!("Scattered {n} pieces into {}", dir.display());
                    self.set_status(true, self.sky_log.clone());
                }
                Err(e) => self.sky_log = format!("Scatter failed: {e}"),
            },
            Err(e) => self.sky_log = format!("Read failed: {e}"),
        }
    }

    fn gather(&mut self) {
        let dir = PathBuf::from(self.sky_dir.trim());
        if !dir.is_dir() {
            self.sky_log = "Choose the folder that holds the pieces.".into();
            return;
        }
        match gather_pieces(&dir) {
            Ok(bytes) => {
                let mut dlg = rfd::FileDialog::new().set_file_name("gathered.sg1");
                dlg = dlg.set_directory(&dir);
                if let Some(dest) = dlg.save_file() {
                    match std::fs::write(&dest, &bytes) {
                        Ok(()) => {
                            self.mark = dest.display().to_string();
                            self.sky_log = format!("Gathered → {}", dest.display());
                            self.set_status(true, self.sky_log.clone());
                            self.refresh_probe();
                        }
                        Err(e) => self.sky_log = format!("Write failed: {e}"),
                    }
                }
            }
            Err(e) => self.sky_log = format!("Gather failed: {e}"),
        }
    }
}

fn read_probe(path: &Path) -> Result<Probe, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let (h, merkle_ok, live, k, recovered) = verify(&data).map_err(|e| e.to_string())?;
    Ok(Probe {
        name: h.name.clone(),
        mode: h.mode(),
        live,
        n: h.n as usize,
        k,
        merkle_ok,
        recovered,
        orig: h.orig_len,
        true_name: hex32(&h.digest),
        envelope: hex32(&sha256(&data)),
    })
}

fn restore_name(mark: &Path, session_input: &str) -> String {
    let from_mark = suggested_output_name(mark);
    if session_input.is_empty() {
        return from_mark;
    }
    let inp = PathBuf::from(session_input);
    if mark != inp.with_extension("sg1").as_path() {
        return from_mark;
    }
    match inp.file_name().and_then(|s| s.to_str()) {
        Some(orig) if !orig.is_empty() && orig.len() >= from_mark.len() => orig.to_string(),
        _ => from_mark,
    }
}

fn punch(path: &Path, pct: u8) -> Result<u32, String> {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    let len = f.metadata().map_err(|e| e.to_string())?.len();
    if len < 8 {
        return Err("file too small".into());
    }
    let want = ((len as u128 * pct as u128) / 100).max(1) as u64;
    let hits = want.min(8192).max(1);
    let mut n = 0u32;
    for _ in 0..hits {
        let mut rb = [0u8; 8];
        getrandom::getrandom(&mut rb).map_err(|e| e.to_string())?;
        let off = u64::from_le_bytes(rb) % len;
        f.seek(SeekFrom::Start(off)).map_err(|e| e.to_string())?;
        f.write_all(&[0x00]).map_err(|e| e.to_string())?;
        n += 1;
    }
    Ok(n)
}

fn fmt_bytes(n: u64) -> String {
    const K: f64 = 1024.0;
    let x = n as f64;
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KiB", x / K)
    } else if n < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", x / (K * K))
    } else {
        format!("{:.2} GiB", x / (K * K * K))
    }
}

fn basename(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| path.to_string())
}

fn eyebrow(ui: &mut Ui, text: &str) {
    ui.label(
        RichText::new(text.to_uppercase())
            .color(MUTED)
            .size(11.0)
            .family(FontFamily::Monospace)
            .extra_letter_spacing(2.4),
    );
}

fn headline(ui: &mut Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .color(CREAM)
            .size(32.0)
            .family(serif_family()),
    );
}

fn muted(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).color(MUTED).size(13.5));
}

fn card(ui: &mut Ui, selected: bool, add: impl FnOnce(&mut Ui)) {
    Frame::new()
        .fill(if selected { SECONDARY } else { CARD })
        .stroke(stroke(if selected { GOLD } else { BORDER }))
        .corner_radius(12.0)
        .inner_margin(Margin::same(16))
        .show(ui, add);
}

fn dashed_card(ui: &mut Ui, add: impl FnOnce(&mut Ui)) -> egui::Response {
    Frame::new()
        .fill(CARD)
        .stroke(stroke(BORDER))
        .corner_radius(12.0)
        .inner_margin(Margin::same(20))
        .show(ui, add)
        .response
}

fn primary_btn(ui: &mut Ui, label: &str) -> egui::Response {
    ui.add_sized(
        [ui.available_width(), 44.0],
        egui::Button::new(RichText::new(label).color(BG).size(15.0).strong())
            .fill(GOLD)
            .stroke(Stroke::NONE)
            .corner_radius(8.0),
    )
}

fn secondary_btn(ui: &mut Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(label).color(CREAM).size(13.5))
            .fill(SECONDARY)
            .stroke(stroke(BORDER))
            .corner_radius(8.0)
            .min_size(Vec2::new(88.0, 36.0)),
    )
}

fn ghost_btn(ui: &mut Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(
            RichText::new(label)
                .color(MUTED)
                .size(12.0)
                .family(FontFamily::Monospace),
        )
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::NONE),
    )
}

fn field(ui: &mut Ui, value: &mut String, hint: &str, password: bool) {
    let mut te = TextEdit::singleline(value)
        .hint_text(RichText::new(hint).color(MUTED))
        .desired_width(f32::INFINITY)
        .background_color(SECONDARY);
    if password {
        te = te.password(true);
    }
    ui.add(te);
}

fn draw_mark(ui: &mut Ui, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let p = ui.painter();
    let c = rect.center();
    let r = size * 0.34;
    let s = Stroke::new(1.35_f32, CREAM);
    p.circle_stroke(c, r, s);
    p.line_segment(
        [
            egui::pos2(c.x, c.y - r * 0.72),
            egui::pos2(c.x, c.y + r * 0.72),
        ],
        s,
    );
    p.line_segment(
        [
            egui::pos2(c.x, c.y - r * 0.42),
            egui::pos2(c.x - r * 0.72, c.y - r * 0.95),
        ],
        s,
    );
    p.line_segment(
        [
            egui::pos2(c.x, c.y - r * 0.42),
            egui::pos2(c.x + r * 0.72, c.y - r * 0.95),
        ],
        s,
    );
    p.line_segment(
        [
            egui::pos2(c.x, c.y + r * 0.72),
            egui::pos2(c.x - r * 0.62, c.y + r * 1.18),
        ],
        s,
    );
    p.line_segment(
        [
            egui::pos2(c.x, c.y + r * 0.72),
            egui::pos2(c.x + r * 0.62, c.y + r * 1.18),
        ],
        s,
    );
}

fn mode_stripes(ui: &mut Ui, k: u8, n: u8, active: bool) {
    let n = n.max(1) as usize;
    let k = k as usize;
    let height = 8.0;
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), height), Sense::hover());
    let gap = 2.0;
    let w = ((rect.width() + gap) / n as f32) - gap;
    let p = ui.painter();
    for i in 0..n {
        let x = rect.left() + i as f32 * (w + gap);
        let r = egui::Rect::from_min_size(egui::pos2(x, rect.top()), Vec2::new(w.max(1.5), height));
        if i < k {
            p.rect_filled(
                r,
                2.0,
                if active {
                    CREAM
                } else {
                    CREAM.gamma_multiply(0.45)
                },
            );
        } else {
            p.rect_stroke(
                r,
                2.0,
                Stroke::new(1.0_f32, if active { GOLD } else { BORDER }),
                egui::StrokeKind::Inside,
            );
        }
    }
}

impl eframe::App for Lab {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("hdr")
            .exact_height(HEADER_H)
            .frame(
                Frame::new()
                    .fill(BG)
                    .inner_margin(Margin::symmetric(20, 0))
                    .stroke(Stroke::new(0.0_f32, BG)),
            )
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    draw_mark(ui, 28.0);
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("Sigil")
                            .color(CREAM)
                            .size(18.0)
                            .family(serif_family()),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        for (page, label) in [
                            (Page::Grimoire, "Grimoire"),
                            (Page::Sky, "Sky"),
                            (Page::Scry, "Scry"),
                            (Page::Lab, "Lab"),
                        ] {
                            let active = self.page == page;
                            let txt = RichText::new(label).size(14.0).color(if active {
                                CREAM
                            } else {
                                MUTED
                            });
                            if ui
                                .add(
                                    egui::Button::new(txt)
                                        .fill(Color32::TRANSPARENT)
                                        .stroke(Stroke::NONE),
                                )
                                .clicked()
                            {
                                self.page = page;
                            }
                        }
                    });
                });
            });

        egui::TopBottomPanel::top("hdr_line")
            .exact_height(1.0)
            .frame(Frame::new().fill(BORDER))
            .show(ctx, |_| {});

        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(BG)
                    .inner_margin(Margin::symmetric(28, 20)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| match self.page {
                        Page::Lab => self.ui_lab(ui),
                        Page::Scry => self.ui_scry(ui),
                        Page::Sky => self.ui_sky(ui),
                        Page::Grimoire => self.ui_grimoire(ui),
                    });
            });
    }
}

impl Lab {
    fn ui_lab(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.set_max_width(ui.available_width() - 280.0);
                eyebrow(ui, "Lab");
                ui.add_space(4.0);
                headline(ui, "Turn a file into a mark you can copy.");
                ui.add_space(6.0);
                muted(
                    ui,
                    "Inscribe makes a .sg1 file. De-scribe unpacks the original. To look at a mark without unpacking it, use Scry.",
                );
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Max), |ui| {
                self.lab_tabs(ui);
            });
        });
        ui.add_space(18.0);
        self.status_line(ui);
        match self.tab {
            LabTab::Inscribe => self.ui_inscribe(ui),
            LabTab::Describe => self.ui_describe(ui),
        }
    }

    fn lab_tabs(&mut self, ui: &mut Ui) {
        Frame::new()
            .fill(SECONDARY)
            .stroke(stroke(BORDER))
            .corner_radius(8.0)
            .inner_margin(Margin::same(4))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    for (tab, label) in [
                        (LabTab::Inscribe, "Inscribe"),
                        (LabTab::Describe, "De-scribe"),
                    ] {
                        let on = self.tab == tab;
                        let txt = RichText::new(label)
                            .size(14.0)
                            .color(if on { BG } else { MUTED })
                            .strong();
                        if ui
                            .add(
                                egui::Button::new(txt)
                                    .fill(if on { GOLD } else { Color32::TRANSPARENT })
                                    .stroke(Stroke::NONE)
                                    .corner_radius(6.0)
                                    .min_size(Vec2::new(108.0, 36.0)),
                            )
                            .clicked()
                        {
                            self.tab = tab;
                        }
                    }
                });
            });
    }

    fn status_line(&mut self, ui: &mut Ui) {
        if self.status.is_empty() {
            return;
        }
        let color = if self.status_ok { OK } else { BAD };
        Frame::new()
            .fill(if self.status_ok {
                Color32::from_rgba_unmultiplied(93, 138, 106, 28)
            } else {
                Color32::from_rgba_unmultiplied(180, 90, 74, 28)
            })
            .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.45)))
            .corner_radius(8.0)
            .inner_margin(Margin::symmetric(12, 8))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(&self.status)
                        .color(if self.status_ok {
                            CREAM
                        } else {
                            Color32::from_rgb(232, 200, 190)
                        })
                        .size(13.0)
                        .family(FontFamily::Monospace),
                );
            });
        ui.add_space(8.0);
    }

    fn ui_inscribe(&mut self, ui: &mut Ui) {
        let w = ui.available_width();
        ui.columns(2, |cols| {
            cols[0].set_min_width((w * 0.46).max(320.0));
            self.ui_inscribe_left(&mut cols[0]);
            self.ui_inscribe_right(&mut cols[1]);
        });
    }

    fn ui_inscribe_left(&mut self, ui: &mut Ui) {
        card(ui, false, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Your file").color(CREAM).size(13.5));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ghost_btn(ui, "OR PICK A FILE").clicked() {
                        self.pick_in();
                    }
                });
            });
            ui.add_space(8.0);
            if self.input.trim().is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space(18.0);
                    ui.label(RichText::new("No file yet").color(MUTED).size(13.0));
                    ui.add_space(4.0);
                    muted(ui, "Pick a file. Inscribe writes a .sg1 next to it.");
                    ui.add_space(12.0);
                    if secondary_btn(ui, "Browse").clicked() {
                        self.pick_in();
                    }
                    ui.add_space(10.0);
                });
            } else {
                Frame::new()
                    .fill(SECONDARY)
                    .stroke(stroke(BORDER))
                    .corner_radius(8.0)
                    .inner_margin(Margin::symmetric(12, 10))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label(
                                    RichText::new(basename(&self.input)).color(CREAM).size(14.5),
                                );
                                ui.label(
                                    RichText::new(fmt_bytes(self.input_len))
                                        .color(MUTED)
                                        .size(12.0)
                                        .family(FontFamily::Monospace),
                                );
                            });
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ghost_btn(ui, "CHANGE").clicked() {
                                        self.pick_in();
                                    }
                                },
                            );
                        });
                    });
            }
        });
        ui.add_space(12.0);

        ui.label(
            RichText::new("Kind")
                .color(MUTED)
                .size(11.0)
                .family(FontFamily::Monospace)
                .extra_letter_spacing(1.4),
        );
        let mut picked = self.mode;
        for spec in &MODES {
            let selected = spec.mode == self.mode;
            let resp = Frame::new()
                .fill(if selected { SECONDARY } else { CARD })
                .stroke(stroke(if selected { GOLD } else { BORDER }))
                .corner_radius(10.0)
                .inner_margin(Margin::same(12))
                .show(ui, |ui| {
                    mode_stripes(ui, spec.k, spec.n, selected);
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(spec.label)
                                .color(CREAM)
                                .size(18.0)
                                .family(serif_family()),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                RichText::new(format!("{} · {}", spec.loss, spec.cost))
                                    .color(MUTED)
                                    .size(11.0)
                                    .family(FontFamily::Monospace),
                            );
                        });
                    });
                    ui.label(
                        RichText::new(format!("{} · {}", spec.metaphor, spec.layout))
                            .color(MUTED)
                            .size(11.0)
                            .family(FontFamily::Monospace),
                    );
                    ui.add_space(4.0);
                    ui.label(RichText::new(spec.blurb).color(MUTED).size(13.0));
                })
                .response
                .interact(Sense::click());
            if resp.clicked() {
                picked = spec.mode;
            }
            ui.add_space(6.0);
        }
        if picked != self.mode {
            self.mode = picked;
            self.hex_pct = match picked {
                Mode::Glyph => 6,
                Mode::Reflection => 25,
                Mode::Seal => 50,
            };
        }

        card(ui, false, |ui| {
            ui.label(
                RichText::new("Ward — optional password")
                    .color(CREAM)
                    .size(13.5),
            );
            ui.add_space(6.0);
            field(
                ui,
                &mut self.ward,
                "Leave blank if you do not want a password",
                true,
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "This is the only real lock. If you leave it blank, the file is scrambled so it does not look like itself, but anyone with Sigil can still open it.",
                )
                .color(MUTED)
                .size(12.0),
            );
        });
        ui.add_space(10.0);

        egui::CollapsingHeader::new(
            RichText::new("Covenant and Geas (optional)")
                .color(MUTED)
                .size(13.0),
        )
        .show(ui, |ui| {
            ui.add_space(6.0);
            ui.label(
                RichText::new("Covenant — a note, not a lock")
                    .color(CREAM)
                    .size(13.0),
            );
            field(
                ui,
                &mut self.covenant,
                "e.g. app=game-save;class=private",
                false,
            );
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Geas — bind companion files")
                        .color(CREAM)
                        .size(13.0),
                );
                if secondary_btn(ui, "Bind file").clicked() {
                    self.pick_geas();
                }
            });
            if self.geas.is_empty() {
                muted(
                    ui,
                    "De-scribe will refuse unless those exact files are present. Up to two.",
                );
            } else {
                let names: Vec<String> = self
                    .geas
                    .iter()
                    .map(|p| basename(&p.display().to_string()))
                    .collect();
                ui.label(
                    RichText::new(format!("Bound: {}", names.join(", ")))
                        .color(CREAM)
                        .size(12.5),
                );
                if ghost_btn(ui, "CLEAR").clicked() {
                    self.geas.clear();
                }
            }
        });
        ui.add_space(14.0);

        let label = format!("Inscribe a {}", mode_copy(self.mode).label);
        if primary_btn(ui, &label).clicked() {
            self.inscribe();
        }
        ui.add_space(20.0);
    }

    fn ui_inscribe_right(&mut self, ui: &mut Ui) {
        if self.probe.is_none() && self.mark.trim().is_empty() {
            dashed_card(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(48.0);
                    ui.label(
                        RichText::new("Nothing inscribed yet")
                            .color(CREAM)
                            .size(24.0)
                            .family(serif_family()),
                    );
                    ui.add_space(8.0);
                    ui.set_max_width(360.0);
                    ui.label(
                        RichText::new(
                            "Pick a file on the left. Choose Glyph, Reflection, or Seal. Then press Inscribe. After that you can Hex (damage) pieces on purpose and try De-scribe.",
                        )
                        .color(MUTED)
                        .size(13.5),
                    );
                    ui.add_space(48.0);
                });
            });
            return;
        }

        if let Some(pr) = self.probe.clone() {
            let spec = mode_copy(pr.mode);
            let mut scry = false;
            let mut describe = false;
            card(ui, false, |ui| {
                ui.label(
                    RichText::new(format!("Your mark · {}", spec.metaphor))
                        .color(MUTED)
                        .size(11.0)
                        .family(FontFamily::Monospace)
                        .extra_letter_spacing(1.2),
                );
                ui.label(
                    RichText::new(spec.label)
                        .color(CREAM)
                        .size(26.0)
                        .family(serif_family()),
                );
                ui.label(RichText::new(spec.layout).color(MUTED).size(12.0));
                ui.add_space(10.0);
                ui.columns(2, |c| {
                    kv(&mut c[0], "Original", &fmt_bytes(pr.orig));
                    kv(
                        &mut c[1],
                        "Good pieces",
                        &format!("{}/{} · need {}", pr.live, pr.n, pr.k),
                    );
                    kv(
                        &mut c[0],
                        "Binding",
                        if pr.merkle_ok {
                            "OK — pieces match"
                        } else {
                            "open — damage or unread"
                        },
                    );
                    kv(
                        &mut c[1],
                        "Map",
                        if pr.recovered { "recovered" } else { "intact" },
                    );
                });
                ui.add_space(6.0);
                ui.label(
                    RichText::new(format!(
                        "name  {}",
                        if pr.name.is_empty() { "—" } else { &pr.name }
                    ))
                    .color(MUTED)
                    .size(11.5)
                    .family(FontFamily::Monospace),
                );
                ui.label(
                    RichText::new(format!("true name  {}", pr.true_name))
                        .color(MUTED)
                        .size(11.0)
                        .family(FontFamily::Monospace),
                );
                ui.add_space(4.0);
                muted(
                    ui,
                    "True name = fingerprint of your original file. Binding = check of the 16 pieces. Keystone = spare copies of the header. Ember = a copy of the map inside every piece.",
                );
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if secondary_btn(ui, "Scry without opening").clicked() {
                        scry = true;
                    }
                    if secondary_btn(ui, "De-scribe this mark").clicked() {
                        describe = true;
                    }
                });
            });
            if scry {
                self.scry_current();
            }
            if describe {
                self.describe();
            }
            ui.add_space(12.0);
        }

        let mut do_hex = false;
        let mut do_describe = false;
        card(ui, false, |ui| {
            ui.label(
                RichText::new("The 16 pieces — Hex damages the mark on purpose")
                    .color(MUTED)
                    .size(11.0)
                    .family(FontFamily::Monospace)
                    .extra_letter_spacing(1.0),
            );
            ui.add_space(4.0);
            let spec = mode_copy(self.mode);
            ui.label(
                RichText::new(format!(
                    "{} needs {} good pieces and has {} spares. Hex writes random holes into the .sg1, then De-scribe tries to get the original back.",
                    spec.label,
                    spec.k,
                    spec.n - spec.k
                ))
                .color(MUTED)
                .size(12.5),
            );
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("How much to damage (Hex)")
                        .color(CREAM)
                        .size(13.0),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!("{}%", self.hex_pct))
                            .color(MUTED)
                            .size(12.0)
                            .family(FontFamily::Monospace),
                    );
                });
            });
            ui.add(egui::Slider::new(&mut self.hex_pct, 0..=70).show_value(false));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if secondary_btn(ui, "Hex").clicked() {
                    do_hex = true;
                }
                if primary_btn_inline(ui, "De-scribe") {
                    do_describe = true;
                }
            });
        });
        if do_hex {
            self.hex();
        }
        if do_describe {
            self.describe();
        }
    }

    fn ui_describe(&mut self, ui: &mut Ui) {
        ui.set_max_width(560.0);
        let drop = dashed_card(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(28.0);
                ui.label(
                    RichText::new("Drop a .sg1 file here")
                        .color(CREAM)
                        .size(24.0)
                        .family(serif_family()),
                );
                ui.add_space(4.0);
                muted(
                    ui,
                    "Scry runs as soon as it lands. Then you can De-scribe to unpack it.",
                );
                if !self.mark.trim().is_empty() {
                    ui.add_space(10.0);
                    let extra = self
                        .probe
                        .as_ref()
                        .map(|p| format!(" · {}", mode_copy(p.mode).label))
                        .unwrap_or_default();
                    ui.label(
                        RichText::new(format!("{}{extra}", basename(&self.mark)))
                            .color(CREAM)
                            .size(12.5)
                            .family(FontFamily::Monospace),
                    );
                }
                ui.add_space(12.0);
                if secondary_btn(ui, "Browse").clicked() {
                    self.pick_mark();
                }
                ui.add_space(20.0);
            });
        });
        if drop.clicked() {
            self.pick_mark();
        }

        ui.add_space(14.0);
        ui.label(
            RichText::new("Password (Ward), if you set one")
                .color(CREAM)
                .size(13.5),
        );
        field(ui, &mut self.ward, "", true);

        if !self.companions.is_empty() || !self.geas.is_empty() {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Geas — companion files this mark requires")
                        .color(CREAM)
                        .size(13.0),
                );
                if secondary_btn(ui, "Attach").clicked() {
                    self.pick_companions();
                }
            });
            if !self.companions.is_empty() {
                let names: Vec<String> = self
                    .companions
                    .iter()
                    .map(|p| basename(&p.display().to_string()))
                    .collect();
                muted(ui, &format!("Attached: {}", names.join(", ")));
            }
        }

        ui.add_space(14.0);
        let can = PathBuf::from(self.mark.trim()).is_file();
        let mut do_describe = false;
        let mut do_scry = false;
        ui.add_enabled_ui(can, |ui| {
            if primary_btn(ui, "De-scribe").clicked() {
                do_describe = true;
            }
            ui.add_space(8.0);
            if secondary_btn(ui, "Scry without opening").clicked() {
                do_scry = true;
            }
        });
        if do_describe {
            self.describe();
        }
        if do_scry {
            self.scry_current();
        }

        if let Some(pr) = self.probe.clone() {
            ui.add_space(16.0);
            self.probe_card(ui, &pr);
        }

        if !self.described_to.is_empty() {
            ui.add_space(12.0);
            Frame::new()
                .fill(Color32::from_rgba_unmultiplied(93, 138, 106, 28))
                .stroke(Stroke::new(1.0_f32, OK.gamma_multiply(0.4)))
                .corner_radius(12.0)
                .inner_margin(Margin::same(16))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new("De-scribed")
                            .color(OK)
                            .size(11.0)
                            .family(FontFamily::Monospace)
                            .extra_letter_spacing(1.4),
                    );
                    ui.label(
                        RichText::new(basename(&self.described_to))
                            .color(CREAM)
                            .size(22.0)
                            .family(serif_family()),
                    );
                    muted(ui, &self.described_to);
                });
        }
        ui.add_space(24.0);
    }

    fn ui_scry(&mut self, ui: &mut Ui) {
        ui.set_max_width(640.0);
        eyebrow(ui, "Scry");
        ui.add_space(4.0);
        headline(ui, "Look at a mark without opening it.");
        ui.add_space(8.0);
        muted(
            ui,
            "Drop a .sg1 here. Scry tells you if it is still the same file. The original stays packed. If you wrote down a true name earlier, paste it below to compare.",
        );
        ui.add_space(16.0);
        ui.label(
            RichText::new("True name or envelope hash you wrote down (optional)")
                .color(CREAM)
                .size(13.0),
        );
        field(
            ui,
            &mut self.scry_expected,
            "true name or envelope hash",
            false,
        );
        ui.add_space(12.0);

        let drop = dashed_card(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(36.0);
                ui.label(
                    RichText::new("Drop a .sg1 file")
                        .color(CREAM)
                        .size(24.0)
                        .family(serif_family()),
                );
                muted(ui, "click to browse");
                if !self.mark.trim().is_empty() {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(basename(&self.mark))
                            .color(CREAM)
                            .size(12.5)
                            .family(FontFamily::Monospace),
                    );
                }
                ui.add_space(12.0);
                if secondary_btn(ui, "Browse").clicked() {
                    self.pick_mark();
                }
                ui.add_space(28.0);
            });
        });
        if drop.clicked() {
            self.pick_mark();
        }

        self.status_line(ui);

        if let Some(pr) = self.probe.clone() {
            ui.add_space(16.0);
            let want = self
                .scry_expected
                .replace(|c: char| !c.is_ascii_hexdigit(), "");
            let verdict = scry_verdict(&pr, &want);
            self.verdict_card(ui, verdict, &pr);
        }
        ui.add_space(24.0);
    }

    fn ui_sky(&mut self, ui: &mut Ui) {
        ui.set_max_width(720.0);
        eyebrow(ui, "Sky");
        ui.add_space(4.0);
        headline(ui, "Scatter a mark. Gather it back.");
        ui.add_space(8.0);
        muted(
            ui,
            "Scatter splits one mark into piece files you can send on different paths. Any k pieces are enough. Gather puts them back into one .sg1. A constellation is different: it is a named list of stars (whole marked files), not the pieces of one file.",
        );
        ui.add_space(16.0);
        self.status_line(ui);

        let mut do_scatter = false;
        let mut do_gather = false;
        card(ui, false, |ui| {
            ui.label(RichText::new("Mark").color(CREAM).size(13.5));
            ui.horizontal(|ui| {
                ui.add(
                    TextEdit::singleline(&mut self.mark)
                        .desired_width(f32::INFINITY)
                        .hint_text(RichText::new(".sg1 path").color(MUTED)),
                );
                if secondary_btn(ui, "Browse").clicked() {
                    self.pick_mark();
                }
            });
            ui.add_space(8.0);
            ui.label(RichText::new("Folder for pieces").color(CREAM).size(13.5));
            ui.horizontal(|ui| {
                ui.add(
                    TextEdit::singleline(&mut self.sky_dir)
                        .desired_width(f32::INFINITY)
                        .hint_text(RichText::new("empty folder").color(MUTED)),
                );
                if secondary_btn(ui, "Folder").clicked() {
                    self.pick_folder();
                }
            });
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if primary_btn_inline(ui, "Scatter") {
                    do_scatter = true;
                }
                if secondary_btn(ui, "Gather").clicked() {
                    do_gather = true;
                }
            });
            if !self.sky_log.is_empty() {
                ui.add_space(10.0);
                ui.label(
                    RichText::new(&self.sky_log)
                        .color(CREAM)
                        .size(13.0)
                        .family(FontFamily::Monospace),
                );
            }
        });
        if do_scatter {
            self.scatter();
        }
        if do_gather {
            self.gather();
        }
        ui.add_space(12.0);
        muted(
            ui,
            "Rain (extra pieces of one star) is the terminal:  sigil deluge  and  sigil gather. A constellation of many files:  sigil constellation add ./Taxes ./file.",
        );
    }

    fn ui_grimoire(&mut self, ui: &mut Ui) {
        ui.set_max_width(720.0);
        eyebrow(ui, "Grimoire");
        ui.add_space(4.0);
        headline(ui, "The same words as the lab.");
        ui.add_space(10.0);
        muted(
            ui,
            "This window is the same engine as the terminal command. The published lab in the browser is a size-capped demonstration. Here, files are not capped.",
        );
        ui.add_space(18.0);

        for (title, body) in [
            (
                "Inscribe / De-scribe / Scry",
                "Encode, decode, and inspect without decoding. Inscribe writes a .sg1 next to your file. De-scribe puts the original name back.",
            ),
            (
                "Glyph",
                "k = n = 16. Content identity only. No repair. Smallest mark. If any piece is damaged, it stops.",
            ),
            (
                "Reflection",
                "k = 12, n = 16. Recovers from up to 4 of 16 piece failures (~25%). Default. About 1.3× the original.",
            ),
            (
                "Seal",
                "k = 8, n = 16. Recovers from up to 8 of 16 piece failures (~50%). About twice the size. Use when this is the only copy that matters.",
            ),
            (
                "Ward",
                "Optional password. The only real lock. Blank means scrambled, not secret — anyone with Sigil can still open it.",
            ),
            (
                "Covenant / Geas",
                "A Covenant is a short note on the mark, not a lock. A Geas binds companion files: De-scribe refuses if they are missing or changed.",
            ),
            (
                "Keystone / Ember",
                "Keystone = spare copies of the header at the front. Ember = a copy of the map inside every piece, so a smashed header can still open.",
            ),
            (
                "Hex",
                "Writes holes into a mark on purpose so you can watch Reflection or Seal rebuild the original. Not something you do to a file you care about keeping damaged.",
            ),
            (
                "Boot disk",
                "A live USB whose filesystem.squashfs is a Seal. Firmware still boots GRUB + kernel + initrd. Initrd Scrys, De-scribes if the image was chewed, and stops if it is too damaged. Terminal: sigil boot prepare <usb>  ·  sigil boot mend <usb>.",
            ),
            (
                "Star / constellation / atlas",
                "A star is one .sg1. A constellation is a named list of stars, a folder on disk: the card plus one star per unique true name. Adding a file you already have only updates the list. An atlas (.sga) is the bag so they cannot scatter. De-scribe refuses if a named star is missing. Terminal: sigil constellation add ./Taxes ./file  ·  sigil constellation atlas ./Taxes.",
            ),
        ] {
            card(ui, false, |ui| {
                ui.label(
                    RichText::new(title)
                        .color(CREAM)
                        .size(20.0)
                        .family(serif_family()),
                );
                ui.add_space(4.0);
                ui.label(RichText::new(body).color(MUTED).size(13.5));
            });
            ui.add_space(8.0);
        }
        ui.add_space(12.0);
        muted(ui, "Terminal, same machine:  sigil inscribe -o out.sg1 file   ·   sigil scry out.sg1   ·   sigil de-scribe -o file out.sg1");
        ui.add_space(24.0);
    }

    fn probe_card(&self, ui: &mut Ui, pr: &Probe) {
        let spec = mode_copy(pr.mode);
        card(ui, false, |ui| {
            ui.columns(2, |c| {
                kv(&mut c[0], "Type", spec.label);
                kv(
                    &mut c[1],
                    "Good pieces",
                    &format!("{}/{} · need {}", pr.live, pr.n, pr.k),
                );
                kv(
                    &mut c[0],
                    "Binding",
                    if pr.merkle_ok {
                        "OK — pieces match"
                    } else {
                        "not OK — damage or unread"
                    },
                );
                kv(
                    &mut c[1],
                    "Spares",
                    if pr.live >= pr.k {
                        "enough left to repair"
                    } else {
                        "not enough left to repair"
                    },
                );
            });
            ui.add_space(6.0);
            ui.label(
                RichText::new(format!("true name  {}", pr.true_name))
                    .color(MUTED)
                    .size(11.0)
                    .family(FontFamily::Monospace),
            );
        });
    }

    fn verdict_card(&self, ui: &mut Ui, verdict: Verdict, pr: &Probe) {
        let (title, blurb, ok) = match verdict {
            Verdict::Itself => (
                "Unchanged.",
                "This is still the same file. Nothing was unpacked.",
                true,
            ),
            Verdict::Recovered => (
                "Header was damaged. A spare map held.",
                "The front of the file was smashed. A Keystone or Ember copy of the map was used. The original file is still the same.",
                true,
            ),
            Verdict::Mendable => (
                "Damaged, but can be repaired.",
                "Some pieces are missing. Reflection or Seal can still rebuild it. Use De-scribe in the lab to unpack.",
                true,
            ),
            Verdict::Lost => (
                "Too damaged.",
                "Too many pieces are gone. Sigil will not guess the rest.",
                false,
            ),
            Verdict::Mismatch => (
                "Not the true name you pasted.",
                "This is a valid mark, but it is not the file you thought. Treat it as a different file.",
                false,
            ),
        };
        let stroke_c = if ok {
            OK.gamma_multiply(0.45)
        } else {
            BAD.gamma_multiply(0.5)
        };
        let fill = if ok {
            Color32::from_rgba_unmultiplied(93, 138, 106, 24)
        } else {
            Color32::from_rgba_unmultiplied(180, 90, 74, 24)
        };
        Frame::new()
            .fill(fill)
            .stroke(Stroke::new(1.0_f32, stroke_c))
            .corner_radius(12.0)
            .inner_margin(Margin::same(20))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(title)
                        .color(CREAM)
                        .size(28.0)
                        .family(serif_family()),
                );
                ui.add_space(6.0);
                ui.label(RichText::new(blurb).color(MUTED).size(13.5));
                ui.add_space(14.0);
                self.probe_card(ui, pr);
                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!("envelope  {}", pr.envelope))
                        .color(MUTED)
                        .size(11.0)
                        .family(FontFamily::Monospace),
                );
            });
    }
}

fn kv(ui: &mut Ui, k: &str, v: &str) {
    ui.label(RichText::new(k).color(MUTED).size(12.5));
    ui.label(
        RichText::new(v)
            .color(CREAM)
            .size(15.0)
            .family(serif_family()),
    );
    ui.add_space(6.0);
}

fn primary_btn_inline(ui: &mut Ui, label: &str) -> bool {
    ui.add(
        egui::Button::new(RichText::new(label).color(BG).size(14.0).strong())
            .fill(GOLD)
            .stroke(Stroke::NONE)
            .corner_radius(8.0)
            .min_size(Vec2::new(120.0, 36.0)),
    )
    .clicked()
}

#[derive(Clone, Copy)]
enum Verdict {
    Itself,
    Recovered,
    Mendable,
    Lost,
    Mismatch,
}

fn scry_verdict(pr: &Probe, want: &str) -> Verdict {
    if !want.is_empty() {
        let a = pr.true_name.to_lowercase();
        let b = pr.envelope.to_lowercase();
        let w = want.to_lowercase();
        if w != a && w != b && !a.starts_with(&w) && !b.starts_with(&w) {
            return Verdict::Mismatch;
        }
    }
    if pr.merkle_ok && pr.live == pr.n {
        if pr.recovered {
            Verdict::Recovered
        } else {
            Verdict::Itself
        }
    } else if pr.live >= pr.k {
        Verdict::Mendable
    } else {
        Verdict::Lost
    }
}
