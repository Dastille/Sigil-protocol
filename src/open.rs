//! Open: De-scribe to temp, launch the usual app, delete when you say you're done.

use crate::{is_dir_pack, payload_name, unseal_dir_only, unseal_path, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn run_open(
    mark: &Path,
    pass: Option<&str>,
    wards: &[(String, String)],
    only: &[String],
    keep: bool,
) -> Result<()> {
    let tmp = std::env::temp_dir().join(format!("sigil-open-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let target = if is_dir_pack(mark) {
        unseal_dir_only(mark, &tmp, pass, &[], only, wards)?;
        if only.is_empty() {
            tmp.clone()
        } else {
            first_file(&tmp).ok_or_else(|| crate::Error::Msg("nothing extracted".into()))?
        }
    } else {
        let name = payload_name(mark)?;
        let dest = tmp.join(name);
        unseal_path(mark, &dest, pass, &[])?;
        dest
    };
    println!("opened {}", target.display());
    launch(&target)?;
    if keep {
        println!("left in place: {}", target.display());
        return Ok(());
    }
    println!("Press Enter when you're done looking — then this copy is deleted.");
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    let _ = fs::remove_dir_all(&tmp);
    println!("temp copy gone. The .sg1 is unchanged.");
    Ok(())
}

fn first_file(root: &Path) -> Option<PathBuf> {
    fn walk(p: &Path, out: &mut Option<PathBuf>) {
        if out.is_some() {
            return;
        }
        if p.is_file() {
            *out = Some(p.to_path_buf());
            return;
        }
        if let Ok(rd) = fs::read_dir(p) {
            for e in rd.flatten() {
                walk(&e.path(), out);
            }
        }
    }
    let mut o = None;
    walk(root, &mut o);
    o
}

fn launch(path: &Path) -> Result<()> {
    let r = if cfg!(windows) {
        Command::new("cmd").args(["/C", "start", ""]).arg(path).status()
    } else if cfg!(target_os = "macos") {
        Command::new("open").arg(path).status()
    } else {
        Command::new("xdg-open").arg(path).status()
    };
    match r {
        Ok(s) if s.success() => Ok(()),
        Ok(_) => {
            println!("no viewer hooked — file is {}", path.display());
            Ok(())
        }
        Err(_) => {
            println!("no viewer hooked — file is {}", path.display());
            Ok(())
        }
    }
}
