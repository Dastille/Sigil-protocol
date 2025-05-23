use anyhow::Result;
pub fn run(archive: &str, output: &str) -> Result<()> { println!("Recovering {} to {}", archive, output); Ok(()) }