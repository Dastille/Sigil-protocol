use anyhow::Result;
pub fn run(input: &str, archive: &str, output: &str) -> Result<()> { println!("Embedding {} into {} as {}", archive, input, output); Ok(()) }