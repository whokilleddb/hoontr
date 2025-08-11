#[derive(Clone, Copy, Debug,PartialEq, Eq)]
pub enum ARCH {
    X64,
    X86,
    All,
}

impl std::str::FromStr for ARCH {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input.to_lowercase().as_str() {
            "x64" => Ok(ARCH::X64),
            "x86" => Ok(ARCH::X86),
            "all" => Ok(ARCH::All),
            _ => Err(format!("Invalid arch: {}", input)),
        }
    }
}