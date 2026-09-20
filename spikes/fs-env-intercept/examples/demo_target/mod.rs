//! The "application under test". It knows nothing about the sandbox: it reads its environment,
//! a config file, `/dev/urandom`, `getrandom`, a state directory, its pid and `uname`, exactly as a
//! small daemon would.
//!
//! Injected bug: in strict mode (file *and* environment) the retry budget is mixed with the first
//! nonce byte and used as a table index; `retries as u8 == nonce[0]` makes the index wrap.

use std::fs::File;
use std::io::Read;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Config {
    pub mode: String,
    pub retries: u32,
    pub name: String,
    pub seed: u64,
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut config = Config {
            mode: "lenient".to_string(),
            retries: 3,
            ..Config::default()
        };
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(format!("line {}: expected key=value", number + 1));
            };
            match key.trim() {
                "mode" => config.mode = value.trim().to_string(),
                "retries" => {
                    config.retries = value
                        .trim()
                        .parse()
                        .map_err(|e| format!("line {}: retries: {e}", number + 1))?
                }
                "name" => config.name = value.trim().to_string(),
                "seed" => {
                    config.seed = value
                        .trim()
                        .parse()
                        .map_err(|e| format!("line {}: seed: {e}", number + 1))?
                }
                other => return Err(format!("line {}: unknown key {other:?}", number + 1)),
            }
        }
        Ok(config)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub config: Config,
    pub env_mode: String,
    pub nonce: [u8; 8],
    pub key: [u8; 16],
    pub state_entries: Vec<String>,
    pub pid: u32,
    pub release: String,
    pub retry_slot: u8,
}

pub fn run() -> Result<Summary, String> {
    let env_mode = std::env::var("APP_MODE").unwrap_or_else(|_| "lenient".to_string());

    let text = std::fs::read_to_string("/etc/app/app.conf").map_err(|e| format!("config: {e}"))?;
    let config = Config::parse(&text)?;

    let mut nonce = [0u8; 8];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut nonce))
        .map_err(|e| format!("urandom: {e}"))?;

    let mut key = [0u8; 16];
    // SAFETY: valid buffer of the given length.
    let n = unsafe { libc::getrandom(key.as_mut_ptr().cast(), key.len(), 0) };
    if n != key.len() as isize {
        return Err(format!("getrandom: {}", std::io::Error::last_os_error()));
    }

    let mut state_entries: Vec<String> = match std::fs::read_dir("/var/lib/app") {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => Vec::new(),
    };
    state_entries.sort();

    let pid = std::process::id();
    // SAFETY: utsname is plain old data.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: valid pointer.
    unsafe { libc::uname(&mut uts) };
    let release = uts
        .release
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8 as char)
        .collect::<String>();

    let retry_slot = if config.mode == "strict" && env_mode == "strict" {
        let table: [u8; 256] = std::array::from_fn(|i| i as u8);
        let budget = (config.retries & 0xff) as u8;
        // BUG: `budget - nonce[0] - 1` wraps to 255 when budget == nonce[0]; the `+ 1` below
        // then indexes one past the end.
        let index = budget.wrapping_sub(nonce[0]).wrapping_sub(1);
        table[usize::from(index) + 1]
    } else {
        0
    };

    Ok(Summary {
        config,
        env_mode,
        nonce,
        key,
        state_entries,
        pid,
        release,
        retry_slot,
    })
}
