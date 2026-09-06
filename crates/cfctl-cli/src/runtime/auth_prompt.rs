//! Hidden input for the public API-token import command.

use super::prelude::{CliError, Result};

#[cfg(unix)]
pub(super) fn read_api_token_prompt() -> Result<String> {
    use std::fs::OpenOptions;
    use std::io::Write;

    use rustix::termios::{LocalModes, OptionalActions, SpecialCodeIndex, tcgetattr, tcsetattr};

    let mut terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| CliError::Input(
            "--prompt requires a controlling terminal; use --stdin or a protected --value-in file in a noninteractive session".to_owned(),
        ))?;
    let original = tcgetattr(&terminal).map_err(prompt_error)?;
    let mut hidden = original.clone();
    hidden
        .local_modes
        .remove(LocalModes::ECHO | LocalModes::ECHONL | LocalModes::ICANON | LocalModes::ISIG);
    hidden.special_codes[SpecialCodeIndex::VMIN] = 1;
    hidden.special_codes[SpecialCodeIndex::VTIME] = 0;
    let guard = TerminalRestore {
        terminal: terminal.try_clone().map_err(prompt_error)?,
        original,
    };
    tcsetattr(&terminal, OptionalActions::Flush, &hidden).map_err(prompt_error)?;
    terminal
        .write_all(b"API token (hidden; Ctrl-C cancels): ")
        .map_err(prompt_error)?;
    terminal.flush().map_err(prompt_error)?;
    let value = read_hidden_value(&mut terminal);
    // Restore before returning the value, including cancellation and read errors.
    tcsetattr(&guard.terminal, OptionalActions::Flush, &guard.original).map_err(prompt_error)?;
    terminal.write_all(b"\n").map_err(prompt_error)?;
    value.map_err(prompt_error)
}

#[cfg(not(unix))]
pub(super) fn read_api_token_prompt() -> Result<String> {
    Err(CliError::Input(
        "--prompt is unavailable on this platform; use --stdin or a protected --value-in file"
            .to_owned(),
    ))
}

#[cfg(unix)]
struct TerminalRestore {
    terminal: std::fs::File,
    original: rustix::termios::Termios,
}

#[cfg(unix)]
impl Drop for TerminalRestore {
    fn drop(&mut self) {
        let _restored = rustix::termios::tcsetattr(
            &self.terminal,
            rustix::termios::OptionalActions::Flush,
            &self.original,
        );
    }
}

#[cfg(unix)]
fn prompt_error(error: impl std::fmt::Display) -> CliError {
    CliError::Input(format!("hidden API-token input failed: {error}"))
}

#[cfg(unix)]
fn read_hidden_value(reader: &mut impl std::io::Read) -> std::io::Result<String> {
    let mut value = Vec::new();
    loop {
        let mut byte = [0_u8];
        reader.read_exact(&mut byte)?;
        match byte[0] {
            b'\r' | b'\n' => break,
            3 | 4 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled; no token was imported",
                ));
            }
            8 | 127 => {
                value.pop();
            }
            0x21..=0x7e if value.len() < 4096 => value.push(byte[0]),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "expected one bounded ASCII token without spaces or control characters",
                ));
            }
        }
    }
    String::from_utf8(value).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid token encoding")
    })
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(clippy::expect_used)]
    use super::read_hidden_value;

    #[test]
    fn hidden_input_supports_backspace_and_rejects_cancel_or_control_data() {
        assert_eq!(
            read_hidden_value(&mut b"cfut_abx\x7fc\n".as_slice()).expect("token"),
            "cfut_abc"
        );
        for input in [
            b"cfut_private\x03".as_slice(),
            b"cfut_private\x04",
            b"cfut_private\t",
        ] {
            let mut reader = input;
            let error = read_hidden_value(&mut reader).expect_err("invalid input");
            assert!(!error.to_string().contains("cfut_private"));
        }
    }
}
