/// Initial dimensions for an interactive terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalOptions {
    pub columns: u32,
    pub rows: u32,
}

impl Default for TerminalOptions {
    fn default() -> Self {
        Self {
            columns: 80,
            rows: 24,
        }
    }
}

impl TerminalOptions {
    #[must_use]
    pub const fn new(columns: u32, rows: u32) -> Self {
        Self { columns, rows }
    }
}
