//! Report sinks: one module per Perl `corvex_report_*.plugin`.

pub mod csv;
pub mod html;
pub mod json;
pub mod markdown;
pub mod sql;
pub mod text;
pub mod xml;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

/// Helper: open a writer for a report. `None` means stdout.
pub(crate) fn open_writer(path: Option<&Path>) -> Box<dyn Write + Send> {
    match path {
        Some(p) => match File::create(p) {
            Ok(f) => Box::new(BufWriter::new(f)),
            Err(e) => {
                eprintln!("- ERROR: failed to open {}: {e}", p.display());
                Box::new(std::io::stdout())
            }
        },
        None => Box::new(std::io::stdout()),
    }
}
