//! `-evasion` URI transform table.

use crate::http::encode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evasion {
    RandomUriEncoding,
    SelfReferenceDirs,
    PrematureUrlEnd,
    LongRandomPrefix,
    ParamHiding,
    TabSeparator,
    CaseSensitivity,
    WindowsDelimiter,
    SessionSplicing,
}

impl Evasion {
    pub fn parse(flag: char) -> Option<Self> {
        match flag {
            '1' => Some(Self::RandomUriEncoding),
            '2' => Some(Self::SelfReferenceDirs),
            '3' => Some(Self::PrematureUrlEnd),
            '4' => Some(Self::LongRandomPrefix),
            '5' => Some(Self::ParamHiding),
            '6' => Some(Self::TabSeparator),
            '7' => Some(Self::CaseSensitivity),
            '8' => Some(Self::WindowsDelimiter),
            '9' | 'A' | 'a' => Some(Self::SessionSplicing),
            _ => None,
        }
    }

    pub fn apply(&self, uri: &str) -> String {
        match self {
            Self::RandomUriEncoding => encode::encode_random_hex(uri),
            Self::SelfReferenceDirs => uri.replace('/', "/./"),
            Self::PrematureUrlEnd => format!("/%20HTTP/1.0%0d%0a/../../{}", uri.trim_start_matches('/')),
            Self::LongRandomPrefix => {
                format!("/{}/../{}", "x".repeat(128), uri.trim_start_matches('/'))
            }
            Self::ParamHiding => format!("{uri}?x=1"),
            Self::TabSeparator => uri.replace(' ', "\t"),
            Self::CaseSensitivity => encode::encode_random_case(uri),
            Self::WindowsDelimiter => uri.replace('/', "\\"),
            Self::SessionSplicing => uri.to_string(), // requires multi-packet sending
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct EvasionSet {
    pub modes: Vec<Evasion>,
}

impl EvasionSet {
    pub fn parse(flags: &str) -> Self {
        Self {
            modes: flags.chars().filter_map(Evasion::parse).collect(),
        }
    }

    pub fn apply(&self, mut uri: String) -> String {
        for e in &self.modes {
            uri = e.apply(&uri);
        }
        uri
    }
}
