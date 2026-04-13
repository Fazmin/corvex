// Serializable data model for the 14 Corvex databases.
//
// This module is intentionally self-contained — no deps outside serde/std —
// because build.rs includes it directly via `#[path = ...]` to generate the
// bincode blobs at build time.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Databases {
    pub tests: TestDb,
    pub outdated: OutdatedDb,
    pub favicon: FaviconDb,
    pub server_msgs: ServerMsgsDb,
    pub realms: RealmsDb,
    pub variables: VariablesDb,
    pub content_search: ContentSearchDb,
    pub headers_common: HeadersCommonDb,
    pub headers_suggested: HeadersSuggestedDb,
    pub multiple_index: MultipleIndexDb,
    pub options: OptionsDb,
    pub useragents: UseragentsDb,
    pub dictionary: DictionaryDb,
    pub fourohfour: FourOhFourDb,
    pub subdomains: SubdomainsDb,
}

// db_tests --------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestDb {
    pub rows: Vec<TestRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRow {
    pub id: String,
    pub references: String,
    pub tuning: String,   // concatenated category chars (0..f + x)
    pub uri: String,      // may contain @VARS
    pub method: String,
    pub dsl: String,      // DSL source; parsed at runtime
    pub message: String,
    pub data: String,
    pub headers: String,
}

// db_outdated -----------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutdatedDb {
    pub rows: Vec<OutdatedRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutdatedRow {
    pub id: String,
    pub server_regex: String,
    pub version: String,
    pub message: String,
}

// db_favicon ------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaviconDb {
    pub rows: Vec<FaviconRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaviconRow {
    pub id: String,
    pub md5: String,
    pub description: String,
}

// db_server_msgs --------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerMsgsDb {
    pub rows: Vec<ServerMsgRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerMsgRow {
    pub id: String,
    pub server_regex: String,
    pub reference: String,
    pub message: String,
}

// db_realms -------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmsDb {
    pub rows: Vec<RealmRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmRow {
    pub id: String,
    pub realm: String,      // "@ANY" means match any
    pub user: String,
    pub password: String,
    pub message: String,
}

// db_variables ----------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariablesDb {
    /// Each entry is (name without leading @, space-separated values)
    pub entries: Vec<(String, Vec<String>)>,
}

// db_content_search -----------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentSearchDb {
    pub rows: Vec<ContentSearchRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentSearchRow {
    pub id: String,
    pub references: String,
    pub matchstring: String,
    pub message: String,
}

// db_headers_common / db_headers_suggested ------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadersCommonDb {
    pub headers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadersSuggestedDb {
    pub rows: Vec<HeaderSuggestedRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderSuggestedRow {
    pub header: String,
    pub reference: String,
}

// db_multiple_index -----------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipleIndexDb {
    pub names: Vec<String>,
}

// db_options ------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptionsDb {
    pub rows: Vec<OptionRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptionRow {
    pub id: String,
    pub method: String,
    pub references: String,
    pub message: String,
}

// db_useragents ---------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UseragentsDb {
    pub agents: Vec<String>,
}

// db_dictionary ---------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DictionaryDb {
    pub entries: Vec<String>,
}

// db_subdomains ---------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainsDb {
    pub prefixes: Vec<String>,
}

// db_404_strings --------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FourOhFourDb {
    pub signatures: Vec<String>,
}
