//! EPSS (Exploit Prediction Scoring System) data fetcher and loader.
//!
//! Downloads the daily EPSS CSV file and loads scores into the database.

use crate::vulndb::models::EpssScore;
use std::io::Read;
use tracing;

/// EPSS data download URL (compressed CSV).
const EPSS_URL: &str = "https://epss.cyentia.com/epss_scores-current.csv.gz";

/// EPSS data fetcher.
pub struct EpssClient {
    client: reqwest::Client,
}

impl EpssClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Download and parse the current EPSS scores CSV.
    /// Returns a vector of EPSS score records.
    pub async fn fetch_scores(&self) -> Result<Vec<EpssScore>, String> {
        tracing::info!(target: "vulndb", "downloading EPSS scores from {}", EPSS_URL);

        let resp = self
            .client
            .get(EPSS_URL)
            .send()
            .await
            .map_err(|e| format!("EPSS download failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("EPSS API returned status {}", resp.status()));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("EPSS read failed: {e}"))?;

        // Decompress gzip
        let mut decoder = flate2::read::GzDecoder::new(&bytes[..]);
        let mut csv_data = String::new();
        decoder
            .read_to_string(&mut csv_data)
            .map_err(|e| format!("EPSS decompress failed: {e}"))?;

        parse_epss_csv(&csv_data)
    }
}

/// Parse the EPSS CSV data.
/// Format: header comments starting with #, then `cve,epss,percentile` header, then data rows.
fn parse_epss_csv(data: &str) -> Result<Vec<EpssScore>, String> {
    let mut scores = Vec::new();
    let mut date = String::new();
    let mut in_header = true;

    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Skip comment lines, but extract date if present
        if line.starts_with('#') {
            if line.contains("score_date:") {
                date = line
                    .split("score_date:")
                    .nth(1)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
            }
            continue;
        }

        // Skip the CSV header row
        if in_header && line.starts_with("cve,") {
            in_header = false;
            continue;
        }
        in_header = false;

        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 3 {
            let cve_id = parts[0].trim().to_string();
            let score: f32 = parts[1].trim().parse().unwrap_or(0.0);
            let percentile: f32 = parts[2].trim().parse().unwrap_or(0.0);

            if cve_id.starts_with("CVE-") {
                scores.push(EpssScore {
                    cve_id,
                    score,
                    percentile,
                    date: date.clone(),
                });
            }
        }
    }

    tracing::info!(target: "vulndb", "parsed {} EPSS scores", scores.len());
    Ok(scores)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_epss_csv() {
        let csv = r#"#model_version:v2023.03.01,score_date:2024-01-15T00:00:00+0000
cve,epss,percentile
CVE-2021-44228,0.97565,0.99990
CVE-2023-1234,0.00123,0.45000
"#;
        let scores = parse_epss_csv(csv).unwrap();
        assert_eq!(scores.len(), 2);
        assert_eq!(scores[0].cve_id, "CVE-2021-44228");
        assert!((scores[0].score - 0.97565).abs() < 0.001);
        assert_eq!(scores[0].date, "2024-01-15T00:00:00+0000");
    }
}
