//! Built-in plugins for the Rust Corvex port.
//!
//! Each module corresponds to one Perl `.plugin` file under
//! [../../program/plugins/](../../program/plugins/). The report sinks
//! that live under `report::*` parallel the `corvex_report_*.plugin` files.
//!
//! Plugins register via [`register_all`] which builds a [`PluginRegistry`]
//! and a list of [`ReportSink`]s ready to be handed to the scanner.

use corvex_core::plugin::{Plugin, PluginRegistry};
use corvex_core::report::{ReportFormat, ReportSink};
use std::sync::Arc;

pub mod apacheusers;
pub mod auth;
pub mod cgi;
pub mod compliance;
pub mod content_search;
pub mod dns_enum;
pub mod cookies;
pub mod dictionary_attack;
pub mod favicon;
pub mod fileops;
pub mod headers;
pub mod ms10_070;
pub mod msgs;
pub mod multiple_index;
pub mod negotiate;
pub mod netservices;
pub mod options;
pub mod optionsbleed;
pub mod os_fingerprint;
pub mod outdated;
pub mod paths;
pub mod put_del_test;
pub mod report;
pub mod robots;
pub mod shellshock;
pub mod siebel;
pub mod sitefiles;
pub mod springboot;
pub mod sqli_plugin;
pub mod ssl;
pub mod tests_plugin;
pub mod tls_audit;

/// Register every built-in scan plugin.
pub fn register_all() -> PluginRegistry {
    let mut reg = PluginRegistry::new();

    // Ordered roughly by weight (lower weights run first within a hook).
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        // DNS enumeration — weight 5, runs first in Recon.
        Arc::new(dns_enum::DnsEnumPlugin::default()),
        // TLS deep audit — weight 12, Recon.
        Arc::new(tls_audit::TlsAuditPlugin::default()),
        // OS fingerprinting — weight 15, Recon.
        Arc::new(os_fingerprint::OsFingerprintPlugin::default()),
        Arc::new(headers::HeadersPlugin::default()),
        Arc::new(msgs::MsgsPlugin::default()),
        Arc::new(outdated::OutdatedPlugin::default()),
        Arc::new(auth::AuthPlugin::default()),
        Arc::new(ssl::SslPlugin::default()),
        Arc::new(cookies::CookiesPlugin::default()),
        Arc::new(content_search::ContentSearchPlugin::default()),
        Arc::new(paths::PathsPlugin::default()),
        Arc::new(robots::RobotsPlugin::default()),
        Arc::new(cgi::CgiPlugin::default()),
        Arc::new(favicon::FaviconPlugin::default()),
        Arc::new(multiple_index::MultipleIndexPlugin::default()),
        Arc::new(negotiate::NegotiatePlugin::default()),
        Arc::new(options::OptionsPlugin::default()),
        Arc::new(optionsbleed::OptionsbleedPlugin::default()),
        Arc::new(put_del_test::PutDelPlugin::default()),
        Arc::new(apacheusers::ApacheUsersPlugin::default()),
        Arc::new(sitefiles::SitefilesPlugin::default()),
        Arc::new(fileops::FileopsPlugin::default()),
        Arc::new(shellshock::ShellshockPlugin::default()),
        Arc::new(ms10_070::Ms10_070Plugin::default()),
        Arc::new(springboot::SpringbootPlugin::default()),
        Arc::new(siebel::SiebelPlugin::default()),
        Arc::new(dictionary_attack::DictionaryAttackPlugin::default()),
        // Compliance audit — weight 25 in Postfetch hook.
        Arc::new(compliance::CompliancePlugin::default()),
        // Network service checks — weight 40 in Scan hook.
        Arc::new(netservices::NetServicesPlugin::default()),
        // Active SQL injection scanner — weight 50 in the Active hook.
        Arc::new(sqli_plugin::SqliPlugin::default()),
        // The big one — runs db_tests. Weight 99 = last.
        Arc::new(tests_plugin::TestsPlugin::default()),
    ];

    for p in plugins {
        reg.register(p);
    }
    reg
}

/// Build a set of report sinks matching the `-Format` CLI flag.
/// `formats` is a comma-separated list like "txt,json".
pub fn build_sinks(
    formats: &str,
    output: Option<&std::path::Path>,
) -> Vec<Box<dyn ReportSink>> {
    let list: Vec<ReportFormat> = formats
        .split(',')
        .filter_map(|s| ReportFormat::parse(s.trim()))
        .collect();
    let mut sinks: Vec<Box<dyn ReportSink>> = Vec::new();
    for fmt in list {
        let sink: Box<dyn ReportSink> = match fmt {
            ReportFormat::Text => Box::new(report::text::TextSink::new(output)),
            ReportFormat::Json => Box::new(report::json::JsonSink::new(output)),
            ReportFormat::Csv => Box::new(report::csv::CsvSink::new(output)),
            ReportFormat::Xml => Box::new(report::xml::XmlSink::new(output)),
            ReportFormat::Html => Box::new(report::html::HtmlSink::new(output)),
            ReportFormat::Sql => Box::new(report::sql::SqlSink::new(output)),
        };
        sinks.push(sink);
    }
    if sinks.is_empty() {
        sinks.push(Box::new(report::text::TextSink::new(output)));
    }
    sinks
}
