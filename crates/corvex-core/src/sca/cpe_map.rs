//! CPE mapping table: maps (ecosystem, package_name) to (cpe_vendor, cpe_product).
//!
//! This allows cross-referencing package names from dependency manifests
//! against the NVD CPE database.

use crate::sca::component::Ecosystem;

/// Look up the CPE vendor and product for a known package.
/// Returns `(vendor, product)` or `None` if no mapping exists.
pub fn lookup_cpe(ecosystem: Ecosystem, name: &str) -> Option<(&'static str, &'static str)> {
    let key = name.to_lowercase();
    let key = key.as_str();

    match ecosystem {
        Ecosystem::Npm => NPM_MAP.iter().find(|(n, _, _)| *n == key).map(|(_, v, p)| (*v, *p)),
        Ecosystem::PyPI => PYPI_MAP.iter().find(|(n, _, _)| *n == key).map(|(_, v, p)| (*v, *p)),
        Ecosystem::Cargo => CARGO_MAP.iter().find(|(n, _, _)| *n == key).map(|(_, v, p)| (*v, *p)),
        Ecosystem::Maven => MAVEN_MAP.iter().find(|(n, _, _)| *n == key).map(|(_, v, p)| (*v, *p)),
        Ecosystem::Go => GO_MAP.iter().find(|(n, _, _)| *n == key).map(|(_, v, p)| (*v, *p)),
        Ecosystem::RubyGems => RUBY_MAP.iter().find(|(n, _, _)| *n == key).map(|(_, v, p)| (*v, *p)),
        Ecosystem::Packagist => PHP_MAP.iter().find(|(n, _, _)| *n == key).map(|(_, v, p)| (*v, *p)),
        _ => None,
    }
}

/// Look up the CPE vendor and product for a Wappalyzer-detected web
/// technology name. Keyed on display names produced by the stack
/// fingerprint engine (e.g. "nginx", "Apache HTTP Server", "WordPress").
/// Match is case-insensitive. Returns `None` when the product isn't in
/// the curated banner map — callers can fall back to [`guess_cpe`].
pub fn lookup_web_tech_cpe(name: &str) -> Option<(&'static str, &'static str)> {
    let key = name.to_lowercase();
    WEB_TECH_MAP
        .iter()
        .find(|(n, _, _)| n.eq_ignore_ascii_case(&key))
        .map(|(_, v, p)| (*v, *p))
}

/// Guess CPE from the package name when no mapping exists.
/// Uses the package name as both vendor and product.
pub fn guess_cpe(name: &str) -> (String, String) {
    let normalized = name
        .to_lowercase()
        .replace(['/', '@', ':'], "_")
        .replace("__", "_")
        .trim_matches('_')
        .to_string();
    (normalized.clone(), normalized)
}

// (package_name, cpe_vendor, cpe_product)
static NPM_MAP: &[(&str, &str, &str)] = &[
    ("express", "expressjs", "express"),
    ("lodash", "lodash", "lodash"),
    ("axios", "axios", "axios"),
    ("jquery", "jquery", "jquery"),
    ("react", "facebook", "react"),
    ("angular", "google", "angular"),
    ("vue", "vuejs", "vue.js"),
    ("webpack", "webpack.js", "webpack"),
    ("next", "vercel", "next.js"),
    ("node-fetch", "node-fetch_project", "node-fetch"),
    ("minimist", "minimist_project", "minimist"),
    ("glob-parent", "glob-parent_project", "glob-parent"),
    ("shelljs", "shelljs", "shelljs"),
    ("tar", "isaacs", "tar"),
    ("node-forge", "digitalbazaar", "forge"),
    ("jsonwebtoken", "auth0", "jsonwebtoken"),
    ("helmet", "helmetjs", "helmet"),
    ("passport", "jaredhanson", "passport"),
    ("moment", "momentjs", "moment"),
    ("underscore", "underscorejs", "underscore"),
    ("handlebars", "handlebarsjs", "handlebars"),
    ("ejs", "ejs", "ejs"),
    ("socket.io", "socket.io", "socket.io"),
    ("mysql", "mysqljs", "mysql"),
    ("pg", "node-postgres", "pg"),
    ("mongodb", "mongodb", "mongodb_node.js_driver"),
    ("sequelize", "sequelizejs", "sequelize"),
    ("mongoose", "mongoosejs", "mongoose"),
    ("cors", "expressjs", "cors"),
    ("body-parser", "expressjs", "body-parser"),
];

static PYPI_MAP: &[(&str, &str, &str)] = &[
    ("django", "djangoproject", "django"),
    ("flask", "palletsprojects", "flask"),
    ("requests", "python-requests", "requests"),
    ("numpy", "numpy", "numpy"),
    ("pandas", "pandas-dev", "pandas"),
    ("pillow", "python-pillow", "pillow"),
    ("cryptography", "pyca", "cryptography"),
    ("paramiko", "paramiko", "paramiko"),
    ("pyyaml", "pyyaml", "pyyaml"),
    ("jinja2", "palletsprojects", "jinja2"),
    ("werkzeug", "palletsprojects", "werkzeug"),
    ("sqlalchemy", "sqlalchemy", "sqlalchemy"),
    ("celery", "celeryproject", "celery"),
    ("redis", "redis", "redis-py"),
    ("boto3", "amazon", "boto3"),
    ("urllib3", "python", "urllib3"),
    ("setuptools", "python", "setuptools"),
    ("pip", "pypa", "pip"),
    ("certifi", "certifi", "certifi"),
    ("lxml", "lxml", "lxml"),
    ("scrapy", "scrapy", "scrapy"),
    ("twisted", "twistedmatrix", "twisted"),
    ("tornado", "tornadoweb", "tornado"),
    ("aiohttp", "aio-libs", "aiohttp"),
    ("gunicorn", "gunicorn", "gunicorn"),
    ("uvicorn", "encode", "uvicorn"),
    ("fastapi", "tiangolo", "fastapi"),
    ("starlette", "encode", "starlette"),
    ("pydantic", "pydantic", "pydantic"),
    ("httpx", "encode", "httpx"),
];

static CARGO_MAP: &[(&str, &str, &str)] = &[
    ("openssl", "openssl", "openssl"),
    ("hyper", "hyperium", "hyper"),
    ("tokio", "tokio-rs", "tokio"),
    ("serde", "serde-rs", "serde"),
    ("regex", "rust-lang", "regex"),
    ("reqwest", "seanmonstar", "reqwest"),
    ("rusqlite", "rusqlite", "rusqlite"),
    ("diesel", "diesel-rs", "diesel"),
    ("actix-web", "actix", "actix-web"),
    ("rocket", "sergiobenitez", "rocket"),
    ("axum", "tokio-rs", "axum"),
    ("ring", "briansmith", "ring"),
    ("rustls", "rustls", "rustls"),
    ("chrono", "chronotope", "chrono"),
    ("clap", "clap-rs", "clap"),
];

static MAVEN_MAP: &[(&str, &str, &str)] = &[
    ("org.apache.logging.log4j:log4j-core", "apache", "log4j"),
    ("org.springframework:spring-core", "vmware", "spring_framework"),
    ("org.springframework.boot:spring-boot", "vmware", "spring_boot"),
    ("com.fasterxml.jackson.core:jackson-databind", "fasterxml", "jackson-databind"),
    ("org.apache.struts:struts2-core", "apache", "struts"),
    ("org.apache.tomcat:tomcat-catalina", "apache", "tomcat"),
    ("commons-collections:commons-collections", "apache", "commons_collections"),
    ("org.apache.commons:commons-text", "apache", "commons-text"),
    ("mysql:mysql-connector-java", "oracle", "mysql_connector\\/j"),
    ("org.postgresql:postgresql", "postgresql", "postgresql_jdbc_driver"),
    ("com.google.guava:guava", "google", "guava"),
    ("org.apache.httpcomponents:httpclient", "apache", "httpclient"),
    ("io.netty:netty-all", "netty", "netty"),
    ("org.hibernate:hibernate-core", "hibernate", "hibernate_orm"),
    ("javax.servlet:javax.servlet-api", "oracle", "java_se"),
];

static GO_MAP: &[(&str, &str, &str)] = &[
    ("github.com/gin-gonic/gin", "gin-gonic", "gin"),
    ("github.com/gorilla/mux", "gorillatoolkit", "mux"),
    ("github.com/go-sql-driver/mysql", "go-sql-driver_project", "go-sql-driver"),
    ("github.com/lib/pq", "lib_pq_project", "pq"),
    ("github.com/dgrijalva/jwt-go", "jwt-go_project", "jwt-go"),
    ("golang.org/x/crypto", "golang", "crypto"),
    ("golang.org/x/net", "golang", "net"),
    ("golang.org/x/text", "golang", "text"),
    ("github.com/go-yaml/yaml", "go-yaml_project", "yaml"),
    ("github.com/sirupsen/logrus", "logrus_project", "logrus"),
];

static RUBY_MAP: &[(&str, &str, &str)] = &[
    ("rails", "rubyonrails", "rails"),
    ("actionpack", "rubyonrails", "actionpack"),
    ("activerecord", "rubyonrails", "activerecord"),
    ("activesupport", "rubyonrails", "activesupport"),
    ("rack", "rack_project", "rack"),
    ("nokogiri", "nokogiri", "nokogiri"),
    ("devise", "heartcombo", "devise"),
    ("sinatra", "sinatrarb", "sinatra"),
    ("puma", "puma", "puma"),
    ("sidekiq", "contribsys", "sidekiq"),
];

static PHP_MAP: &[(&str, &str, &str)] = &[
    ("laravel/framework", "laravel", "laravel"),
    ("symfony/http-foundation", "sensiolabs", "symfony"),
    ("symfony/http-kernel", "sensiolabs", "symfony"),
    ("guzzlehttp/guzzle", "guzzlephp", "guzzle"),
    ("monolog/monolog", "monolog_project", "monolog"),
    ("phpunit/phpunit", "phpunit", "phpunit"),
    ("doctrine/orm", "doctrine-project", "orm"),
    ("twig/twig", "symfony", "twig"),
    ("vlucas/phpdotenv", "vlucas", "phpdotenv"),
    ("league/flysystem", "thephpleague", "flysystem"),
];

// (wappalyzer_display_name, cpe_vendor, cpe_product)
//
// Keyed on the names the stack-fingerprint engine emits (both the seed
// set and high-signal upstream Wappalyzer entries). Only products with
// a reasonable version-aware CPE on NVD are mapped — anything missing
// falls back to `guess_cpe`, which still produces usable findings for
// well-named products.
static WEB_TECH_MAP: &[(&str, &str, &str)] = &[
    // Web servers
    ("nginx", "nginx", "nginx"),
    ("apache http server", "apache", "http_server"),
    ("apache", "apache", "http_server"),
    ("microsoft iis", "microsoft", "internet_information_services"),
    ("iis", "microsoft", "internet_information_services"),
    ("lighttpd", "lighttpd", "lighttpd"),
    ("caddy", "caddyserver", "caddy"),
    ("openresty", "openresty", "openresty"),
    // CDNs / load balancers (limited CVE footprint but still mapped)
    ("cloudflare", "cloudflare", "cloudflare"),
    ("haproxy", "haproxy", "haproxy"),
    // Programming languages / runtimes
    ("php", "php", "php"),
    ("node.js", "nodejs", "node.js"),
    ("python", "python", "python"),
    ("ruby", "ruby-lang", "ruby"),
    ("perl", "perl", "perl"),
    ("openssl", "openssl", "openssl"),
    // App servers / containers
    ("apache tomcat", "apache", "tomcat"),
    ("tomcat", "apache", "tomcat"),
    ("jetty", "eclipse", "jetty"),
    ("jboss", "redhat", "jboss_enterprise_application_platform"),
    ("wildfly", "redhat", "wildfly"),
    ("websphere", "ibm", "websphere_application_server"),
    ("weblogic", "oracle", "weblogic_server"),
    // CMS / web frameworks (product-level CPE)
    ("wordpress", "wordpress", "wordpress"),
    ("drupal", "drupal", "drupal"),
    ("joomla", "joomla", "joomla\\!"),
    ("magento", "magento", "magento"),
    ("typo3", "typo3", "typo3"),
    ("moodle", "moodle", "moodle"),
    ("mediawiki", "mediawiki", "mediawiki"),
    ("phpbb", "phpbb", "phpbb"),
    ("laravel", "laravel", "laravel"),
    ("django", "djangoproject", "django"),
    ("flask", "palletsprojects", "flask"),
    ("express", "expressjs", "express"),
    ("next.js", "vercel", "next.js"),
    ("nuxt.js", "nuxtjs", "nuxt"),
    ("asp.net", "microsoft", "asp.net"),
    ("spring framework", "vmware", "spring_framework"),
    ("spring boot", "vmware", "spring_boot"),
    ("struts", "apache", "struts"),
    ("symfony", "sensiolabs", "symfony"),
    ("codeigniter", "codeigniter", "codeigniter"),
    ("yii", "yiisoft", "yii"),
    ("cakephp", "cakefoundation", "cakephp"),
    ("zend", "zend", "zend_framework"),
    // JS libraries (banner-style hits from HTML/script references)
    ("jquery", "jquery", "jquery"),
    ("jquery ui", "jquery", "jquery_ui"),
    ("bootstrap", "getbootstrap", "bootstrap"),
    ("angular", "google", "angular"),
    ("angularjs", "angularjs", "angular.js"),
    ("react", "facebook", "react"),
    ("vue.js", "vuejs", "vue.js"),
    ("vue", "vuejs", "vue.js"),
    ("underscore.js", "underscorejs", "underscore"),
    ("lodash", "lodash", "lodash"),
    ("moment.js", "momentjs", "moment"),
    // Data stores surfaced via admin UIs (phpMyAdmin etc.) and ops panels
    ("phpmyadmin", "phpmyadmin", "phpmyadmin"),
    ("mysql", "oracle", "mysql"),
    ("mariadb", "mariadb", "mariadb"),
    ("postgresql", "postgresql", "postgresql"),
    ("redis", "redis", "redis"),
    ("mongodb", "mongodb", "mongodb"),
    // Other tools often banner-detected
    ("jira", "atlassian", "jira"),
    ("confluence", "atlassian", "confluence"),
    ("bitbucket", "atlassian", "bitbucket"),
    ("gitlab", "gitlab", "gitlab"),
    ("jenkins", "jenkins", "jenkins"),
    ("grafana", "grafana", "grafana"),
    ("kibana", "elastic", "kibana"),
    ("elasticsearch", "elastic", "elasticsearch"),
    ("prometheus", "prometheus", "prometheus"),
    ("exim", "exim", "exim"),
    ("postfix", "postfix", "postfix"),
    ("openssh", "openbsd", "openssh"),
    ("git", "git-scm", "git"),
    ("subversion", "apache", "subversion"),
    ("nextcloud", "nextcloud", "nextcloud"),
    ("owncloud", "owncloud", "owncloud"),
    // Misc high-value CVE targets
    ("rails", "rubyonrails", "rails"),
    ("ruby on rails", "rubyonrails", "rails"),
    ("werkzeug", "palletsprojects", "werkzeug"),
    ("gunicorn", "gunicorn", "gunicorn"),
    ("uvicorn", "encode", "uvicorn"),
    ("varnish", "varnish-cache", "varnish"),
    ("openproject", "openproject", "openproject"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_tech_lookup_is_case_insensitive() {
        assert_eq!(lookup_web_tech_cpe("nginx"), Some(("nginx", "nginx")));
        assert_eq!(lookup_web_tech_cpe("NGINX"), Some(("nginx", "nginx")));
        assert_eq!(
            lookup_web_tech_cpe("Apache HTTP Server"),
            Some(("apache", "http_server")),
        );
        assert_eq!(lookup_web_tech_cpe("WordPress"), Some(("wordpress", "wordpress")));
    }

    #[test]
    fn web_tech_lookup_returns_none_for_unknown() {
        assert!(lookup_web_tech_cpe("Definitely-Not-A-Product").is_none());
    }
}
