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
