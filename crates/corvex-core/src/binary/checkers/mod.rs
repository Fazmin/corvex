//! Registry of binary checkers for common vulnerable libraries.

use crate::binary::checker::{pattern, BinaryChecker, RegexChecker};

/// Create all registered binary checkers (~50 common libraries).
pub fn register_all() -> Vec<Box<dyn BinaryChecker>> {
    vec![
        // Crypto & TLS
        checker("OpenSSL", "openssl", "openssl", &[
            r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)",
            r"openssl[/-](\d+\.\d+\.\d+)",
        ]),
        checker("LibreSSL", "openbsd", "libressl", &[
            r"LibreSSL\s+(\d+\.\d+\.\d+)",
        ]),
        checker("GnuTLS", "gnu", "gnutls", &[
            r"GnuTLS\s+(\d+\.\d+\.\d+)",
            r"gnutls[/-](\d+\.\d+\.\d+)",
        ]),
        checker("libssh2", "libssh2", "libssh2", &[
            r"libssh2[/-](\d+\.\d+\.\d+)",
            r"SSH-2\.0-libssh2[_/-](\d+\.\d+\.\d+)",
        ]),
        checker("libssh", "libssh", "libssh", &[
            r"libssh[/-](\d+\.\d+\.\d+)",
        ]),

        // HTTP / Networking
        checker("curl", "haxx", "curl", &[
            r"curl[/-](\d+\.\d+\.\d+)",
            r"libcurl[/-](\d+\.\d+\.\d+)",
        ]),
        checker("wget", "gnu", "wget", &[
            r"Wget[/-](\d+\.\d+(?:\.\d+)?)",
        ]),
        checker("nginx", "f5", "nginx", &[
            r"nginx[/-](\d+\.\d+\.\d+)",
        ]),
        checker("Apache HTTP Server", "apache", "http_server", &[
            r"Apache[/-](\d+\.\d+\.\d+)",
            r"httpd[/-](\d+\.\d+\.\d+)",
        ]),
        checker("lighttpd", "lighttpd", "lighttpd", &[
            r"lighttpd[/-](\d+\.\d+\.\d+)",
        ]),

        // Compression
        checker("zlib", "zlib", "zlib", &[
            r"zlib\s+(\d+\.\d+\.\d+)",
            r"zlib[/-](\d+\.\d+\.\d+)",
        ]),
        checker("bzip2", "bzip", "bzip2", &[
            r"bzip2[/,-]\s*(\d+\.\d+\.\d+)",
        ]),
        checker("xz/liblzma", "tukaani", "xz", &[
            r"liblzma[/-](\d+\.\d+\.\d+)",
            r"xz[/-](\d+\.\d+\.\d+)",
        ]),
        checker("libzip", "libzip", "libzip", &[
            r"libzip[/-](\d+\.\d+\.\d+)",
        ]),
        checker("zstd", "facebook", "zstandard", &[
            r"zstd[/-](\d+\.\d+\.\d+)",
        ]),

        // XML / Parsing
        checker("libxml2", "xmlsoft", "libxml2", &[
            r"libxml2[/-](\d+\.\d+\.\d+)",
            r"LIBXML2[/-](\d+\.\d+\.\d+)",
        ]),
        checker("libxslt", "xmlsoft", "libxslt", &[
            r"libxslt[/-](\d+\.\d+\.\d+)",
        ]),
        checker("expat", "libexpat_project", "libexpat", &[
            r"expat[/_-](\d+\.\d+\.\d+)",
            r"libexpat[/-](\d+\.\d+\.\d+)",
        ]),

        // Image
        checker("libpng", "libpng", "libpng", &[
            r"libpng[/-](\d+\.\d+\.\d+)",
            r"PNG Reference Library[/-]\s*(\d+\.\d+\.\d+)",
        ]),
        checker("libjpeg", "ijg", "libjpeg", &[
            r"libjpeg[/-](\d+[a-z]?)",
        ]),
        checker("libtiff", "libtiff", "libtiff", &[
            r"libtiff[/-](\d+\.\d+\.\d+)",
            r"LIBTIFF.*?(\d+\.\d+\.\d+)",
        ]),
        checker("libwebp", "google", "libwebp", &[
            r"libwebp[/-](\d+\.\d+\.\d+)",
        ]),
        checker("ImageMagick", "imagemagick", "imagemagick", &[
            r"ImageMagick\s+(\d+\.\d+\.\d+)",
        ]),
        checker("FFmpeg", "ffmpeg", "ffmpeg", &[
            r"FFmpeg\s+(?:version\s+)?(\d+\.\d+(?:\.\d+)?)",
            r"ffmpeg[/-](\d+\.\d+(?:\.\d+)?)",
        ]),

        // Database
        checker("SQLite", "sqlite", "sqlite", &[
            r"SQLite\s+(\d+\.\d+\.\d+)",
            r"sqlite[/-](\d+\.\d+\.\d+)",
        ]),
        checker("PostgreSQL", "postgresql", "postgresql", &[
            r"PostgreSQL\s+(\d+\.\d+(?:\.\d+)?)",
        ]),
        checker("MySQL", "oracle", "mysql", &[
            r"MySQL\s+(\d+\.\d+\.\d+)",
            r"mysql[/-](\d+\.\d+\.\d+)",
        ]),
        checker("Redis", "redis", "redis", &[
            r"Redis\s+(?:server\s+)?v?=?(\d+\.\d+\.\d+)",
        ]),

        // Language runtimes
        checker("Python", "python", "python", &[
            r"Python[/-](\d+\.\d+\.\d+)",
        ]),
        checker("Node.js", "nodejs", "node.js", &[
            r"node[/-]v?(\d+\.\d+\.\d+)",
            r"Node\.js\s+v?(\d+\.\d+\.\d+)",
        ]),
        checker("PHP", "php", "php", &[
            r"PHP[/-](\d+\.\d+\.\d+)",
        ]),
        checker("Ruby", "ruby-lang", "ruby", &[
            r"ruby[/-](\d+\.\d+\.\d+)",
        ]),
        checker("Perl", "perl", "perl", &[
            r"perl[/-]v?(\d+\.\d+\.\d+)",
        ]),
        checker("Go", "golang", "go", &[
            r"go(\d+\.\d+(?:\.\d+)?)",
        ]),
        checker("Java/OpenJDK", "oracle", "jdk", &[
            r"openjdk[/-](\d+\.\d+\.\d+)",
            r"java[/-](\d+\.\d+\.\d+)",
        ]),

        // System libraries
        checker("glibc", "gnu", "glibc", &[
            r"GLIBC[_](\d+\.\d+(?:\.\d+)?)",
            r"glibc[/-](\d+\.\d+(?:\.\d+)?)",
        ]),
        checker("musl", "musl-libc", "musl", &[
            r"musl\s+(\d+\.\d+\.\d+)",
        ]),
        checker("libpcre", "pcre", "pcre", &[
            r"PCRE\s+(\d+\.\d+(?:\.\d+)?)",
            r"libpcre[/-](\d+\.\d+\.\d+)",
        ]),
        checker("libpcre2", "pcre", "pcre2", &[
            r"PCRE2\s+(\d+\.\d+(?:\.\d+)?)",
            r"libpcre2[/-](\d+\.\d+\.\d+)",
        ]),

        // Networking tools
        checker("OpenSSH", "openbsd", "openssh", &[
            r"OpenSSH[_/-](\d+\.\d+[p]?\d*)",
        ]),
        checker("Bind", "isc", "bind", &[
            r"BIND\s+(\d+\.\d+\.\d+)",
            r"named[/-](\d+\.\d+\.\d+)",
        ]),
        checker("Samba", "samba", "samba", &[
            r"Samba\s+(\d+\.\d+\.\d+)",
        ]),
        checker("OpenLDAP", "openldap", "openldap", &[
            r"OpenLDAP[/-](\d+\.\d+\.\d+)",
        ]),
        checker("Postfix", "postfix", "postfix", &[
            r"Postfix[/-](\d+\.\d+\.\d+)",
        ]),

        // Misc
        checker("Git", "git-scm", "git", &[
            r"git\s+version\s+(\d+\.\d+\.\d+)",
            r"git[/-](\d+\.\d+\.\d+)",
        ]),
        checker("Bash", "gnu", "bash", &[
            r"GNU bash.*?(\d+\.\d+\.\d+)",
            r"bash[/-](\d+\.\d+\.\d+)",
        ]),
        checker("Vim", "vim", "vim", &[
            r"VIM\s+-\s+Vi\s+IMproved\s+(\d+\.\d+)",
            r"vim[/-](\d+\.\d+(?:\.\d+)?)",
        ]),
        checker("Sudo", "sudo_project", "sudo", &[
            r"Sudo\s+version\s+(\d+\.\d+\.\d+)",
            r"sudo[/-](\d+\.\d+\.\d+)",
        ]),
        checker("systemd", "systemd_project", "systemd", &[
            r"systemd\s+(\d+(?:\.\d+)?)",
        ]),
        checker("dnsmasq", "thekelleys", "dnsmasq", &[
            r"dnsmasq[/-](\d+\.\d+(?:\.\d+)?)",
        ]),
        checker("HAProxy", "haproxy", "haproxy", &[
            r"HAProxy\s+version\s+(\d+\.\d+\.\d+)",
            r"haproxy[/-](\d+\.\d+\.\d+)",
        ]),
    ]
}

fn checker(
    name: &'static str,
    vendor: &'static str,
    product: &'static str,
    patterns: &[&str],
) -> Box<dyn BinaryChecker> {
    Box::new(RegexChecker {
        lib_name: name,
        vendor,
        product,
        patterns: patterns.iter().map(|p| pattern(p)).collect(),
    })
}
