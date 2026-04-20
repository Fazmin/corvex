//! Tokenizer + recursive-descent parser for the DSL expression language.

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Num(f64),
    Str(String),
    Ident(String),
    True,
    False,
    Null,

    LParen,
    RParen,
    Comma,

    Plus,
    Minus,
    Star,
    Slash,
    Percent,

    Eq,   // ==
    Neq,  // !=
    Lt,
    Lte,
    Gt,
    Gte,

    AndAnd, // &&
    OrOr,   // ||
    Bang,   // !
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("lex: {0}")]
    Lex(String),
    #[error("parse: {0}")]
    Parse(String),
}

pub fn tokenize(src: &str) -> Result<Vec<Token>, ParseError> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b' ' | b'\t' | b'\n' | b'\r' => {
                i += 1;
            }
            b'(' => {
                out.push(Token::LParen);
                i += 1;
            }
            b')' => {
                out.push(Token::RParen);
                i += 1;
            }
            b',' => {
                out.push(Token::Comma);
                i += 1;
            }
            b'+' => {
                out.push(Token::Plus);
                i += 1;
            }
            b'-' => {
                out.push(Token::Minus);
                i += 1;
            }
            b'*' => {
                out.push(Token::Star);
                i += 1;
            }
            b'/' => {
                out.push(Token::Slash);
                i += 1;
            }
            b'%' => {
                out.push(Token::Percent);
                i += 1;
            }
            b'=' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    out.push(Token::Eq);
                    i += 2;
                } else {
                    return Err(ParseError::Lex(format!("unexpected `=` at {i}")));
                }
            }
            b'!' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    out.push(Token::Neq);
                    i += 2;
                } else {
                    out.push(Token::Bang);
                    i += 1;
                }
            }
            b'<' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    out.push(Token::Lte);
                    i += 2;
                } else {
                    out.push(Token::Lt);
                    i += 1;
                }
            }
            b'>' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    out.push(Token::Gte);
                    i += 2;
                } else {
                    out.push(Token::Gt);
                    i += 1;
                }
            }
            b'&' => {
                if bytes.get(i + 1) == Some(&b'&') {
                    out.push(Token::AndAnd);
                    i += 2;
                } else {
                    return Err(ParseError::Lex(format!("unexpected `&` at {i}")));
                }
            }
            b'|' => {
                if bytes.get(i + 1) == Some(&b'|') {
                    out.push(Token::OrOr);
                    i += 2;
                } else {
                    return Err(ParseError::Lex(format!("unexpected `|` at {i}")));
                }
            }
            b'"' | b'\'' => {
                let quote = c;
                i += 1;
                let start = i;
                let mut buf = String::new();
                while i < bytes.len() && bytes[i] != quote {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        let esc = bytes[i + 1];
                        let out_c = match esc {
                            b'n' => '\n',
                            b't' => '\t',
                            b'r' => '\r',
                            b'\\' => '\\',
                            b'"' => '"',
                            b'\'' => '\'',
                            _ => esc as char,
                        };
                        buf.push(out_c);
                        i += 2;
                    } else {
                        buf.push(bytes[i] as char);
                        i += 1;
                    }
                }
                if i >= bytes.len() {
                    return Err(ParseError::Lex(format!(
                        "unterminated string starting at {start}"
                    )));
                }
                i += 1; // closing quote
                out.push(Token::Str(buf));
            }
            _ if c.is_ascii_digit() => {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.')
                {
                    i += 1;
                }
                let s = std::str::from_utf8(&bytes[start..i]).unwrap();
                let n: f64 = s
                    .parse()
                    .map_err(|e| ParseError::Lex(format!("bad number `{s}`: {e}")))?;
                out.push(Token::Num(n));
            }
            _ if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
                {
                    i += 1;
                }
                let s = std::str::from_utf8(&bytes[start..i]).unwrap();
                match s {
                    "true" => out.push(Token::True),
                    "false" => out.push(Token::False),
                    "null" | "nil" => out.push(Token::Null),
                    _ => out.push(Token::Ident(s.to_string())),
                }
            }
            _ => {
                return Err(ParseError::Lex(format!(
                    "unexpected char {:?} at {i}",
                    c as char
                )));
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub enum Expr {
    Num(f64),
    Str(String),
    Bool(bool),
    Null,
    Ident(String),
    Call(String, Vec<Expr>),
    Unary(UnaryOp, Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Not,
    Neg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Neq,
    Lt,
    Lte,
    Gt,
    Gte,
    And,
    Or,
}

pub fn parse(src: &str) -> Result<Expr, ParseError> {
    let tokens = tokenize(src)?;
    let mut p = Parser { tokens, pos: 0 };
    let expr = p.parse_or()?;
    if p.pos < p.tokens.len() {
        return Err(ParseError::Parse(format!(
            "trailing tokens starting at position {}",
            p.pos
        )));
    }
    Ok(expr)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn eat(&mut self, t: &Token) -> bool {
        if self.peek() == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn bump(&mut self) -> Option<Token> {
        if self.pos < self.tokens.len() {
            let t = self.tokens[self.pos].clone();
            self.pos += 1;
            Some(t)
        } else {
            None
        }
    }

    fn parse_or(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_and()?;
        while self.eat(&Token::OrOr) {
            let rhs = self.parse_and()?;
            lhs = Expr::Binary(BinOp::Or, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_eq()?;
        while self.eat(&Token::AndAnd) {
            let rhs = self.parse_eq()?;
            lhs = Expr::Binary(BinOp::And, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_eq(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_cmp()?;
        loop {
            let op = if self.eat(&Token::Eq) {
                BinOp::Eq
            } else if self.eat(&Token::Neq) {
                BinOp::Neq
            } else {
                break;
            };
            let rhs = self.parse_cmp()?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_cmp(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_add()?;
        loop {
            let op = if self.eat(&Token::Lt) {
                BinOp::Lt
            } else if self.eat(&Token::Lte) {
                BinOp::Lte
            } else if self.eat(&Token::Gt) {
                BinOp::Gt
            } else if self.eat(&Token::Gte) {
                BinOp::Gte
            } else {
                break;
            };
            let rhs = self.parse_add()?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_add(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_mul()?;
        loop {
            let op = if self.eat(&Token::Plus) {
                BinOp::Add
            } else if self.eat(&Token::Minus) {
                BinOp::Sub
            } else {
                break;
            };
            let rhs = self.parse_mul()?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_mul(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_unary()?;
        loop {
            let op = if self.eat(&Token::Star) {
                BinOp::Mul
            } else if self.eat(&Token::Slash) {
                BinOp::Div
            } else if self.eat(&Token::Percent) {
                BinOp::Mod
            } else {
                break;
            };
            let rhs = self.parse_unary()?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        if self.eat(&Token::Bang) {
            let e = self.parse_unary()?;
            return Ok(Expr::Unary(UnaryOp::Not, Box::new(e)));
        }
        if self.eat(&Token::Minus) {
            let e = self.parse_unary()?;
            return Ok(Expr::Unary(UnaryOp::Neg, Box::new(e)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        let tok = self
            .bump()
            .ok_or_else(|| ParseError::Parse("unexpected end of input".into()))?;
        match tok {
            Token::Num(n) => Ok(Expr::Num(n)),
            Token::Str(s) => Ok(Expr::Str(s)),
            Token::True => Ok(Expr::Bool(true)),
            Token::False => Ok(Expr::Bool(false)),
            Token::Null => Ok(Expr::Null),
            Token::LParen => {
                let e = self.parse_or()?;
                if !self.eat(&Token::RParen) {
                    return Err(ParseError::Parse("missing closing `)`".into()));
                }
                Ok(e)
            }
            Token::Ident(name) => {
                if self.eat(&Token::LParen) {
                    let mut args = Vec::new();
                    if !self.eat(&Token::RParen) {
                        loop {
                            args.push(self.parse_or()?);
                            if self.eat(&Token::Comma) {
                                continue;
                            }
                            if self.eat(&Token::RParen) {
                                break;
                            }
                            return Err(ParseError::Parse(
                                "expected `,` or `)` in call".into(),
                            ));
                        }
                    }
                    Ok(Expr::Call(name, args))
                } else {
                    Ok(Expr::Ident(name))
                }
            }
            other => Err(ParseError::Parse(format!(
                "unexpected token {other:?} at primary"
            ))),
        }
    }
}

/// Walk an AST and collect every function name referenced in `Call`
/// nodes. Used by the template classifier to allowlist-check DSL.
pub fn referenced_functions(ast: &Expr) -> Vec<String> {
    let mut out = Vec::new();
    walk(ast, &mut out);
    out
}

fn walk(e: &Expr, out: &mut Vec<String>) {
    match e {
        Expr::Call(name, args) => {
            out.push(name.clone());
            for a in args {
                walk(a, out);
            }
        }
        Expr::Unary(_, e) => walk(e, out),
        Expr::Binary(_, a, b) => {
            walk(a, out);
            walk(b, out);
        }
        _ => {}
    }
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Mod => "%",
            Self::Eq => "==",
            Self::Neq => "!=",
            Self::Lt => "<",
            Self::Lte => "<=",
            Self::Gt => ">",
            Self::Gte => ">=",
            Self::And => "&&",
            Self::Or => "||",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_call_with_args() {
        let e = parse("md5(body)").unwrap();
        match e {
            Expr::Call(n, args) => {
                assert_eq!(n, "md5");
                assert_eq!(args.len(), 1);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_binop_chain() {
        let e = parse("status_code == 200 && contains(body, \"ok\")").unwrap();
        if let Expr::Binary(BinOp::And, _, _) = e {
            // fine
        } else {
            panic!("expected top-level &&");
        }
    }

    #[test]
    fn rejects_trailing_garbage() {
        assert!(parse("1 + 2 )").is_err());
    }
}
