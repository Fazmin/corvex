//! DSL evaluator. Consumes the AST produced by `parser` and resolves
//! identifiers against an [`Environment`].

use crate::dsl::fns;
use crate::dsl::parser::{BinOp, Expr, UnaryOp};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Null,
}

impl Value {
    pub fn truthy(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            Self::Int(n) => *n != 0,
            Self::Float(f) => *f != 0.0,
            Self::Str(s) => !s.is_empty(),
            Self::Null => false,
        }
    }

    pub fn to_string_lossy(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Self::Str(s) => std::borrow::Cow::Borrowed(s),
            Self::Int(n) => std::borrow::Cow::Owned(n.to_string()),
            Self::Float(f) => std::borrow::Cow::Owned(f.to_string()),
            Self::Bool(b) => std::borrow::Cow::Borrowed(if *b { "true" } else { "false" }),
            Self::Null => std::borrow::Cow::Borrowed(""),
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(n) => Some(*n),
            Self::Float(f) => Some(*f as i64),
            Self::Bool(b) => Some(if *b { 1 } else { 0 }),
            Self::Str(s) => s.parse().ok(),
            Self::Null => None,
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        match self {
            Self::Int(n) => Some(*n as f64),
            Self::Float(f) => Some(*f),
            Self::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Self::Str(s) => s.parse().ok(),
            Self::Null => None,
        }
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Self::Str(s)
    }
}
impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Self::Str(s.to_string())
    }
}
impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Self::Int(n)
    }
}
impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EvalError {
    #[error("unknown identifier: {0}")]
    UnknownIdent(String),
    #[error("unknown function: {0}")]
    UnknownFn(String),
    #[error("argument error: {0}")]
    Arg(String),
    #[error("type error: {0}")]
    Type(String),
}

/// Variable environment for DSL evaluation — populated by the executor
/// with per-request context (`status_code`, `body`, `content_length`,
/// `BaseURL`, extractor outputs, …).
#[derive(Debug, Default, Clone)]
pub struct Environment {
    vars: HashMap<String, Value>,
}

impl Environment {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, k: impl Into<String>, v: impl Into<Value>) {
        self.vars.insert(k.into(), v.into());
    }

    pub fn get(&self, k: &str) -> Option<&Value> {
        self.vars.get(k)
    }
}

pub fn eval(expr: &Expr, env: &Environment) -> Result<Value, EvalError> {
    match expr {
        Expr::Num(n) => {
            if n.fract() == 0.0 && n.abs() < (i64::MAX as f64) {
                Ok(Value::Int(*n as i64))
            } else {
                Ok(Value::Float(*n))
            }
        }
        Expr::Str(s) => Ok(Value::Str(s.clone())),
        Expr::Bool(b) => Ok(Value::Bool(*b)),
        Expr::Null => Ok(Value::Null),
        Expr::Ident(name) => env
            .get(name)
            .cloned()
            .ok_or_else(|| EvalError::UnknownIdent(name.clone())),
        Expr::Call(name, args) => {
            let mut vs = Vec::with_capacity(args.len());
            for a in args {
                vs.push(eval(a, env)?);
            }
            fns::call(name, &vs)
        }
        Expr::Unary(op, inner) => {
            let v = eval(inner, env)?;
            match op {
                UnaryOp::Not => Ok(Value::Bool(!v.truthy())),
                UnaryOp::Neg => match v {
                    Value::Int(n) => Ok(Value::Int(-n)),
                    Value::Float(f) => Ok(Value::Float(-f)),
                    other => Err(EvalError::Type(format!(
                        "cannot negate {:?}",
                        other
                    ))),
                },
            }
        }
        Expr::Binary(op, a, b) => {
            // Short-circuit logical ops.
            if matches!(op, BinOp::And | BinOp::Or) {
                let lhs = eval(a, env)?;
                if matches!(op, BinOp::And) && !lhs.truthy() {
                    return Ok(Value::Bool(false));
                }
                if matches!(op, BinOp::Or) && lhs.truthy() {
                    return Ok(Value::Bool(true));
                }
                let rhs = eval(b, env)?;
                return Ok(Value::Bool(rhs.truthy()));
            }
            let lhs = eval(a, env)?;
            let rhs = eval(b, env)?;
            apply_binop(*op, lhs, rhs)
        }
    }
}

fn apply_binop(op: BinOp, lhs: Value, rhs: Value) -> Result<Value, EvalError> {
    match op {
        BinOp::Add => {
            if let (Value::Str(a), b) = (&lhs, &rhs) {
                return Ok(Value::Str(format!("{}{}", a, b.to_string_lossy())));
            }
            if let (a, Value::Str(b)) = (&lhs, &rhs) {
                return Ok(Value::Str(format!("{}{}", a.to_string_lossy(), b)));
            }
            numeric(lhs, rhs, |a, b| a + b, |a, b| a + b)
        }
        BinOp::Sub => numeric(lhs, rhs, |a, b| a - b, |a, b| a - b),
        BinOp::Mul => numeric(lhs, rhs, |a, b| a * b, |a, b| a * b),
        BinOp::Div => numeric(
            lhs,
            rhs,
            |a, b| if b == 0 { 0 } else { a / b },
            |a, b| a / b,
        ),
        BinOp::Mod => numeric(
            lhs,
            rhs,
            |a, b| if b == 0 { 0 } else { a % b },
            |a, b| a % b,
        ),
        BinOp::Eq => Ok(Value::Bool(values_equal(&lhs, &rhs))),
        BinOp::Neq => Ok(Value::Bool(!values_equal(&lhs, &rhs))),
        BinOp::Lt => Ok(Value::Bool(cmp_lt(&lhs, &rhs))),
        BinOp::Lte => Ok(Value::Bool(cmp_lt(&lhs, &rhs) || values_equal(&lhs, &rhs))),
        BinOp::Gt => Ok(Value::Bool(cmp_lt(&rhs, &lhs))),
        BinOp::Gte => Ok(Value::Bool(
            cmp_lt(&rhs, &lhs) || values_equal(&lhs, &rhs),
        )),
        BinOp::And | BinOp::Or => unreachable!("handled above"),
    }
}

fn numeric(
    lhs: Value,
    rhs: Value,
    i: fn(i64, i64) -> i64,
    f: fn(f64, f64) -> f64,
) -> Result<Value, EvalError> {
    match (lhs, rhs) {
        (Value::Int(a), Value::Int(b)) => Ok(Value::Int(i(a, b))),
        (a, b) => {
            let af = a.as_float().ok_or_else(|| {
                EvalError::Type(format!("cannot coerce {a:?} to number"))
            })?;
            let bf = b.as_float().ok_or_else(|| {
                EvalError::Type(format!("cannot coerce {b:?} to number"))
            })?;
            Ok(Value::Float(f(af, bf)))
        }
    }
}

fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => x == y,
        (Value::Float(x), Value::Float(y)) => x == y,
        (Value::Str(x), Value::Str(y)) => x == y,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Null, Value::Null) => true,
        (Value::Int(x), Value::Float(y)) | (Value::Float(y), Value::Int(x)) => {
            (*x as f64) == *y
        }
        (Value::Str(s), other) | (other, Value::Str(s)) => {
            other.to_string_lossy() == *s
        }
        _ => false,
    }
}

fn cmp_lt(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => x < y,
        (Value::Float(x), Value::Float(y)) => x < y,
        (Value::Str(x), Value::Str(y)) => x < y,
        _ => match (a.as_float(), b.as_float()) {
            (Some(x), Some(y)) => x < y,
            _ => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::parser::parse;

    fn env_with_body(body: &str, status: i64) -> Environment {
        let mut e = Environment::new();
        e.set("body", body);
        e.set("status_code", Value::Int(status));
        e
    }

    #[test]
    fn status_and_contains() {
        let expr = parse("status_code == 200 && contains(body, \"ok\")").unwrap();
        let env = env_with_body("it is ok here", 200);
        let v = eval(&expr, &env).unwrap();
        assert_eq!(v, Value::Bool(true));
    }

    #[test]
    fn md5_round_trip() {
        let expr = parse("md5(\"abc\")").unwrap();
        let v = eval(&expr, &Environment::new()).unwrap();
        assert_eq!(
            v,
            Value::Str("900150983cd24fb0d6963f7d28e17f72".to_string())
        );
    }
}
