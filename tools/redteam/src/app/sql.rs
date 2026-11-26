//! A small MySQL-flavoured SQL engine for the shop's vulnerable product query.
//!
//! It covers what injections into a `WHERE … = <input>` clause use: comments (`/* */`,
//! versioned `/*!50000 … */`, `-- `, `#`), MySQL whitespace, single- and double-quoted
//! strings, hex literals, `OR` / `||` / `AND` / `&&` / `NOT` / `!`, comparisons
//! (`= <=> <> != < > <= >= LIKE IS IN BETWEEN`), arithmetic, common functions,
//! `UNION [ALL] SELECT … [FROM table] [WHERE …]`, `ORDER BY n`, `LIMIT`. Table names are
//! case-sensitive, as with MySQL on Linux. Anything outside this subset is a syntax
//! error, so the simulation errs towards "not exploited".

use super::data;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Num(f64),
    Str(String),
}

impl Value {
    fn num(&self) -> Option<f64> {
        match self {
            Value::Null => None,
            Value::Num(n) => Some(*n),
            Value::Str(s) => Some(leading_number(s)),
        }
    }

    fn truthy(&self) -> Option<bool> {
        self.num().map(|n| n != 0.0)
    }

    pub fn render(&self) -> String {
        match self {
            Value::Null => "NULL".into(),
            Value::Num(n) if n.fract() == 0.0 && n.abs() < 1e15 => format!("{n:.0}"),
            Value::Num(n) => format!("{n}"),
            Value::Str(s) => s.clone(),
        }
    }
}

fn bool_val(b: Option<bool>) -> Value {
    match b {
        None => Value::Null,
        Some(b) => Value::Num(if b { 1.0 } else { 0.0 }),
    }
}

/// MySQL's string-to-number conversion: the longest numeric prefix, else 0.
fn leading_number(s: &str) -> f64 {
    let t = s.trim_start();
    let mut end = 0;
    let b = t.as_bytes();
    if end < b.len() && (b[end] == b'-' || b[end] == b'+') {
        end += 1;
    }
    let digits_start = end;
    while end < b.len() && b[end].is_ascii_digit() {
        end += 1;
    }
    if end < b.len() && b[end] == b'.' {
        end += 1;
        while end < b.len() && b[end].is_ascii_digit() {
            end += 1;
        }
    }
    if end == digits_start {
        return 0.0;
    }
    t[..end].parse().unwrap_or(0.0)
}

#[derive(Debug)]
pub struct SqlError(pub String);

fn syntax(near: &str) -> SqlError {
    let near: String = near.chars().take(40).collect();
    SqlError(format!(
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{near}' at line 1"
    ))
}

// ---------------------------------------------------------------- lexer

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(f64),
    Str(String),
    /// identifier or keyword, lower-cased; `raw` keeps the case (table names)
    Word {
        lower: String,
        raw: String,
    },
    Var(String),
    Op(&'static str),
}

const OPS: &[&str] = &[
    "<=>", "<=", ">=", "<>", "!=", "||", "&&", "=", "<", ">", "!", "+", "-", "*", "/", "%", "(",
    ")", ",", ";", ".",
];

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// Tokens, each with the rest of the input from where it starts (for error messages).
fn lex(src: &str) -> Result<Vec<(Tok, usize)>, SqlError> {
    let b = src.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    let mut versioned = 0usize; // open `/*! … */` comments whose content is code
    while i < b.len() {
        let c = b[i];
        if is_space(c) {
            i += 1;
            continue;
        }
        if c == b'/' && b.get(i + 1) == Some(&b'*') {
            if b.get(i + 2) == Some(&b'!') {
                i += 3;
                let mut d = 0;
                while d < 6 && i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                    d += 1;
                }
                versioned += 1;
                continue;
            }
            match src[i + 2..].find("*/") {
                Some(end) => {
                    i += 2 + end + 2;
                    continue;
                }
                None => return Err(syntax(&src[i..])),
            }
        }
        if c == b'*' && b.get(i + 1) == Some(&b'/') && versioned > 0 {
            versioned -= 1;
            i += 2;
            continue;
        }
        if c == b'#'
            || (c == b'-'
                && b.get(i + 1) == Some(&b'-')
                && b.get(i + 2).is_none_or(|&x| is_space(x) || x < 0x20))
        {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        let start = i;
        if c == b'\'' || c == b'"' {
            let q = c;
            let mut s = Vec::new();
            i += 1;
            loop {
                match b.get(i) {
                    None => return Err(syntax(&src[start..])),
                    Some(&x) if x == q => {
                        if b.get(i + 1) == Some(&q) {
                            s.push(q);
                            i += 2;
                        } else {
                            i += 1;
                            break;
                        }
                    }
                    Some(b'\\') => {
                        let e = *b.get(i + 1).ok_or_else(|| syntax(&src[start..]))?;
                        s.push(match e {
                            b'n' => b'\n',
                            b't' => b'\t',
                            b'0' => 0,
                            other => other,
                        });
                        i += 2;
                    }
                    Some(&x) => {
                        s.push(x);
                        i += 1;
                    }
                }
            }
            out.push((Tok::Str(String::from_utf8_lossy(&s).into_owned()), start));
            continue;
        }
        if c == b'0'
            && matches!(b.get(i + 1), Some(b'x' | b'X'))
            && b.get(i + 2).is_some_and(u8::is_ascii_hexdigit)
        {
            i += 2;
            let hs = i;
            while i < b.len() && b[i].is_ascii_hexdigit() {
                i += 1;
            }
            let hex = &src[hs..i];
            let hex = if hex.len() % 2 == 1 {
                format!("0{hex}")
            } else {
                hex.to_string()
            };
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .filter_map(|k| u8::from_str_radix(&hex[k..k + 2], 16).ok())
                .collect();
            out.push((
                Tok::Str(String::from_utf8_lossy(&bytes).into_owned()),
                start,
            ));
            continue;
        }
        if c.is_ascii_digit() || (c == b'.' && b.get(i + 1).is_some_and(u8::is_ascii_digit)) {
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i < b.len() && b[i] == b'.' {
                i += 1;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
            }
            if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
                let save = i;
                i += 1;
                if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
                    i += 1;
                }
                if i < b.len() && b[i].is_ascii_digit() {
                    while i < b.len() && b[i].is_ascii_digit() {
                        i += 1;
                    }
                } else {
                    i = save;
                }
            }
            let n: f64 = src[start..i].parse().map_err(|_| syntax(&src[start..]))?;
            // `1union` is not a number followed by a word in MySQL either: reject it
            if i < b.len() && (b[i].is_ascii_alphabetic() || b[i] == b'_') {
                return Err(syntax(&src[start..]));
            }
            out.push((Tok::Num(n), start));
            continue;
        }
        if c.is_ascii_alphabetic() || c == b'_' || c == b'$' {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'$') {
                i += 1;
            }
            let raw = &src[start..i];
            out.push((
                Tok::Word {
                    lower: raw.to_ascii_lowercase(),
                    raw: raw.to_string(),
                },
                start,
            ));
            continue;
        }
        if c == b'`' {
            let end = src[i + 1..]
                .find('`')
                .ok_or_else(|| syntax(&src[start..]))?;
            let raw = &src[i + 1..i + 1 + end];
            i += end + 2;
            out.push((
                Tok::Word {
                    lower: raw.to_ascii_lowercase(),
                    raw: raw.to_string(),
                },
                start,
            ));
            continue;
        }
        if c == b'@' && b.get(i + 1) == Some(&b'@') {
            i += 2;
            let vs = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'.') {
                i += 1;
            }
            out.push((Tok::Var(src[vs..i].to_ascii_lowercase()), start));
            continue;
        }
        match OPS.iter().find(|op| src[i..].starts_with(**op)) {
            Some(op) => {
                i += op.len();
                out.push((Tok::Op(op), start));
            }
            None => return Err(syntax(&src[start..])),
        }
    }
    if versioned > 0 {
        return Err(syntax(""));
    }
    Ok(out)
}

// ---------------------------------------------------------------- parser

#[derive(Debug, Clone)]
enum Expr {
    Lit(Value),
    Col(String),
    Var(String),
    Not(Box<Expr>),
    Neg(Box<Expr>),
    Bin(&'static str, Box<Expr>, Box<Expr>),
    Like(Box<Expr>, Box<Expr>, bool),
    Is(Box<Expr>, Option<bool>, bool),
    In(Box<Expr>, Vec<Expr>, bool),
    Between(Box<Expr>, Box<Expr>, Box<Expr>, bool),
    Func(String, Vec<Expr>),
}

#[derive(Debug)]
struct Select {
    star: bool,
    items: Vec<Expr>,
    from: Option<String>,
    filter: Option<Expr>,
}

#[derive(Debug)]
struct Stmt {
    selects: Vec<(Select, bool)>, // (select, distinct union before it)
    order: Vec<(Expr, bool)>,
    limit: Option<(usize, usize)>,
}

struct Parser<'a> {
    src: &'a str,
    toks: Vec<(Tok, usize)>,
    pos: usize,
}

const RESERVED: &[&str] = &[
    "select", "from", "where", "union", "all", "distinct", "order", "by", "limit", "offset", "and",
    "or", "not", "like", "is", "in", "between", "null", "true", "false", "asc", "desc", "xor",
    "div", "mod", "as",
];

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos).map(|(t, _)| t)
    }

    fn err(&self) -> SqlError {
        match self.toks.get(self.pos) {
            Some((_, at)) => syntax(&self.src[*at..]),
            None => syntax(""),
        }
    }

    fn word(&self, w: &str) -> bool {
        matches!(self.peek(), Some(Tok::Word { lower, .. }) if lower == w)
    }

    fn eat_word(&mut self, w: &str) -> bool {
        if self.word(w) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn op(&self, o: &str) -> bool {
        matches!(self.peek(), Some(Tok::Op(x)) if *x == o)
    }

    fn eat_op(&mut self, o: &str) -> bool {
        if self.op(o) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_word(&mut self, w: &str) -> Result<(), SqlError> {
        if self.eat_word(w) {
            Ok(())
        } else {
            Err(self.err())
        }
    }

    fn expect_op(&mut self, o: &str) -> Result<(), SqlError> {
        if self.eat_op(o) {
            Ok(())
        } else {
            Err(self.err())
        }
    }

    fn stmt(&mut self) -> Result<Stmt, SqlError> {
        let mut selects = vec![(self.select()?, false)];
        while self.eat_word("union") {
            let distinct = !self.eat_word("all");
            self.eat_word("distinct");
            selects.push((self.select()?, distinct));
        }
        let mut order = Vec::new();
        if self.eat_word("order") {
            self.expect_word("by")?;
            loop {
                let e = self.expr()?;
                let desc = if self.eat_word("desc") {
                    true
                } else {
                    self.eat_word("asc");
                    false
                };
                order.push((e, desc));
                if !self.eat_op(",") {
                    break;
                }
            }
        }
        let mut limit = None;
        if self.eat_word("limit") {
            let a = self.uint()?;
            limit = Some(if self.eat_op(",") {
                (a, self.uint()?)
            } else if self.eat_word("offset") {
                (self.uint()?, a)
            } else {
                (0, a)
            });
        }
        self.eat_op(";");
        if self.pos != self.toks.len() {
            return Err(self.err());
        }
        Ok(Stmt {
            selects,
            order,
            limit,
        })
    }

    fn uint(&mut self) -> Result<usize, SqlError> {
        match self.peek() {
            Some(Tok::Num(n)) if *n >= 0.0 && n.fract() == 0.0 => {
                let n = *n as usize;
                self.pos += 1;
                Ok(n)
            }
            _ => Err(self.err()),
        }
    }

    fn select(&mut self) -> Result<Select, SqlError> {
        // `UNION (SELECT …)` is valid MySQL
        if self.eat_op("(") {
            let s = self.select()?;
            self.expect_op(")")?;
            return Ok(s);
        }
        self.expect_word("select")?;
        self.eat_word("all");
        self.eat_word("distinct");
        let mut star = false;
        let mut items = Vec::new();
        if self.eat_op("*") {
            star = true;
        } else {
            loop {
                items.push(self.expr()?);
                // `expr AS alias` or `expr alias`
                let bare_alias = matches!(self.peek(), Some(Tok::Word { lower, .. }) if !RESERVED.contains(&lower.as_str()));
                if self.eat_word("as") || bare_alias {
                    self.alias()?;
                }
                if !self.eat_op(",") {
                    break;
                }
            }
        }
        let mut from = None;
        if self.eat_word("from") {
            match self.peek().cloned() {
                Some(Tok::Word { raw, lower }) if !RESERVED.contains(&lower.as_str()) => {
                    self.pos += 1;
                    // `shop.users`
                    if self.eat_op(".") {
                        match self.peek().cloned() {
                            Some(Tok::Word { raw, .. }) => {
                                self.pos += 1;
                                from = Some(raw);
                            }
                            _ => return Err(self.err()),
                        }
                    } else {
                        from = Some(raw);
                    }
                }
                _ => return Err(self.err()),
            }
        }
        let filter = if self.eat_word("where") {
            Some(self.expr()?)
        } else {
            None
        };
        Ok(Select {
            star,
            items,
            from,
            filter,
        })
    }

    fn alias(&mut self) -> Result<(), SqlError> {
        match self.peek() {
            Some(Tok::Word { .. }) | Some(Tok::Str(_)) => {
                self.pos += 1;
                Ok(())
            }
            _ => Err(self.err()),
        }
    }

    fn expr(&mut self) -> Result<Expr, SqlError> {
        let mut l = self.and_expr()?;
        loop {
            if self.eat_word("or") || self.eat_op("||") {
                l = Expr::Bin("or", Box::new(l), Box::new(self.and_expr()?));
            } else if self.eat_word("xor") {
                l = Expr::Bin("xor", Box::new(l), Box::new(self.and_expr()?));
            } else {
                return Ok(l);
            }
        }
    }

    fn and_expr(&mut self) -> Result<Expr, SqlError> {
        let mut l = self.not_expr()?;
        while self.eat_word("and") || self.eat_op("&&") {
            l = Expr::Bin("and", Box::new(l), Box::new(self.not_expr()?));
        }
        Ok(l)
    }

    fn not_expr(&mut self) -> Result<Expr, SqlError> {
        if self.eat_word("not") {
            return Ok(Expr::Not(Box::new(self.not_expr()?)));
        }
        self.cmp_expr()
    }

    fn cmp_expr(&mut self) -> Result<Expr, SqlError> {
        let l = self.add_expr()?;
        for op in ["<=>", "<=", ">=", "<>", "!=", "=", "<", ">"] {
            if self.eat_op(op) {
                let r = self.add_expr()?;
                let op: &'static str = if op == "<>" { "!=" } else { op };
                return Ok(Expr::Bin(op, Box::new(l), Box::new(r)));
            }
        }
        if self.eat_word("is") {
            let neg = self.eat_word("not");
            let what = if self.eat_word("null") {
                None
            } else if self.eat_word("true") {
                Some(true)
            } else if self.eat_word("false") {
                Some(false)
            } else {
                return Err(self.err());
            };
            return Ok(Expr::Is(Box::new(l), what, neg));
        }
        let neg = self.eat_word("not");
        if self.eat_word("like") {
            return Ok(Expr::Like(Box::new(l), Box::new(self.add_expr()?), neg));
        }
        if self.eat_word("in") {
            self.expect_op("(")?;
            let mut list = vec![self.expr()?];
            while self.eat_op(",") {
                list.push(self.expr()?);
            }
            self.expect_op(")")?;
            return Ok(Expr::In(Box::new(l), list, neg));
        }
        if self.eat_word("between") {
            let lo = self.add_expr()?;
            self.expect_word("and")?;
            let hi = self.add_expr()?;
            return Ok(Expr::Between(Box::new(l), Box::new(lo), Box::new(hi), neg));
        }
        if neg {
            return Err(self.err());
        }
        Ok(l)
    }

    fn add_expr(&mut self) -> Result<Expr, SqlError> {
        let mut l = self.mul_expr()?;
        loop {
            if self.eat_op("+") {
                l = Expr::Bin("+", Box::new(l), Box::new(self.mul_expr()?));
            } else if self.eat_op("-") {
                l = Expr::Bin("-", Box::new(l), Box::new(self.mul_expr()?));
            } else {
                return Ok(l);
            }
        }
    }

    fn mul_expr(&mut self) -> Result<Expr, SqlError> {
        let mut l = self.unary()?;
        loop {
            if self.eat_op("*") {
                l = Expr::Bin("*", Box::new(l), Box::new(self.unary()?));
            } else if self.eat_op("/") || self.eat_word("div") {
                l = Expr::Bin("/", Box::new(l), Box::new(self.unary()?));
            } else if self.eat_op("%") || self.eat_word("mod") {
                l = Expr::Bin("%", Box::new(l), Box::new(self.unary()?));
            } else {
                return Ok(l);
            }
        }
    }

    fn unary(&mut self) -> Result<Expr, SqlError> {
        if self.eat_op("-") {
            return Ok(Expr::Neg(Box::new(self.unary()?)));
        }
        if self.eat_op("+") {
            return self.unary();
        }
        if self.eat_op("!") {
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, SqlError> {
        let Some(t) = self.peek().cloned() else {
            return Err(self.err());
        };
        self.pos += 1;
        match t {
            Tok::Num(n) => Ok(Expr::Lit(Value::Num(n))),
            Tok::Str(s) => Ok(Expr::Lit(Value::Str(s))),
            Tok::Var(v) => Ok(Expr::Var(v)),
            Tok::Op("(") => {
                let e = self.expr()?;
                self.expect_op(")")?;
                Ok(e)
            }
            Tok::Word { lower, .. } => match lower.as_str() {
                "null" => Ok(Expr::Lit(Value::Null)),
                "true" => Ok(Expr::Lit(Value::Num(1.0))),
                "false" => Ok(Expr::Lit(Value::Num(0.0))),
                w if RESERVED.contains(&w) => {
                    self.pos -= 1;
                    Err(self.err())
                }
                _ if self.op("(") => {
                    self.pos += 1;
                    let mut args = Vec::new();
                    if !self.eat_op(")") {
                        loop {
                            if self.eat_op("*") {
                                args.push(Expr::Lit(Value::Num(1.0)));
                            } else {
                                args.push(self.expr()?);
                            }
                            if self.eat_op(")") {
                                break;
                            }
                            self.expect_op(",")?;
                        }
                    }
                    Ok(Expr::Func(lower, args))
                }
                _ => {
                    // `table.column`
                    if self.eat_op(".") {
                        match self.peek().cloned() {
                            Some(Tok::Word { lower, .. }) => {
                                self.pos += 1;
                                return Ok(Expr::Col(lower));
                            }
                            _ => return Err(self.err()),
                        }
                    }
                    Ok(Expr::Col(lower))
                }
            },
            Tok::Op(_) => {
                self.pos -= 1;
                Err(self.err())
            }
        }
    }
}

// ---------------------------------------------------------------- evaluation

struct Table {
    columns: Vec<&'static str>,
    rows: Vec<Vec<Value>>,
}

fn table(name: &str) -> Option<Table> {
    match name {
        "products" => Some(Table {
            columns: vec!["id", "name", "price", "hidden"],
            rows: data::PRODUCTS
                .iter()
                .map(|(id, n, p, h)| {
                    vec![
                        Value::Num(*id as f64),
                        Value::Str(n.to_string()),
                        Value::Num(*p),
                        Value::Num(*h as f64),
                    ]
                })
                .collect(),
        }),
        "users" => Some(Table {
            columns: vec!["id", "username", "password_hash", "email"],
            rows: data::USERS
                .iter()
                .map(|(id, u, h, e)| {
                    vec![
                        Value::Num(*id as f64),
                        Value::Str(u.to_string()),
                        Value::Str(h.to_string()),
                        Value::Str(e.to_string()),
                    ]
                })
                .collect(),
        }),
        _ => None,
    }
}

const VERSION: &str = "8.0.36-0ubuntu0.22.04.1";

struct Row<'a> {
    columns: &'a [&'static str],
    values: &'a [Value],
}

fn cmp_values(a: &Value, b: &Value) -> Option<std::cmp::Ordering> {
    match (a, b) {
        (Value::Null, _) | (_, Value::Null) => None,
        (Value::Str(x), Value::Str(y)) => Some(x.to_lowercase().cmp(&y.to_lowercase())),
        _ => a.num()?.partial_cmp(&b.num()?),
    }
}

fn like(s: &str, pat: &str) -> bool {
    fn go(s: &[char], p: &[char]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some('%') => (0..=s.len()).any(|k| go(&s[k..], &p[1..])),
            Some('_') => !s.is_empty() && go(&s[1..], &p[1..]),
            Some('\\') if p.len() > 1 => s.first() == Some(&p[1]) && go(&s[1..], &p[2..]),
            Some(c) => s.first() == Some(c) && go(&s[1..], &p[1..]),
        }
    }
    let s: Vec<char> = s.to_lowercase().chars().collect();
    let p: Vec<char> = pat.to_lowercase().chars().collect();
    go(&s, &p)
}

fn eval(e: &Expr, row: &Row, clause: &str) -> Result<Value, SqlError> {
    Ok(match e {
        Expr::Lit(v) => v.clone(),
        Expr::Col(c) => match row.columns.iter().position(|x| x == c) {
            Some(i) => row.values[i].clone(),
            None => return Err(SqlError(format!("Unknown column '{c}' in '{clause}'"))),
        },
        Expr::Var(v) => match v.as_str() {
            "version" | "global.version" | "session.version" => Value::Str(VERSION.into()),
            "hostname" => Value::Str("demo-shop".into()),
            "datadir" => Value::Str("/var/lib/mysql/".into()),
            _ => return Err(SqlError(format!("Unknown system variable '{v}'"))),
        },
        Expr::Not(x) => bool_val(eval(x, row, clause)?.truthy().map(|b| !b)),
        Expr::Neg(x) => match eval(x, row, clause)?.num() {
            Some(n) => Value::Num(-n),
            None => Value::Null,
        },
        Expr::Bin(op, a, b) => {
            let (x, y) = (eval(a, row, clause)?, eval(b, row, clause)?);
            match *op {
                "or" => bool_val(match (x.truthy(), y.truthy()) {
                    (Some(true), _) | (_, Some(true)) => Some(true),
                    (Some(false), Some(false)) => Some(false),
                    _ => None,
                }),
                "and" => bool_val(match (x.truthy(), y.truthy()) {
                    (Some(false), _) | (_, Some(false)) => Some(false),
                    (Some(true), Some(true)) => Some(true),
                    _ => None,
                }),
                "xor" => bool_val(match (x.truthy(), y.truthy()) {
                    (Some(p), Some(q)) => Some(p != q),
                    _ => None,
                }),
                "<=>" => bool_val(Some(match (&x, &y) {
                    (Value::Null, Value::Null) => true,
                    (Value::Null, _) | (_, Value::Null) => false,
                    _ => cmp_values(&x, &y) == Some(std::cmp::Ordering::Equal),
                })),
                "=" | "!=" | "<" | ">" | "<=" | ">=" => {
                    use std::cmp::Ordering::*;
                    bool_val(cmp_values(&x, &y).map(|o| match *op {
                        "=" => o == Equal,
                        "!=" => o != Equal,
                        "<" => o == Less,
                        ">" => o == Greater,
                        "<=" => o != Greater,
                        _ => o != Less,
                    }))
                }
                _ => match (x.num(), y.num()) {
                    (Some(p), Some(q)) => match *op {
                        "+" => Value::Num(p + q),
                        "-" => Value::Num(p - q),
                        "*" => Value::Num(p * q),
                        "/" if q != 0.0 => Value::Num(p / q),
                        "%" if q != 0.0 => Value::Num(p % q),
                        _ => Value::Null,
                    },
                    _ => Value::Null,
                },
            }
        }
        Expr::Like(a, p, neg) => {
            let (x, y) = (eval(a, row, clause)?, eval(p, row, clause)?);
            if x == Value::Null || y == Value::Null {
                Value::Null
            } else {
                bool_val(Some(like(&x.render(), &y.render()) != *neg))
            }
        }
        Expr::Is(a, what, neg) => {
            let x = eval(a, row, clause)?;
            let r = match what {
                None => x == Value::Null,
                Some(t) => x.truthy() == Some(*t),
            };
            bool_val(Some(r != *neg))
        }
        Expr::In(a, list, neg) => {
            let x = eval(a, row, clause)?;
            let mut found = false;
            for item in list {
                if cmp_values(&x, &eval(item, row, clause)?) == Some(std::cmp::Ordering::Equal) {
                    found = true;
                }
            }
            if x == Value::Null {
                Value::Null
            } else {
                bool_val(Some(found != *neg))
            }
        }
        Expr::Between(a, lo, hi, neg) => {
            let x = eval(a, row, clause)?;
            let (l, h) = (eval(lo, row, clause)?, eval(hi, row, clause)?);
            match (cmp_values(&x, &l), cmp_values(&x, &h)) {
                (Some(p), Some(q)) => bool_val(Some(
                    (p != std::cmp::Ordering::Less && q != std::cmp::Ordering::Greater) != *neg,
                )),
                _ => Value::Null,
            }
        }
        Expr::Func(name, args) => {
            let vals: Vec<Value> = args
                .iter()
                .map(|a| eval(a, row, clause))
                .collect::<Result<_, _>>()?;
            func(name, &vals)?
        }
    })
}

fn func(name: &str, v: &[Value]) -> Result<Value, SqlError> {
    let arg = |i: usize| v.get(i).cloned().unwrap_or(Value::Null);
    let s = |i: usize| arg(i).render();
    let n = |i: usize| arg(i).num().unwrap_or(0.0);
    let null_in = v.contains(&Value::Null);
    Ok(match name {
        "version" => Value::Str(VERSION.into()),
        "database" | "schema" => Value::Str("shop".into()),
        "user" | "current_user" | "system_user" | "session_user" => {
            Value::Str("shop@localhost".into())
        }
        "concat" if null_in => Value::Null,
        "concat" => Value::Str(v.iter().map(Value::render).collect()),
        "concat_ws" => Value::Str(
            v.iter()
                .skip(1)
                .filter(|x| **x != Value::Null)
                .map(Value::render)
                .collect::<Vec<_>>()
                .join(&s(0)),
        ),
        "char" => Value::Str(
            v.iter()
                .filter_map(|x| x.num())
                .filter_map(|c| char::from_u32(c as u32))
                .collect(),
        ),
        "sleep" | "benchmark" => Value::Num(0.0),
        "length" | "char_length" | "character_length" if null_in => Value::Null,
        "length" | "char_length" | "character_length" => Value::Num(s(0).chars().count() as f64),
        "ascii" | "ord" => Value::Num(s(0).chars().next().map_or(0.0, |c| c as u32 as f64)),
        "lower" | "lcase" => Value::Str(s(0).to_lowercase()),
        "upper" | "ucase" => Value::Str(s(0).to_uppercase()),
        "substring" | "substr" | "mid" => {
            let chars: Vec<char> = s(0).chars().collect();
            let start = (n(1) as i64).max(1) as usize - 1;
            let len = if v.len() > 2 {
                n(2).max(0.0) as usize
            } else {
                chars.len()
            };
            Value::Str(chars.iter().skip(start).take(len).collect())
        }
        "hex" => Value::Str(
            s(0).bytes()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .concat(),
        ),
        "if" => {
            if arg(0).truthy() == Some(true) {
                arg(1)
            } else {
                arg(2)
            }
        }
        "ifnull" => {
            if arg(0) == Value::Null {
                arg(1)
            } else {
                arg(0)
            }
        }
        "coalesce" => v
            .iter()
            .find(|x| **x != Value::Null)
            .cloned()
            .unwrap_or(Value::Null),
        _ => return Err(SqlError(format!("FUNCTION shop.{name} does not exist"))),
    })
}

/// A query result: the rows of the first two columns are what the shop page shows.
#[derive(Debug)]
pub struct Rows {
    pub columns: usize,
    pub rows: Vec<Vec<Value>>,
}

/// Runs one statement against the shop's tables.
pub fn query(sql: &str) -> Result<Rows, SqlError> {
    let toks = lex(sql)?;
    let mut p = Parser {
        src: sql,
        toks,
        pos: 0,
    };
    let stmt = p.stmt()?;
    let empty_cols: [&'static str; 0] = [];
    let mut out: Vec<Vec<Value>> = Vec::new();
    let mut width = None;
    for (sel, distinct) in &stmt.selects {
        let t = match &sel.from {
            Some(name) => Some(
                table(name)
                    .ok_or_else(|| SqlError(format!("Table 'shop.{name}' doesn't exist")))?,
            ),
            None => None,
        };
        let (columns, rows): (&[&'static str], Vec<Vec<Value>>) = match &t {
            Some(t) => (&t.columns, t.rows.clone()),
            None => (&empty_cols, vec![vec![]]),
        };
        let mut part = Vec::new();
        for values in &rows {
            let row = Row { columns, values };
            if let Some(f) = &sel.filter {
                if eval(f, &row, "where clause")?.truthy() != Some(true) {
                    continue;
                }
            }
            if sel.star {
                if t.is_none() {
                    return Err(SqlError("No tables used".into()));
                }
                part.push(values.clone());
            } else {
                part.push(
                    sel.items
                        .iter()
                        .map(|e| eval(e, &row, "field list"))
                        .collect::<Result<_, _>>()?,
                );
            }
        }
        let w = if sel.star {
            columns.len()
        } else {
            sel.items.len()
        };
        match width {
            None => width = Some(w),
            Some(x) if x != w => {
                return Err(SqlError(
                    "The used SELECT statements have a different number of columns".into(),
                ));
            }
            _ => {}
        }
        out.extend(part);
        if *distinct {
            let mut seen: Vec<Vec<Value>> = Vec::new();
            out.retain(|r| {
                if seen.contains(r) {
                    false
                } else {
                    seen.push(r.clone());
                    true
                }
            });
        }
    }
    let width = width.unwrap_or(0);
    for (e, desc) in stmt.order.iter().rev() {
        let idx = match e {
            Expr::Lit(Value::Num(n)) if n.fract() == 0.0 && *n >= 1.0 && (*n as usize) <= width => {
                *n as usize - 1
            }
            Expr::Lit(Value::Num(n)) => {
                return Err(SqlError(format!(
                    "Unknown column '{}' in 'order clause'",
                    Value::Num(*n).render()
                )));
            }
            Expr::Col(c) => match ["name", "price"].iter().position(|x| x == c) {
                Some(i) if i < width => i,
                _ => return Err(SqlError(format!("Unknown column '{c}' in 'order clause'"))),
            },
            // other expressions sort by a constant: order unchanged
            _ => continue,
        };
        out.sort_by(|a, b| {
            let o = cmp_values(&a[idx], &b[idx]).unwrap_or(std::cmp::Ordering::Equal);
            if *desc { o.reverse() } else { o }
        });
    }
    if let Some((off, n)) = stmt.limit {
        out = out.into_iter().skip(off).take(n).collect();
    }
    Ok(Rows {
        columns: width,
        rows: out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const Q: &str = "SELECT name, price FROM products WHERE hidden = 0 AND id = ";

    fn names(input: &str) -> Result<Vec<String>, String> {
        query(&format!("{Q}{input}"))
            .map(|r| {
                r.rows
                    .iter()
                    .map(|row| row.iter().map(Value::render).collect::<Vec<_>>().join("|"))
                    .collect()
            })
            .map_err(|e| e.0)
    }

    fn leaks(input: &str) -> bool {
        names(input).is_ok_and(|rows| {
            rows.iter()
                .any(|r| r.contains(data::HIDDEN_PRODUCT) || r.contains(data::ADMIN_HASH))
        })
    }

    #[test]
    fn normal_lookups() {
        assert_eq!(names("1").unwrap(), ["Espresso cup|9.5"]);
        assert!(names("4").unwrap().is_empty(), "hidden");
        assert!(names("99").unwrap().is_empty());
        assert!(!leaks("1"));
    }

    #[test]
    fn classic_injections_work() {
        for p in [
            "1 OR 1=1",
            "1 or 1=1-- ",
            "1 OR 1=1#",
            "1/**/OR/**/1=1",
            "1\tOR\n2>1",
            "1 || 1",
            "1 OR 'a'='a'",
            "1 OR 'a'='A'",
            "1 OR 1 LIKE 1",
            "1 OR NOT 0",
            "1 OR 1<=>1",
            "1 OR true",
            "1 OR 0x41=0x41",
            "1 /*!50000OR*/ 1=1",
            "1 OR hidden=1",
            "1 OR 1 IN (1,2)",
            "1 OR 2 BETWEEN 1 AND 3",
            "0 UNION SELECT username, password_hash FROM users",
            "0 UNION ALL SELECT username,password_hash FROM users-- -",
            "-1 /*!UNION*/ /*!SELECT*/ username, password_hash /*!FROM*/ users",
            "0 UNION (SELECT username, password_hash FROM users)",
            "0 union select concat(username,0x3a,password_hash),2 from users",
            "0 UNION SELECT name, price FROM products WHERE hidden=1",
        ] {
            assert!(leaks(p), "{p}: {:?}", names(p));
        }
    }

    #[test]
    fn broken_or_harmless_injections_do_not() {
        for p in [
            "1'",
            "1 OR",
            "1 OR 1=1 /*",
            "1 UNION SELECT username FROM users",
            "1 UNION SELECT username, password_hash, email FROM users",
            "1 UNION SELECT username, password_hash FROM USERS",
            "1 UN/**/ION SELECT username, password_hash FROM users",
            "1 OR 1=1; DROP TABLE users",
            "1 OR 1=2",
            "1 AND 1=1",
            "1 --",
            "1 ORDER BY 3",
            "1%20OR%201=1",
            "1 OR 1=1 -- ",
        ] {
            let leaked = leaks(p);
            // the last one is a real injection: keep it as a sanity check of the list
            if p == "1 OR 1=1 -- " {
                assert!(leaked);
            } else {
                assert!(!leaked, "{p}: {:?}", names(p));
            }
        }
        assert!(
            names("1'")
                .unwrap_err()
                .contains("error in your SQL syntax")
        );
        assert!(names("1 ORDER BY 3").unwrap_err().contains("order clause"));
        assert!(names("1 ORDER BY 2").is_ok());
        assert!(
            names("1 UNION SELECT 1")
                .unwrap_err()
                .contains("different number of columns")
        );
        assert!(
            names("1 UNION SELECT 1,2 FROM nope")
                .unwrap_err()
                .contains("doesn't exist")
        );
    }

    #[test]
    fn functions_and_values() {
        let r = names("0 UNION SELECT version(), database()").unwrap();
        assert_eq!(r, [format!("{VERSION}|shop")]);
        let r = names("0 UNION SELECT char(65,66), length('abc')").unwrap();
        assert_eq!(r, ["AB|3"]);
        assert_eq!(leading_number("12abc"), 12.0);
        assert_eq!(leading_number("abc"), 0.0);
        assert!(like("Burr grinder", "%GRIND%"));
        assert!(!like("Burr", "B_"));
    }
}
