use std::fmt::{self, Write};

pub struct Pretty<'a> {
    out: &'a mut String,
    width: usize,
    indent: usize,
}

impl<'a> Pretty<'a> {
    pub fn new(out: &'a mut String, width: usize) -> Self {
        Self {
            out,
            width,
            indent: 0,
        }
    }

    pub fn indent(mut self, spaces: usize) -> Self {
        self.indent = spaces;
        self
    }

    pub fn field(&mut self, key: &str, value: impl fmt::Display) -> fmt::Result {
        writeln!(
            self.out,
            "{:indent$}{:<width$} : {}",
            "",
            key,
            value,
            indent = self.indent,
            width = self.width,
        )
    }
}

pub fn fmt_vec<T: std::fmt::Display>(v: &[T]) -> String {
    if v.is_empty() {
        "None".into()
    } else {
        v.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}
