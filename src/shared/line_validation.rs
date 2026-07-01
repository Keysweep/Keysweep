use crate::shared::args::WordlistFilter;

pub fn is_valid_line(line: &str, filter: WordlistFilter) -> bool {
    if filter.skip_empty && line.is_empty() {
        return false;
    }

    let length = line.chars().count();
    if let Some(min_len) = filter.min_len
        && length < min_len
    {
        return false;
    }
    if let Some(max_len) = filter.max_len
        && length > max_len
    {
        return false;
    }

    true
}
