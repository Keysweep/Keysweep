pub const RED: &str = "\x1b[91m";
pub const MAGENTA: &str = "\x1b[35m";
pub const CYAN: &str = "\x1b[96m";
pub const GREEN: &str = "\x1b[92m";
pub const YELLOW: &str = "\x1b[93m";
pub const RESET: &str = "\x1b[0m";
pub const GRAY: &str = "\x1b[90m";
pub const BG_YELLOW: &str = "\x1b[43m";

const BANNER: &str = r#"
  _  __    {Y} ___ {R}                          
 | |/ /___ {Y}/ _ \{R}____ __ _____ ___ _ __
 | ' </ -_){Y} |_|{R}(_-< V  V / -_) -_) '_ \
 |_|\_\___|{Y}\   {R}/__/\_/\_/\___\___| .__/
           {Y} | |_ {R}                |_|   
           {Y} | |_/{R}
           {Y} | |_ {R}
           {Y} |_|_/{R}"#;

pub fn print_banner() {
    println!("{}", BANNER.replace("{Y}", YELLOW).replace("{R}", RESET));
}
