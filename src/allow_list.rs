pub struct AllowList {
    pub mark: u32,
    pub mask: u32,
    pub patterns: Vec<String>,
    pub next: Option<Box<AllowList>>,
}