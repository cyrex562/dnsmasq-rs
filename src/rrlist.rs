pub struct RrList {
    pub rr: u16,
    pub next: Option<Box<RrList>>,
}