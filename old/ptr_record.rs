pub struct PtrRecord {
    pub name: String,
    pub ptr: String,
    pub next: Option<Box<PtrRecord>>,
}