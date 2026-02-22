pub struct TxtRecord {
    pub name: String,
    pub txt: Vec<u8>,
    pub class: u16,
    pub len: u16,
    pub stat: i32,
    pub next: Option<Box<TxtRecord>>,
}
