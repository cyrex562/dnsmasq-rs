pub struct Cname {
    pub ttl: i32,
    pub flag: i32,
    pub alias: String,
    pub target: String,
    pub next: Option<Box<Cname>>,
    pub targetp: Option<Box<Cname>>,
}
