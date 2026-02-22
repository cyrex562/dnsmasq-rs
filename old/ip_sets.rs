pub struct Ipsets {
    pub sets: Vec<String>,
    pub domain: String,
    pub next: Option<Box<Ipsets>>,
}