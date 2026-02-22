pub struct RebindDomain {
    pub domain: String,
    pub next: Option<Box<RebindDomain>>,
}