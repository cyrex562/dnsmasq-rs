pub struct Naptr {
    pub name: String,
    pub replace: String,
    pub regexp: String,
    pub services: String,
    pub flags: String,
    pub order: u32,
    pub pref: u32,
    pub next: Option<Box<Naptr>>,
}