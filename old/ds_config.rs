pub struct DsConfig {
    pub name: String,
    pub digest: String,
    pub digestlen: i32,
    pub class: i32,
    pub algo: i32,
    pub keytag: i32,
    pub digest_type: i32,
    pub next: Option<Box<DsConfig>>,
}
