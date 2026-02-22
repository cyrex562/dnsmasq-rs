pub struct HostsFile {
    pub next: Option<Box<HostsFile>>,
    pub flags: i32,
    pub fname: String,
    pub index: u32, // matches to cache entries for logging
}