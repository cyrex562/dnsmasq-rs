pub const MAXDNAME: usize = 256; // Adjust this value as needed

pub union BigName {
    pub name: [u8; MAXDNAME],
    pub next: *mut BigName, // freelist
}
