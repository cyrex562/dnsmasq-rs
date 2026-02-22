pub struct RaInterface {
    pub name: *mut libc::c_char,
    pub mtu_name: *mut libc::c_char,
    pub interval: i32,
    pub lifetime: i32,
    pub prio: i32,
    pub mtu: i32,
    pub next: *mut RaInterface,
}