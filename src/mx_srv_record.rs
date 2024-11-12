pub struct MxSrvRecord {
    pub name: String,
    pub target: String,
    pub issrv: i32,
    pub srvport: i32,
    pub priority: i32,
    pub weight: i32,
    pub offset: u32,
    pub next: Option<Box<MxSrvRecord>>,
}
