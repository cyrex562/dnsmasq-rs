pub struct DhcpNetId {
    pub net: String,
    pub next: Option<Box<DhcpNetId>>,
}

pub struct DhcpNetIdList {
    pub list: Option<Box<DhcpNetId>>,
    pub next: Option<Box<DhcpNetIdList>>,
}