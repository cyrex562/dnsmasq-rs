pub struct DynDir {
    pub next: Option<Box<DynDir>>,
    pub files: Option<Box<HostsFile>>,
    pub flags: i32,
    pub dname: String,
    #[cfg(feature = "have_inotify")]
    pub wd: i32, // inotify watch descriptor
}