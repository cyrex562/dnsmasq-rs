use std::time::SystemTime;

pub struct Resolvc {
    pub next: Option<Box<Resolvc>>,
    pub is_default: i32,
    pub logged: i32,
    pub mtime: SystemTime,
    pub ino: u64,
    pub name: String,
    #[cfg(feature = "have_inotify")]
    pub wd: i32, // inotify watch descriptor
    #[cfg(feature = "have_inotify")]
    pub file: String, // pointer to file part if path
}