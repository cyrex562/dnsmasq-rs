use std::fs::OpenOptions;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use std::os::unix::io::AsRawFd;
use std::ffi::CString;
use std::ptr;
use std::os::unix::fs::OpenOptionsExt;

const SERIAL_UNDEF: i32 = -100;
const SERIAL_EQ: i32 = 0;
const SERIAL_LT: i32 = -1;
const SERIAL_GT: i32 = 1;

static mut TIMESTAMP_TIME: Option<time_t> = None;
static mut DAEMON: Option<Daemon> = None;

struct Daemon {
    timestamp_file: Option<String>,
    back_to_the_future: bool,
}

fn count_labels(name: &str) -> i32 {
    if name.is_empty() {
        return 0;
    }

    let num_labels = name.matches('.').count();
    if name.starts_with('.') {
        num_labels as i32
    } else {
        num_labels as i32 + 1
    }
}

fn serial_compare_32(s1: u32, s2: u32) -> i32 {
    if s1 == s2 {
        return SERIAL_EQ;
    }

    if (s1 < s2 && (s2 - s1) < (1 << 31)) || (s1 > s2 && (s1 - s2) > (1 << 31)) {
        return SERIAL_LT;
    }
    if (s1 < s2 && (s2 - s1) > (1 << 31)) || (s1 > s2 && (s1 - s2) < (1 << 31)) {
        return SERIAL_GT;
    }
    SERIAL_UNDEF
}

fn setup_timestamp() -> i32 {
    unsafe {
        let daemon = DAEMON.as_mut().unwrap();
        daemon.back_to_the_future = false;

        if let Some(ref timestamp_file) = daemon.timestamp_file {
            let path = Path::new(timestamp_file);
            if let Ok(metadata) = path.metadata() {
                TIMESTAMP_TIME = Some(metadata.modified().unwrap().duration_since(UNIX_EPOCH).unwrap().as_secs() as time_t);
                if diff_time(TIMESTAMP_TIME.unwrap(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as time_t) <= 0 {
                    let c_timestamp_file = CString::new(timestamp_file.clone()).unwrap();
                    if libc::utimes(c_timestamp_file.as_ptr(), ptr::null()) == -1 {
                        eprintln!("failed to update mtime on {}: {}", timestamp_file, std::io::Error::last_os_error());
                    }
                    daemon.back_to_the_future = true;
                    return 0;
                }
                return 1;
            }

            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
                let fd = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o666)
                    .custom_flags(libc::O_NONBLOCK | libc::O_EXCL)
                    .open(path);
                if let Ok(file) = fd {
                    file.sync_all().unwrap();

                    TIMESTAMP_TIME = Some(1420070400); // 1-1-2015
                    let times = [libc::timeval {
                        tv_sec: TIMESTAMP_TIME.unwrap(),
                        tv_usec: 0,
                    }; 2];
                    let c_timestamp_file = CString::new(timestamp_file.clone()).unwrap();
                    if libc::utimes(c_timestamp_file.as_ptr(), times.as_ptr()) == 0 {
                        if diff_time(TIMESTAMP_TIME.unwrap(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as time_t) <= 0 {
                            daemon.back_to_the_future = true;
                            return 0;
                        }
                        return 1;
                    }
                }
            }
        }
        -1
    }
}

fn is_check_date(curtime: u64) -> bool {
    unsafe {
        let daemon = DAEMON.as_ref().unwrap();
        if let Some(_) = daemon.timestamp_file {
            if !daemon.back_to_the_future && diff_time(TIMESTAMP_TIME.unwrap(), curtime as time_t) <= 0 {
                if libc::utimes(
                    CString::new(daemon.timestamp_file.as_ref().unwrap().clone()).unwrap().as_ptr(),
                    ptr::null(),
                ) != 0 {
                    eprintln!(
                        "failed to update mtime on {}: {}",
                        daemon.timestamp_file.as_ref().unwrap(),
                        std::io::Error::last_os_error()
                    );
                }
                println!("system time considered valid, now checking DNSSEC signature timestamps.");
                daemon.back_to_the_future = true;
                return true;
            }
        }
        false
    }
}

fn diff_time(time1: time_t, time2: time_t) -> i64 {
    time1 as i64 - time2 as i64
}

fn main() {
    unsafe {
        DAEMON = Some(Daemon {
            timestamp_file: Some(String::from("/path/to/timestamp_file")), // Modify as needed
            back_to_the_future: false,
        });
    }

    setup_timestamp();
}