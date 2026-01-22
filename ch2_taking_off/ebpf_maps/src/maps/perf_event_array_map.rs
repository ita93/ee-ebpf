use libbpf_sys::{__u32, BPF_MAP_TYPE_PERF_EVENT_ARRAY, bpf_map_create};
use std::ffi::CString;
use std::{io, mem, ptr};

// BPF_MAP_TYPE_PERF_EVENT_ARRAY
// The Perf Event Array map provides a mechanism to redirect perf events
// (such as hardware counters or software events) into user space using the
// perf ring buffer infrastructure

fn create_perf_event_array_map() -> Result<i32, io::Error> {
    let map_name = CString::new("perf_event_array_example").unwrap();
    let fd = unsafe {
        bpf_map_create(
            BPF_MAP_TYPE_PERF_EVENT_ARRAY,
            map_name.as_ptr(),
            mem::size_of::<i32>() as __u32,
            mem::size_of::<i32>() as __u32,
            64,
            ptr::null(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

pub fn run() {
    match create_perf_event_array_map() {
        Ok(fd) => {
            println!("Created a perf event array map with fd {}", fd);
        }
        Err(e) => {
            eprintln!("Failed to create perf event array map with error {}", e);
        }
    }
}
