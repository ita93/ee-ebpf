use libbpf_sys::{__u32, BPF_MAP_TYPE_PROG_ARRAY, bpf_map_create};
use std::ffi::CString;
use std::{io, mem, ptr};

// BPF_TYPE_PROG_ARRAY_MAP
// Hold reference to other ebpf programs, enabling tail call.
// Tail call allow ebpf program to jump to another program with out
// returning.

fn create_prog_array_map() -> Result<i32, io::Error> {
    let map_name = CString::new("prog_array_example").unwrap();

    let fd = unsafe {
        bpf_map_create(
            BPF_MAP_TYPE_PROG_ARRAY,
            map_name.as_ptr(),
            mem::size_of::<i32>() as __u32,
            mem::size_of::<i32>() as __u32,
            32,
            ptr::null(),
        )
    };

    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

pub fn run() {
    match create_prog_array_map() {
        Ok(fd) => {
            println!("Created a prog array map with fd {}", fd);
        }
        Err(e) => {
            eprintln!("Failed to create prog array map with error {}", e);
        }
    }
}
