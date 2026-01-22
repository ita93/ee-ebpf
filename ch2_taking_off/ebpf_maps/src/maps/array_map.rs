use libbpf_sys::{__u32, BPF_MAP_TYPE_ARRAY, bpf_map_create};
use std::ffi::CString;
use std::{io, mem, ptr};

// BPF_MAP_TYPE_ARRAY
// stores a fixed number of elements indexed by integer keys.
// Allow constant time index access.
// Suitable for scenario that the amount of data are known in advanced.
// Typical uses include lookup tables, static configuration data, or indexing CPU-related counters by CPU number.

fn create_array_map() -> Result<i32, io::Error> {
    let map_name = CString::new("array_map_example").unwrap();

    let fd = unsafe {
        // I think this is just a wrapper create by gen
        bpf_map_create(
            BPF_MAP_TYPE_ARRAY,
            map_name.as_ptr(),
            mem::size_of::<i32>() as __u32,
            mem::size_of::<i32>() as __u32,
            256,         // max_entries
            ptr::null(), // map flags
        )
    };

    if fd < 0 {
        // Capture the Os errorno
        return Err(io::Error::last_os_error());
    }

    Ok(fd)
}

pub fn run() {
    match create_array_map() {
        Ok(fd) => {
            println!("Array map created successfully with fd: {}", fd);

            // In Rust, we should explicitly close the FD or wrap it in
            // an OwnedFd to close it automatically when it drops.
            // For this direct translation, we'll use libc::close.
            unsafe { libc::close(fd) };
        }
        Err(e) => {
            eprintln!("Failed to create array map: {}", e);
        }
    }
}
