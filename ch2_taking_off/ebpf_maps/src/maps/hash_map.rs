use libbpf_sys::{__u32, BPF_MAP_TYPE_HASH, bpf_map_create};
use std::ffi::CString;
use std::{io, mem, ptr};

// BPF_MAP_TYPE_HASH
// store key-value pairs
// Both key and value have fixed size at creation time.
// Fast lookup/update -> greate choice for data that update frequently.
// Common uses include tracking connection states in networking, counting
// events keyed by process ID or file descriptor, or caching metadata for quick lookups.

fn create_hash_map() -> Result<i32, io::Error> {
    let map_name = CString::new("hash_map_example").unwrap();

    // We use an unsafe block because we are calling a C function directly.
    let fd = unsafe {
        bpf_map_create(
            BPF_MAP_TYPE_HASH,
            map_name.as_ptr(),
            mem::size_of::<i32>() as __u32,
            mem::size_of::<i32>() as __u32,
            1024,        // max_entries
            ptr::null(), // opts (matches the NULL in your C code)
        )
    };

    if fd < 0 {
        // Capture the OS error (errno) if the call failed
        return Err(io::Error::last_os_error());
    }

    Ok(fd)
}

pub fn run() {
    match create_hash_map() {
        Ok(fd) => {
            println!("Hash map created successfully with fd: {}", fd);

            // In Rust, we should explicitly close the FD or wrap it in
            // an OwnedFd to close it automatically when it drops.
            // For this direct translation, we'll use libc::close.
            unsafe { libc::close(fd) };
        }
        Err(e) => {
            eprintln!("Failed to create hash map: {}", e);
        }
    }
}
