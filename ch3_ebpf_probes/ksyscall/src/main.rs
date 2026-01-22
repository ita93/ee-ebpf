mod bpf;
use std::ffi::CStr;
use std::io;
use std::mem::MaybeUninit;
use std::time::Duration;

use anyhow::Result;
use bpf::*;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{RingBuffer, RingBufferBuilder};
use plain::{Plain, copy_from_bytes};

unsafe impl Plain for bpf::types::event {}

fn handle_event(data: &[u8]) -> i32 {
    let mut ev = bpf::types::event::default();
    match copy_from_bytes(&mut ev, data) {
        Ok(_) => {
            let cstr = unsafe { CStr::from_ptr(ev.path.as_ptr() as *const u8) };
            let bin_path = cstr.to_str().unwrap();
            println!("[execve] pid: {}, path: {}, argv: ", ev.pid, bin_path);
            ev.argv
                .iter()
                .filter(|argv| argv[0] != '\0' as i8)
                .for_each(|argv| {
                    let cstr = unsafe { CStr::from_ptr(argv.as_ptr() as *const u8) };
                    let argv_str = cstr.to_str().unwrap();
                    print!("{} ", argv_str);
                });
            println!("");
        }
        Err(e) => {
            eprintln!("error happen during copying the data {:?}", e);
            return -1;
        }
    }

    0
}

fn main() -> Result<()> {
    let skel_builder = KsyscallExecveSkelBuilder::default();
    let mut open_obj = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_obj)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    let mut buf_builder = RingBufferBuilder::new();
    buf_builder.add(&skel.maps.rb, handle_event)?;
    let buf = buf_builder.build()?;
    println!("Tracing execve calls... Ctrl+C to exit.\n");

    loop {
        buf.poll(Duration::from_millis(100))?;
    }
}
