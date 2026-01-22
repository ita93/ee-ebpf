#![feature(str_from_raw_parts)]
mod bpf;
use core::str;
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
    match copy_from_bytes(&mut evt, data) {
        Ok(_) => {
            let pid = evt.pid;
            let cmd_str = unsafe { CStr::from_ptr(evt.command.as_ptr() as *const u8) };
            let mut cmd = cmd_str.to_str().unwrap_or("UNKNOW");
            if cmd.is_empty() {
                println!("a builtin command was execed by pid {} \n", pid);
            } else {
                println!("Command {} execed by pid {} \n", cmd, pid);
            }

            0
        }
        Err(e) => {
            eprintln!("error when handling event {:?}", e);
            -1
        }
    }
}

fn main() -> Result<()> {
    let skel_builder = ShellExecveSkelBuilder::default();
    let mut open_obj = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_obj)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    let mut buf_builder = RingBufferBuilder::new();
    buf_builder.add(&skel.maps.events, handle_event)?;
    let buf = buf_builder.build()?;

    println!("Successfully started! Listening for events...");

    loop {
        buf.poll(Duration::from_millis(100))?;
    }
}
