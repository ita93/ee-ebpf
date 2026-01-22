mod bpf;
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::time::Duration;

use anyhow::Result;
use bpf::*;
use libbpf_rs::PerfBufferBuilder;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use plain::Plain;

unsafe impl Plain for bpf::types::event {}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
}

fn handle_event(_cpu: i32, data: &[u8]) {
    let mut e = bpf::types::event::default();
    plain::copy_from_bytes(&mut e, data).expect("Data buffer was too short");

    let cstr = unsafe { CStr::from_ptr(e.filename.as_ptr() as *const u8) };
    let name = cstr.to_str().unwrap();

    println!("pid: {} , file name: {}, mode: {}", e.pid, name, e.mode);
}

fn main() -> Result<()> {
    let skel_builder = MkdiratSkelBuilder::default();
    let mut open_obj = MaybeUninit::uninit();
    let skel_open = skel_builder.open(&mut open_obj)?;
    let mut skel = skel_open.load()?;
    skel.attach()?;

    println!("Successfully started! Listening for events...\n");

    let perf = PerfBufferBuilder::new(&skel.maps.mkdir)
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    loop {
        perf.poll(Duration::from_millis(1000))?;
    }
}
