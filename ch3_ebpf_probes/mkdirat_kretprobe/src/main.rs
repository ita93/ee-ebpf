mod bpf;
use std::{mem::MaybeUninit, thread::sleep, time::Duration};

use anyhow::Result;
use bpf::*;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};

fn main() -> Result<()> {
    let skel_builder = MkdiratRetSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    let mut skel = open_skel.load()?;
    skel.attach()?;
    println!(
        "Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` \
        to see output of the BPF programs.\n"
    );

    loop {
        eprintln!(".");
        sleep(Duration::from_secs(1));
    }
}
