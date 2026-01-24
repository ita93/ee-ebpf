mod bpf;
use std::{ffi::c_void, io, mem::MaybeUninit, os::fd::AsFd};

use anyhow::Result;
use bpf::*;

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libc::{
    AF_PACKET, ETH_P_ALL, SO_ATTACH_BPF, SOCK_RAW, SOL_SOCKET, setsockopt, socket, socklen_t,
};

fn open_fd() -> Result<i32> {
    unsafe {
        match socket(AF_PACKET, SOCK_RAW, ETH_P_ALL.to_be() as i32) {
            -1 => Err(io::Error::last_os_error().into()),
            fd => Ok(fd),
        }
    }
}

fn main() -> Result<()> {
    let skel_builder = IcmpSkelBuilder::default();
    let mut open_ops = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_ops)?;
    let skel = open_skel.load()?;

    let target_socket_td = open_fd()?;
    let prog_fd = skel.progs.icmp_filter_prog.as_fd();

    match unsafe {
        setsockopt(
            target_socket_td,
            SOL_SOCKET,
            SO_ATTACH_BPF,
            &prog_fd as *const _ as *const c_void,
            size_of_val(&prog_fd) as socklen_t,
        )
    } {
        0 => {
            println!("BPF Attached successfully!");
        }
        _ => {
            println!("Failed to attach BPF, Reason: ");
            return Err(io::Error::last_os_error().into());
        }
    };

    println!("Only ICMP Echo Requests (ping) will be seen by this raw socket.");

    let mut buf = [0u8; 2048];
    loop {
        let n = unsafe {
            libc::read(
                target_socket_td,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };

        if n < 0 {
            let err = io::Error::last_os_error();
            // In case of legitimate interrupts, we can retry
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            eprintln!("read error: {}", err);
            break Ok(());
        } else if n == 0 {
            break Ok(()); // Socket closed
        } else {
            println!("Received {} bytes (ICMP echo request) on this socket", n);
        }
    }
}
