use std::env;

mod maps;
use maps::*;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} Map type (hash, array, ...)", args[0]);
        std::process::exit(1);
    }

    let arg1 = &args[1];
    match arg1.as_str() {
        "hash" => {
            hash_map::run();
        }
        "percpu_hash" => {
            per_cpu_hash_map::run();
        }
        "array" => {
            array_map::run();
        }
        "perf_event_array" => {
            perf_event_array_map::run();
        }
        "prog_array" => {
            prog_array_map::run();
        }
        _ => {
            eprintln!("unsupported map type");
        }
    }
}
