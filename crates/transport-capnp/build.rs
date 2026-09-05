//! Compiles `channel.capnp` into Rust before the crate builds.

fn main() {
    capnpc::CompilerCommand::new()
        .file("channel.capnp")
        .run()
        .expect("compiling channel.capnp (needs the `capnp` binary on PATH)");
}
