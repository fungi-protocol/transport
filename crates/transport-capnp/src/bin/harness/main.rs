//! Generic peer driver for the NixOS VM test network.
//!
//! Lives in the capnp crate because it drives every backend the same way: as a
//! plugin subprocess reached over capnp-rpc (`connect_plugin`). It links no
//! backend crate, so the transport-boundary rule (`capnp` never depends on a
//! backend) holds.

mod run;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let cli = match run::parse_args(std::env::args().collect()) {
        Ok(cli) => cli,
        Err(e) => {
            eprintln!("fungi-harness: {e}");
            std::process::exit(2);
        }
    };
    if let Err(e) = run::run(cli).await {
        eprintln!("fungi-harness: {e}");
        std::process::exit(1);
    }
}
