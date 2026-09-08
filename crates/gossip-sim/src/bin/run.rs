//! Four tables. The thin slice — 20 peers, complete graph and degree 4,
//! five seeds each — carries per-phase hop depth alongside the redundancy
//! factor. The capacity sweep looks for the point at which the engine can
//! no longer preserve convergence: 20 peers, complete graph and degree 4,
//! one seed, capacity swept over 1, 2, 4, 8 and 32. The dependency table
//! charges the push baseline for what it wastes: bytes of validation
//! dependencies delivered to peers that already held them, swept over the
//! share of peers that are full nodes. The scheme comparison puts push,
//! announce/pull and hybrid on the same workload and the same graph, which
//! is the question the item actually asks.

use std::time::Duration;

use gossip_sim::depth::{hop_depths, origins_of, phase_depths};
use gossip_sim::engine::Engine;
use gossip_sim::engine::run_modelled;
use gossip_sim::report::{Row, render};
use gossip_sim::run::{Outcome, RunConfig, Schedule, run};
use gossip_sim::topology::Topology;
use gossip_sim::workload::{
    ConstructionConfig, DependencyAddressing, OpenBroadcastConfig, ProofFormat, Workload,
};

/// The engine queue bound the first two tables run under. Slices 1 and 2
/// were measured before the bound was an input at all, under the engine's
/// own default, so holding it here is what keeps their rows comparable.
const QUEUE_CAPACITY: usize = 64;

/// Say why a drain did not finish, if it did not.
///
/// `drained: false` in a table says a run hit the operational boundary this
/// harness exists to find without saying which one, and a reader who has to
/// go and reproduce the cell to learn that has been charged for a diagnostic
/// the run already had.
fn note_drain(cell: &str, outcome: &Outcome) {
    if let Some(reason) = &outcome.drain_error {
        eprintln!("{cell}: drain did not finish — {reason}");
    }
}

/// Reduce one outcome to a [`Row`], with hop-depth statistics attached from
/// the same workload that drove the run (see [`gossip_sim::depth`]).
fn row_from(outcome: &Outcome, workload: &Workload, degree: usize, seed: u64) -> Row {
    note_drain(
        &format!("n={} k={degree} seed={seed}", outcome.peers),
        outcome,
    );
    let origins = origins_of(workload.phases());
    let depths = hop_depths(&outcome.events, &origins);
    let phases = phase_depths(&depths, workload.phases(), outcome.peers);
    Row::from_outcome(outcome, degree, seed).with_phase_depths(phases)
}

/// Run one cell and reduce it to a [`Row`].
async fn run_row(
    topology: Topology,
    workload: &Workload,
    capacity: usize,
    queue_capacity: usize,
    degree: usize,
    seed: u64,
) -> Row {
    let outcome = run(RunConfig {
        topology,
        workload: workload.clone(),
        capacity,
        queue_capacity,
        schedule: Schedule::Burst,
        engine: Engine::Push,
    })
    .await;
    row_from(&outcome, workload, degree, seed)
}

/// One scheme on one open-broadcast cell, printed under its own label. The
/// dependency accounting has nothing to say here: validation dependencies
/// belong to a construction, not to coalition information.
async fn open_row(
    label: &str,
    peers: usize,
    degree: usize,
    proofs: ProofFormat,
    schedule: Schedule,
    engine: Engine,
) {
    let seed = 0u64;
    let workload = Workload::open_broadcast(OpenBroadcastConfig {
        peers,
        seed,
        proposal_fraction: 0.3,
        proofs,
    });
    let Some(topology) = Topology::degree_k(peers, degree, seed) else {
        eprintln!("open: no connected degree-{degree} graph on {peers} nodes");
        return;
    };
    let config = RunConfig {
        topology,
        workload: workload.clone(),
        capacity: 4096,
        queue_capacity: 8192,
        schedule,
        engine,
    };
    let outcome = match engine {
        Engine::Push | Engine::AsyncAnnouncePull { .. } => run(config).await,
        _ => run_modelled(config).await,
    };
    let row = match engine {
        Engine::Push | Engine::ModelledPush => row_from(&outcome, &workload, degree, seed),
        Engine::AnnouncePull { .. } | Engine::AsyncAnnouncePull { .. } | Engine::Hybrid { .. } => {
            Row::from_outcome(&outcome, degree, seed)
        }
    };
    print!(
        "{label:<22}{}",
        render(&[row]).lines().nth(1).unwrap_or_default()
    );
    println!();
}

/// One scheme on one construction cell, with the full-node share stated:
/// what a peer knowing an object a priori is actually worth to the scheme,
/// as opposed to what push wastes by not being able to use it.
async fn holder_row(
    label: &str,
    peers: usize,
    legacy_fraction: f64,
    full_node_fraction: f64,
    late_addition_fraction: f64,
    dependencies: DependencyAddressing,
    engine: Engine,
) {
    let seed = 0u64;
    let degree = 4;
    let workload = Workload::construction_with(ConstructionConfig {
        peers,
        seed,
        legacy_fraction,
        full_node_fraction,
        late_addition_fraction,
        dependencies,
        validity_proofs_per_phase: 0,
        late_addition_overhead: 0,
        proofs: ProofFormat::Compact,
    });
    let Some(topology) = Topology::degree_k(peers, degree, seed) else {
        return;
    };
    let config = RunConfig {
        topology,
        workload: workload.clone(),
        capacity: 4096,
        queue_capacity: 8192,
        schedule: Schedule::Staggered { publications: 1 },
        engine,
    };
    let outcome = match engine {
        Engine::Push | Engine::AsyncAnnouncePull { .. } => run(config).await,
        _ => run_modelled(config).await,
    };
    note_drain(label, &outcome);
    print!(
        "{label:<22}{}",
        render(&[Row::from_outcome(&outcome, degree, seed)])
            .lines()
            .nth(1)
            .unwrap_or_default()
    );
    println!();
}

/// One scheme on one construction cell carrying BFT overhead.
async fn bft_row(label: &str, peers: usize, proofs: usize, format: ProofFormat, engine: Engine) {
    let seed = 0u64;
    let degree = 4;
    let workload = Workload::construction_with(ConstructionConfig {
        peers,
        seed,
        legacy_fraction: 0.3,
        full_node_fraction: 0.5,
        late_addition_fraction: 1.0,
        dependencies: DependencyAddressing::Separate,
        validity_proofs_per_phase: proofs,
        late_addition_overhead: 0,
        proofs: format,
    });
    let Some(topology) = Topology::degree_k(peers, degree, seed) else {
        return;
    };
    let config = RunConfig {
        topology,
        workload: workload.clone(),
        capacity: 4096,
        queue_capacity: 8192,
        schedule: Schedule::Staggered { publications: 1 },
        engine,
    };
    let outcome = match engine {
        Engine::Push | Engine::AsyncAnnouncePull { .. } => run(config).await,
        _ => run_modelled(config).await,
    };
    note_drain(label, &outcome);
    print!(
        "{label:<22}{}",
        render(&[Row::from_outcome(&outcome, degree, seed)])
            .lines()
            .nth(1)
            .unwrap_or_default()
    );
    println!();
}

/// One scheme on one cell, printed under its own label: `render` has no
/// column for the scheme, and inventing one would put a name in a table
/// whose every other column is a measurement.
async fn scheme_row(label: &str, peers: usize, degree: usize, seed: u64, engine: Engine) {
    let workload = Workload::construction_with(ConstructionConfig {
        peers,
        seed,
        legacy_fraction: 0.3,
        full_node_fraction: 0.5,
        late_addition_fraction: 1.0,
        dependencies: DependencyAddressing::Separate,
        validity_proofs_per_phase: 0,
        late_addition_overhead: 0,
        proofs: ProofFormat::Compact,
    });
    let Some(topology) = Topology::degree_k(peers, degree, seed) else {
        eprintln!("schemes: no connected degree-{degree} graph on {peers} nodes for seed {seed}");
        return;
    };
    let config = RunConfig {
        topology,
        workload: workload.clone(),
        capacity: 4096,
        queue_capacity: 4096,
        schedule: Schedule::Burst,
        engine,
    };
    let outcome = match engine {
        Engine::Push | Engine::AsyncAnnouncePull { .. } => run(config).await,
        _ => run_modelled(config).await,
    };
    // Hop depth and the dependency accounting both key on the hash of a
    // frame's bytes, so they only speak for schemes that put an object on the
    // wire unwrapped. Announce/pull and hybrid tag their frames, and every
    // such lookup misses — which would render as a confident zero rather than
    // as the absence it is. Their latency is the `rounds` column, and their
    // dependency saving is already inside `per_peer`.
    let row = match engine {
        Engine::Push | Engine::ModelledPush => row_from(&outcome, &workload, degree, seed)
            .with_dependency_accounting(&outcome, &workload),
        Engine::AnnouncePull { .. } | Engine::AsyncAnnouncePull { .. } | Engine::Hybrid { .. } => {
            Row::from_outcome(&outcome, degree, seed)
        }
    };
    print!(
        "{label:<22}{}",
        render(&[row]).lines().nth(1).unwrap_or_default()
    );
    println!();
}

/// Every table this driver can print, in the order it prints them. The whole
/// set costs about a minute and holds a few hundred megabytes at its widest
/// cell, which is more than the machine this is measured on wants to give at
/// once, so a table can be asked for by name.
const TABLES: [&str; 17] = [
    "thin",
    "capacity",
    "deps",
    "scale",
    "schemes",
    "grid",
    "open",
    "schedule",
    "bft",
    "thousand",
    "real",
    "holders",
    "late",
    "late-cost",
    "bundling",
    "bundling-sweep",
    "threshold",
];

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let peers = 20;
    let asked: Vec<String> = std::env::args().skip(1).collect();

    // A name matching nothing would otherwise print an empty run, which
    // reads as a table with no rows — the one outcome a measurement driver
    // must not be able to produce silently.
    for name in asked.iter().filter(|name| *name != "all") {
        assert!(
            TABLES.contains(&name.as_str()),
            "no table named {name:?}; the tables are {TABLES:?}"
        );
    }

    for name in TABLES {
        if !asked.is_empty() && !asked.iter().any(|a| a == name || a == "all") {
            continue;
        }
        match name {
            "thin" => thin(peers).await,
            "capacity" => capacity(peers).await,
            "deps" => deps(peers).await,
            "scale" => scale().await,
            "schemes" => schemes().await,
            "grid" => grid().await,
            "open" => open().await,
            "schedule" => schedule(peers).await,
            "bft" => bft().await,
            "thousand" => thousand().await,
            "real" => real().await,
            "holders" => holders().await,
            "late" => late().await,
            "late-cost" => late_cost().await,
            "bundling" => bundling().await,
            "bundling-sweep" => bundling_sweep().await,
            "threshold" => threshold().await,
            other => unreachable!("{other} is named in TABLES but has no table"),
        }
    }
}

/// The thin table.
async fn thin(peers: usize) {
    println!("thin slice: {peers} peers, complete graph and degree 4, five seeds\n");
    let mut rows = Vec::new();
    for seed in 0..5u64 {
        let workload = Workload::construction(peers, seed);
        rows.push(
            run_row(
                Topology::complete(peers),
                &workload,
                32,
                QUEUE_CAPACITY,
                peers - 1,
                seed,
            )
            .await,
        );

        let degree = 4;
        match Topology::degree_k(peers, degree, seed) {
            Some(sparse) => {
                rows.push(run_row(sparse, &workload, 32, QUEUE_CAPACITY, degree, seed).await)
            }
            None => {
                // A short table with no marker corrupts the spread a reader
                // computes from it, so a dropped row must say so.
                eprintln!(
                    "skipping row: degree_k(n={peers}, k={degree}, seed={seed}) found no \
                 connected degree-{degree} graph on {peers} nodes for this seed"
                );
            }
        }
    }
    print!("{}", render(&rows));
}

/// The capacity table.
async fn capacity(peers: usize) {
    println!("\ncapacity sweep: {peers} peers, complete graph and degree 4, seed 0\n");
    let seed = 0u64;
    let workload = Workload::construction(peers, seed);
    // Generous relative to a healthy run at this scale, which converges in
    // well under a second: a run that has not returned by this deadline is
    // not slow, it is stuck. The engine is meant to end a group outright
    // when a queue can no longer preserve convergence (`converged: false`
    // or `drained: false`, both rendered as ordinary rows) — a run that
    // instead never returns is a different finding, reported here rather
    // than awaited forever.
    let deadline = Duration::from_secs(10);
    let mut sweep_rows = Vec::new();
    for capacity in [1usize, 2, 4, 8, 32] {
        for (degree, topology) in [
            (peers - 1, Topology::complete(peers)),
            (
                4,
                Topology::degree_k(peers, 4, seed).expect("n=20, k=4 is feasible"),
            ),
        ] {
            let attempt = run(RunConfig {
                topology,
                workload: workload.clone(),
                capacity,
                queue_capacity: QUEUE_CAPACITY,
                schedule: Schedule::Burst,
                engine: Engine::Push,
            });
            match tokio::time::timeout(deadline, attempt).await {
                Ok(outcome) => sweep_rows.push(row_from(&outcome, &workload, degree, seed)),
                Err(_) => eprintln!(
                    "capacity sweep: degree={degree} capacity={capacity} seed={seed} did not \
                 return within {deadline:?} — the drain hung rather than the engine ending \
                 the group; no row recorded for this cell"
                ),
            }
        }
    }
    print!("{}", render(&sweep_rows));
}

/// The deps table.
async fn deps(peers: usize) {
    // The share of peers that are full nodes is the one input that decides
    // how much of the dependency traffic was avoidable, and it is an
    // assumption rather than a measurement — so it is swept and the curve
    // reported, not defended at one value. The legacy share stays fixed
    // here: it changes how many BYTES are dependencies at all, which the
    // `dep_bytes` column already shows, while the full-node share changes
    // how many of those bytes were wasted.
    println!(
        "\nvalidation dependencies: {peers} peers, degree 4, legacy_fraction 0.3, \
     five seeds, full_node_fraction swept\n"
    );
    let mut dependency_rows = Vec::new();
    for full_node_fraction in [0.0, 0.5, 1.0] {
        for seed in 0..5u64 {
            let workload = Workload::construction_with(ConstructionConfig {
                peers,
                seed,
                legacy_fraction: 0.3,
                full_node_fraction,
                late_addition_fraction: 1.0,
                dependencies: DependencyAddressing::Separate,
                validity_proofs_per_phase: 0,
                late_addition_overhead: 0,
                proofs: ProofFormat::Compact,
            });
            let degree = 4;
            let Some(topology) = Topology::degree_k(peers, degree, seed) else {
                eprintln!(
                    "skipping row: degree_k(n={peers}, k={degree}, seed={seed}) found no \
                 connected degree-{degree} graph on {peers} nodes for this seed"
                );
                continue;
            };
            let outcome = run(RunConfig {
                topology,
                workload: workload.clone(),
                capacity: 32,
                queue_capacity: QUEUE_CAPACITY,
                schedule: Schedule::Burst,
                engine: Engine::Push,
            })
            .await;
            dependency_rows.push(
                row_from(&outcome, &workload, degree, seed)
                    .with_dependency_accounting(&outcome, &workload),
            );
        }
    }
    print!("{}", render(&dependency_rows));
}

/// The scale table.
async fn scale() {
    let seed = 0u64;
    // A run that has not returned by this deadline is not slow, it is
    // stuck: at the engine's default queue bound the group ends outright,
    // which renders as an ordinary row, so a cell that never returns is a
    // different finding and is reported rather than awaited.
    let deadline = Duration::from_secs(10);
    // The peer count the target scale is described in. One table per
    // engine queue bound, because the bound is not a column: at the
    // engine's own default the group stops finishing somewhere between
    // twenty and forty peers, and the same graphs and workloads converge
    // once the queues are wide. The link buffer is held at 32 throughout,
    // since sweeping it from 32 to 1024 at forty peers changes nothing —
    // it is not the bound that binds on this axis.
    for queue_capacity in [64usize, 512] {
        println!(
            "\nscale: degree 4, seed 0, legacy_fraction 0.3, full_node_fraction 0.5, \
         link capacity 32, engine queue {queue_capacity}\n"
        );
        let mut scale_rows = Vec::new();
        for n in [20usize, 40, 60, 80, 100] {
            let workload = Workload::construction_with(ConstructionConfig {
                peers: n,
                seed,
                legacy_fraction: 0.3,
                full_node_fraction: 0.5,
                late_addition_fraction: 1.0,
                dependencies: DependencyAddressing::Separate,
                validity_proofs_per_phase: 0,
                late_addition_overhead: 0,
                proofs: ProofFormat::Compact,
            });
            let degree = 4;
            let Some(topology) = Topology::degree_k(n, degree, seed) else {
                eprintln!("scale: no connected degree-{degree} graph on {n} nodes for seed {seed}");
                continue;
            };
            let attempt = run(RunConfig {
                topology,
                workload: workload.clone(),
                capacity: 32,
                queue_capacity,
                schedule: Schedule::Burst,
                engine: Engine::Push,
            });
            match tokio::time::timeout(deadline, attempt).await {
                Ok(outcome) => scale_rows.push(
                    row_from(&outcome, &workload, degree, seed)
                        .with_dependency_accounting(&outcome, &workload),
                ),
                Err(_) => eprintln!(
                    "scale: n={n} queue={queue_capacity} did not return within {deadline:?} — \
                 the drain hung rather than the engine ending the group; no row recorded"
                ),
            }
        }
        print!("{}", render(&scale_rows));
    }
}

/// The schemes table.
async fn schemes() {
    // The comparison the item asks for: the same workload and the same graph
    // under each scheme. The announcement batch sizes are the packet's own
    // order of magnitude: about fifty 32-byte identities fit in 1500 bytes.
    // Bracketed by the degenerate one-per-frame case so the cost of framing
    // is visible rather than assumed.
    for n in [20usize, 100] {
        println!(
            "\nschemes: {n} peers, degree 4, five seeds, legacy_fraction 0.3, \
         full_node_fraction 0.5\n"
        );
        println!(
            "scheme                {}",
            render(&[]).lines().next().unwrap_or_default()
        );
        // Five sampled graphs per scheme, not one. For push the byte
        // columns are analytic in (n, k) and cannot move; for
        // announce/pull they are NOT — how much announcement gets
        // suppressed depends on which graph was drawn — so one seed
        // would have left the winning scheme's figure indistinguishable
        // from a single sample.
        for seed in 0..5u64 {
            scheme_row("push (engine)", n, 4, seed, Engine::Push).await;
            scheme_row("push (modelled)", n, 4, seed, Engine::ModelledPush).await;
            for batch in [1usize, 8, 50] {
                scheme_row(
                    &format!("announce/pull b={batch}"),
                    n,
                    4,
                    seed,
                    Engine::AnnouncePull { batch },
                )
                .await;
            }
            for push_below in [200usize, 300, 600] {
                scheme_row(
                    &format!("hybrid b=50 <={push_below}"),
                    n,
                    4,
                    seed,
                    Engine::Hybrid {
                        batch: 50,
                        push_below,
                    },
                )
                .await;
            }
        }
    }
}

/// The degree axis, with the spread across seeds. The factor is analytic
/// in (n, k), so five seeds cannot make it wobble — what the seeds are
/// here for is the columns that are NOT analytic, hop depth above all,
/// and to show that a sampled degree-3 graph converges at all rather than
/// partitioning.
async fn grid() {
    // Degree under both schemes on the same cell. Push's byte columns are
    // analytic in (n, k); announce/pull's are not, which is the whole reason
    // the degree knob needs measuring on this workload rather than inheriting
    // the open network's answer.
    for n in [20usize, 100] {
        for degree in [3usize, 4, 8] {
            println!(
                "\ngrid: {n} peers, degree {degree}, five seeds, legacy_fraction 0.3, \
                 full_node_fraction 0.5\n"
            );
            println!(
                "scheme                {}",
                render(&[]).lines().next().unwrap_or_default()
            );
            for seed in 0..5u64 {
                scheme_row("push", n, degree, seed, Engine::Push).await;
                scheme_row(
                    "announce/pull b=50",
                    n,
                    degree,
                    seed,
                    Engine::AnnouncePull { batch: 50 },
                )
                .await;
            }
        }
    }
}

/// The second setting the item names. More peers, fewer and larger
/// messages, no phases — and the proof format swept, because it is the
/// one axis that could plausibly make the open network want a different
/// policy from a construction.
async fn open() {
    // The naive proof format is only run at a hundred peers. At three
    // hundred on a degree-4 graph push moves `4 + 299*3` = 901 copies of
    // a set that the naive format alone pushes past two megabytes, which
    // is gigabytes of copying for a cell whose answer the hundred-peer
    // row already gives — the redundancy factor does not depend on the
    // message sizes.
    for (peers, degree, formats) in [
        (
            100usize,
            4usize,
            &[ProofFormat::Compact, ProofFormat::Naive][..],
        ),
        (300, 4, &[ProofFormat::Compact][..]),
        (300, 8, &[ProofFormat::Compact][..]),
    ] {
        for &proofs in formats {
            let format = proofs.label();
            println!(
                "\nopen broadcast: {peers} peers, degree {degree}, proposal_fraction 0.3, \
                 {format} proofs\n"
            );
            println!(
                "scheme                {}",
                render(&[]).lines().next().unwrap_or_default()
            );
            // The MODEL, not the engine, throughout this table. The
            // asynchronous engine does not finish a single one of these
            // cells: an open broadcast publishes its whole set in one
            // phase rather than three, and at a hundred peers on a
            // degree-4 graph that walks straight into the send-path
            // wedge this crate documents — the process sits at zero CPU
            // rather than failing. That is the open finding against
            // `crates/transport`, reached from a new direction (message
            // size and burst, not graph density), and it is out of
            // scope here. The model is byte-identical to the engine
            // wherever both run, so the comparison below stands.
            open_row(
                "push (modelled)",
                peers,
                degree,
                proofs,
                Schedule::Burst,
                Engine::ModelledPush,
            )
            .await;
            // Whether the engine can run this cell at all is now a
            // question about the schedule, not about the scale: fed one
            // publication at a time it does, and in a burst it wedges.
            if peers <= 100 {
                open_row(
                    "push (engine, stag.)",
                    peers,
                    degree,
                    proofs,
                    Schedule::Staggered { publications: 1 },
                    Engine::Push,
                )
                .await;
            }
            open_row(
                "announce/pull b=50",
                peers,
                degree,
                proofs,
                Schedule::Burst,
                Engine::AnnouncePull { batch: 50 },
            )
            .await;
        }
    }
}

/// The producer side of the queue knob. Bytes do not move with it — a
/// test pins that — so what this table is looking for is whether the
/// capacity boundary does: feeding a phase in one publication at a time,
/// draining between each, is the case where the channel is usually empty.
async fn schedule(peers: usize) {
    let seed = 0u64;
    let deadline = Duration::from_secs(10);
    let workload = Workload::construction(peers, seed);
    for schedule in [Schedule::Burst, Schedule::Staggered { publications: 1 }] {
        println!("\nschedule {schedule:?}: {peers} peers, capacity swept, engine queue 64\n");
        let mut rows = Vec::new();
        for capacity in [1usize, 2, 4, 8, 32] {
            for (degree, topology) in [
                (peers - 1, Topology::complete(peers)),
                (
                    4,
                    Topology::degree_k(peers, 4, seed).expect("n=20, k=4 is feasible"),
                ),
            ] {
                let attempt = run(RunConfig {
                    topology,
                    workload: workload.clone(),
                    capacity,
                    queue_capacity: QUEUE_CAPACITY,
                    schedule,
                    engine: Engine::Push,
                });
                match tokio::time::timeout(deadline, attempt).await {
                    Ok(outcome) => rows.push(row_from(&outcome, &workload, degree, seed)),
                    Err(_) => eprintln!(
                        "schedule {schedule:?}: degree={degree} capacity={capacity} did not \
                         return within {deadline:?}"
                    ),
                }
            }
        }
        print!("{}", render(&rows));
    }
}

/// The construction workload at the message count the target scale is
/// described in. Staggered, because a burst of this much traffic does not
/// get through the engine's send path.
async fn bft() {
    let n = 100;
    // Zero proofs is the happy path; the two formats are the assumption the
    // per-peer figure is most sensitive to, and the budget a constrained
    // device is held to is an absolute figure, not a ratio.
    for (proofs, format) in [
        (0usize, ProofFormat::Compact),
        (3, ProofFormat::Compact),
        (3, ProofFormat::Naive),
    ] {
        println!(
            "\nbft overhead: {n} peers, degree 4, {proofs} validity proofs per peer \
             per phase, {} format\n",
            format.label()
        );
        println!(
            "scheme                {}",
            render(&[]).lines().next().unwrap_or_default()
        );
        bft_row("push (engine)", n, proofs, format, Engine::Push).await;
        bft_row(
            "announce/pull b=50",
            n,
            proofs,
            format,
            Engine::AnnouncePull { batch: 50 },
        )
        .await;
    }
}

/// The open network's own scale. Modelled: the asynchronous engine does
/// not reach a thousand peers, and its own drain is what stops it — every
/// receipt wakes all n waiting tasks. Push is included so the comparison
/// is like for like, since the model reproduces it to the byte wherever
/// both run.
async fn thousand() {
    for degree in [4usize, 8] {
        println!(
            "\nopen broadcast at scale: 1000 peers, degree {degree}, \
             proposal_fraction 0.1, compact proofs\n"
        );
        println!(
            "scheme                {}",
            render(&[]).lines().next().unwrap_or_default()
        );
        for (label, engine) in [
            ("push (modelled)", Engine::ModelledPush),
            ("announce/pull b=50", Engine::AnnouncePull { batch: 50 }),
        ] {
            let seed = 0u64;
            let workload = Workload::open_broadcast(OpenBroadcastConfig {
                peers: 1000,
                seed,
                proposal_fraction: 0.1,
                proofs: ProofFormat::Compact,
            });
            let Some(topology) = Topology::degree_k(1000, degree, seed) else {
                continue;
            };
            let outcome = run_modelled(RunConfig {
                topology,
                workload: workload.clone(),
                capacity: 4096,
                queue_capacity: 8192,
                schedule: Schedule::Burst,
                engine,
            })
            .await;
            print!(
                "{label:<22}{}",
                render(&[Row::from_outcome(&outcome, degree, seed)])
                    .lines()
                    .nth(1)
                    .unwrap_or_default()
            );
            println!();
        }
    }
}

/// The check the recommendation rests on: does announce/pull cost what
/// the model says, when it is built the way the production engine is
/// built? Exact agreement is not expected — push's send count is
/// `k + (n-1)(k-1)` whatever order it runs in, and announcing has no such
/// form — so what this table reports is the size of the gap.
async fn real() {
    for n in [20usize, 40, 100] {
        println!(
            "\nmodel against engine: {n} peers, degree 4, legacy_fraction 0.3, \
             full_node_fraction 0.5\n"
        );
        println!(
            "scheme                {}",
            render(&[]).lines().next().unwrap_or_default()
        );
        scheme_row("push (engine)", n, 4, 0, Engine::Push).await;
        for batch in [1usize, 8, 50] {
            scheme_row(
                &format!("pull b={batch} (model)"),
                n,
                4,
                0,
                Engine::AnnouncePull { batch },
            )
            .await;
            scheme_row(
                &format!("pull b={batch} (engine)"),
                n,
                4,
                0,
                Engine::AsyncAnnouncePull { batch },
            )
            .await;
        }
    }
}

/// The item's own clause: peers request only data they do not already
/// know. The dependency table charges PUSH for what it wastes; this one
/// measures what PULL actually keeps, by moving the share of peers that
/// hold every dependency a priori and watching the traffic move with it.
/// Push cannot use the knowledge at all, so its row must not move.
async fn holders() {
    let n = 100;
    println!("\nholders: {n} peers, degree 4, legacy_fraction 0.3, full_node_fraction swept\n");
    println!(
        "scheme                {}",
        render(&[]).lines().next().unwrap_or_default()
    );
    for full_node_fraction in [0.0, 0.5, 1.0] {
        holder_row(
            &format!("push       f={full_node_fraction}"),
            n,
            0.3,
            full_node_fraction,
            1.0,
            DependencyAddressing::Separate,
            Engine::Push,
        )
        .await;
        holder_row(
            &format!("pull b=50  f={full_node_fraction}"),
            n,
            0.3,
            full_node_fraction,
            1.0,
            DependencyAddressing::Separate,
            Engine::AnnouncePull { batch: 50 },
        )
        .await;
    }
}

/// The other half of the same clause, and the one the workload had been
/// answering at its ceiling. An input named in the coalition formation
/// proposal carries a dependency every participant already holds, so
/// separate addressing is worth something only for what is NOT named there.
/// Sweeping the late-addition share moves the traffic between the setting
/// the protocol describes and the ceiling every other table is measured at.
async fn late() {
    let n = 100;
    println!(
        "\nlate additions: {n} peers, degree 4, legacy_fraction 0.3, \
         full_node_fraction 0.5, late_addition_fraction swept\n"
    );
    println!(
        "scheme                {}",
        render(&[]).lines().next().unwrap_or_default()
    );
    for late_addition_fraction in [0.0, 0.25, 0.5, 1.0] {
        holder_row(
            &format!("push       l={late_addition_fraction}"),
            n,
            0.3,
            0.5,
            late_addition_fraction,
            DependencyAddressing::Separate,
            Engine::Push,
        )
        .await;
        holder_row(
            &format!("pull b=50  l={late_addition_fraction}"),
            n,
            0.3,
            0.5,
            late_addition_fraction,
            DependencyAddressing::Separate,
            Engine::AnnouncePull { batch: 50 },
        )
        .await;
    }
}

/// The counterfactual separate addressing rests on. A dependency carried
/// inside the fragment that needs it has no identity, so no peer can decline
/// it and no announcement is spent naming it: addressing it separately is
/// worth exactly what declining saves, less what naming costs. Both arms, at
/// both ends of the late-addition curve, because what a peer can decline is
/// the whole of the difference.
/// What arriving late costs beyond the dependency nobody holds in advance.
///
/// The `late` table above prices a-priori knowledge alone. An input the
/// proposal does not name also has to be proven spendable by a key it does
/// not name, and that proof is an object no peer can decline — so it is
/// charged here rather than folded into the axis it would contaminate.
async fn late_cost() {
    let n = 100;
    println!(
        "\nlate addition overhead: {n} peers, degree 4, legacy_fraction 0.3, \
         full_node_fraction 0.5, late_addition_fraction 1.0\n"
    );
    println!(
        "scheme                {}",
        render(&[]).lines().next().unwrap_or_default()
    );
    for overhead in [0usize, 1, 2] {
        overhead_row(
            &format!("push       o={overhead}"),
            n,
            overhead,
            Engine::Push,
        )
        .await;
        overhead_row(
            &format!("pull b=50  o={overhead}"),
            n,
            overhead,
            Engine::AnnouncePull { batch: 50 },
        )
        .await;
    }
}

async fn overhead_row(label: &str, peers: usize, overhead: usize, engine: Engine) {
    let seed = 0u64;
    let degree = 4;
    let workload = Workload::construction_with(ConstructionConfig {
        peers,
        seed,
        legacy_fraction: 0.3,
        full_node_fraction: 0.5,
        late_addition_fraction: 1.0,
        dependencies: DependencyAddressing::Separate,
        validity_proofs_per_phase: 0,
        late_addition_overhead: overhead,
        proofs: ProofFormat::Compact,
    });
    let Some(topology) = Topology::degree_k(peers, degree, seed) else {
        return;
    };
    let config = RunConfig {
        topology,
        workload: workload.clone(),
        capacity: 4096,
        queue_capacity: 8192,
        schedule: Schedule::Staggered { publications: 1 },
        engine,
    };
    let outcome = match engine {
        Engine::Push | Engine::AsyncAnnouncePull { .. } => run(config).await,
        _ => run_modelled(config).await,
    };
    note_drain(label, &outcome);
    print!(
        "{label:<22}{}",
        render(&[Row::from_outcome(&outcome, degree, seed)])
            .lines()
            .nth(1)
            .unwrap_or_default()
    );
    println!();
}

async fn bundling() {
    let n = 100;
    println!(
        "\nbundled against separate: {n} peers, degree 4, legacy_fraction 0.3, \
         full_node_fraction 0.5\n"
    );
    println!(
        "scheme                {}",
        render(&[]).lines().next().unwrap_or_default()
    );
    for (engine, name) in [
        (Engine::Push, "push"),
        (Engine::AnnouncePull { batch: 50 }, "pull b=50"),
    ] {
        // Bundled ignores the late-addition share: with no identity there is
        // nothing for the proposal to have named.
        holder_row(
            &format!("{name:<10} bundled"),
            n,
            0.3,
            0.5,
            1.0,
            DependencyAddressing::Bundled,
            engine,
        )
        .await;
        for late in [1.0, 0.0] {
            holder_row(
                &format!("{name:<10} separate l={late}"),
                n,
                0.3,
                0.5,
                late,
                DependencyAddressing::Separate,
                engine,
            )
            .await;
        }
    }
}

/// The cell where separate addressing has its best case: every dependency is
/// a whole previous transaction and every peer already holds it, so declining
/// saves the most bytes it ever can. If naming still loses here it loses
/// everywhere.
async fn bundling_sweep() {
    let n = 100;
    println!(
        "\nbundled against separate, legacy_fraction swept: {n} peers, degree 4, \
         full_node_fraction 1.0, late_addition_fraction 0.0, pull b=50\n"
    );
    println!(
        "scheme                {}",
        render(&[]).lines().next().unwrap_or_default()
    );
    for legacy in [0.0, 0.3, 0.7, 1.0] {
        for (mode, name) in [
            (DependencyAddressing::Bundled, "bundled     "),
            (DependencyAddressing::Separate, "separate    "),
            (
                DependencyAddressing::PreviousTransactionsOnly,
                "prev-tx only",
            ),
        ] {
            holder_row(
                &format!("{name} legacy={legacy}"),
                n,
                legacy,
                1.0,
                0.0,
                mode,
                Engine::AnnouncePull { batch: 50 },
            )
            .await;
        }
    }
}

/// Where the hybrid threshold actually sits. The measured fragment sizes
/// are 182 bytes for a segwit input, 178 for an output, 289 for a
/// signature, 31-43 for a prevout and 410-430 for a previous transaction,
/// so a sweep that only visits 200/300/600 steps over most of them.
async fn threshold() {
    let n = 100;
    println!(
        "\nthreshold: {n} peers, degree 4, seed 0, hybrid with batch 50, \
         push_below swept\n"
    );
    println!(
        "scheme                {}",
        render(&[]).lines().next().unwrap_or_default()
    );
    scheme_row("announce all", n, 4, 0, Engine::AnnouncePull { batch: 50 }).await;
    for push_below in [40usize, 50, 120, 190, 200, 250, 300, 450, 600] {
        scheme_row(
            &format!("push<={push_below}"),
            n,
            4,
            0,
            Engine::Hybrid {
                batch: 50,
                push_below,
            },
        )
        .await;
    }
}
