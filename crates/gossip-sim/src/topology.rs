//! Peer graphs for one run.
//!
//! A degree-k graph is sampled, not constructed, so it must be checked: a
//! partitioned graph cannot converge, and a run that failed for that reason
//! would be indistinguishable from a scheme that does not work.

use std::collections::HashSet;

use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};

/// An undirected peer graph over `n` nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topology {
    /// Node count.
    pub n: usize,
    /// Each edge once, with `a < b`.
    pub edges: Vec<(usize, usize)>,
}

impl Topology {
    /// Every pair connected: the baseline, and the most expensive case.
    pub fn complete(n: usize) -> Self {
        let mut edges = Vec::new();
        for a in 0..n {
            for b in (a + 1)..n {
                edges.push((a, b));
            }
        }
        Self { n, edges }
    }

    /// A k-regular graph over `n` nodes, sampled from `seed`: `None` only
    /// when the parameters admit no such graph (`k` zero, `k >= n`, or
    /// `n * k` odd).
    ///
    /// The pairing model alone is not enough for the grid this harness has
    /// to cover. Discarding a whole sample at the first self-loop or
    /// repeated edge succeeds with probability roughly
    /// `exp(-(k-1)/2 - (k-1)^2/4)`, which does not depend on `n` and
    /// collapses in `k`: measured over fifty seeds it found a degree-4 graph
    /// 94% of the time and a degree-8 graph **never**, at every peer count
    /// from 20 to 300. So the bad pairs are repaired instead of rejected —
    /// swapping the endpoints of a bad pair with those of a random other
    /// pair leaves every node's degree untouched, which is the property the
    /// whole degree axis rests on.
    pub fn degree_k(n: usize, k: usize, seed: u64) -> Option<Self> {
        if k == 0 || k >= n || !(n * k).is_multiple_of(2) {
            return None;
        }
        let mut rng = StdRng::seed_from_u64(seed);
        // A sample that resists repair, or that comes out partitioned, is
        // discarded whole and redrawn: both are rare, and a graph that is
        // not connected cannot converge, which would be indistinguishable
        // from a scheme that does not work.
        for _ in 0..32 {
            let mut stubs: Vec<usize> = (0..n)
                .flat_map(|node| std::iter::repeat_n(node, k))
                .collect();
            stubs.shuffle(&mut rng);
            let mut edges: Vec<(usize, usize)> = stubs
                .chunks_exact(2)
                .map(|pair| (pair[0].min(pair[1]), pair[0].max(pair[1])))
                .collect();

            if repair_into_simple(&mut edges, &mut rng) {
                let candidate = Self { n, edges };
                if candidate.is_connected() {
                    return Some(candidate);
                }
            }
        }
        None
    }

    /// The nodes one hop away.
    pub fn neighbours(&self, node: usize) -> Vec<usize> {
        self.edges
            .iter()
            .filter_map(|&(a, b)| match (a, b) {
                (x, y) if x == node => Some(y),
                (x, y) if y == node => Some(x),
                _ => None,
            })
            .collect()
    }

    /// Whether every node is reachable from node 0.
    pub fn is_connected(&self) -> bool {
        if self.n == 0 {
            return true;
        }
        let mut seen = vec![false; self.n];
        let mut stack = vec![0usize];
        seen[0] = true;
        while let Some(node) = stack.pop() {
            for next in self.neighbours(node) {
                if !seen[next] {
                    seen[next] = true;
                    stack.push(next);
                }
            }
        }
        seen.into_iter().all(|s| s)
    }
}

/// Turn a pairing-model sample into a simple graph in place, or report that
/// this sample resisted. Each swap takes one offending pair and one other
/// pair and exchanges their endpoints, which leaves the degree of all four
/// nodes exactly as it was — the invariant that makes this a repair rather
/// than a different sample.
///
/// Returns whether `edges` came out simple: no self-loop, no pair twice.
fn repair_into_simple(edges: &mut [(usize, usize)], rng: &mut StdRng) -> bool {
    // Each swap fixes at most one offending pair, and a fresh sample has
    // only a handful of them, so this bound is a guard against pathological
    // samples rather than the expected amount of work.
    let budget = 8 * edges.len() + 64;
    for _ in 0..budget {
        let Some(bad) = first_offending(edges) else {
            return true;
        };
        let other = rng.gen_range(0..edges.len());
        if other == bad {
            continue;
        }
        let (a, b) = edges[bad];
        let (c, d) = edges[other];
        for (first, second) in [((a, c), (b, d)), ((a, d), (b, c))] {
            let first = (first.0.min(first.1), first.0.max(first.1));
            let second = (second.0.min(second.1), second.0.max(second.1));
            if first.0 == first.1 || second.0 == second.1 || first == second {
                continue;
            }
            let clashes = edges.iter().enumerate().any(|(index, &edge)| {
                index != bad && index != other && (edge == first || edge == second)
            });
            if clashes {
                continue;
            }
            edges[bad] = first;
            edges[other] = second;
            break;
        }
    }
    first_offending(edges).is_none()
}

/// The index of a pair that keeps `edges` from being a simple graph: a
/// self-loop, or the second and later copies of a repeated pair.
fn first_offending(edges: &[(usize, usize)]) -> Option<usize> {
    let mut seen: HashSet<(usize, usize)> = HashSet::with_capacity(edges.len());
    for (index, &(a, b)) in edges.iter().enumerate() {
        if a == b || !seen.insert((a, b)) {
            return Some(index);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_complete_graph_has_every_pair_once() {
        let t = Topology::complete(5);
        assert_eq!(t.edges.len(), 10);
        assert!(t.is_connected());
        assert_eq!(t.neighbours(0).len(), 4);
    }

    #[test]
    fn a_sampled_graph_has_the_requested_degree_and_is_connected() {
        for seed in 0..20u64 {
            let t = Topology::degree_k(20, 4, seed).expect("20 nodes of degree 4 is feasible");
            assert!(t.is_connected(), "seed {seed} produced a partitioned graph");
            for node in 0..20 {
                assert_eq!(t.neighbours(node).len(), 4, "seed {seed}, node {node}");
            }
        }
    }

    /// Every degree the grid sweeps, at both ends of the peer range. The
    /// degree-8 cells are the reason the sampler repairs instead of
    /// rejecting: whole-sample rejection found no degree-8 graph at all, so
    /// this is the test that would have caught the grid being unrunnable.
    #[test]
    fn every_degree_the_grid_sweeps_yields_a_simple_connected_graph() {
        for n in [20usize, 100] {
            for k in [3usize, 4, 8] {
                for seed in 0..10u64 {
                    let t = Topology::degree_k(n, k, seed)
                        .unwrap_or_else(|| panic!("n={n}, k={k}, seed={seed} is feasible"));

                    assert!(t.is_connected(), "n={n}, k={k}, seed={seed}: partitioned");
                    assert_eq!(
                        t.edges.len(),
                        n * k / 2,
                        "n={n}, k={k}, seed={seed}: edge count"
                    );
                    assert!(
                        first_offending(&t.edges).is_none(),
                        "n={n}, k={k}, seed={seed}: self-loop or repeated edge"
                    );
                    for node in 0..n {
                        assert_eq!(
                            t.neighbours(node).len(),
                            k,
                            "n={n}, k={k}, seed={seed}, node={node}: repair must preserve degree"
                        );
                    }
                }
            }
        }
    }

    proptest::proptest! {
        /// The grid test above pins ten seeds at the cells the tables use,
        /// which says a partitioned draw was not SEEN, not that one cannot
        /// happen. This walks the feasible input space instead, so a degree
        /// or a peer count nothing currently sweeps cannot quietly hand back
        /// a graph that cannot converge.
        #[test]
        fn any_feasible_degree_yields_a_simple_connected_k_regular_graph(
            n in 4usize..60,
            k in 2usize..12,
            seed: u64,
        ) {
            proptest::prop_assume!(k < n && (n * k).is_multiple_of(2));

            let t = Topology::degree_k(n, k, seed)
                .unwrap_or_else(|| panic!("n={n}, k={k}, seed={seed} is feasible"));

            proptest::prop_assert!(t.is_connected(), "n={}, k={}, seed={}: partitioned", n, k, seed);
            proptest::prop_assert!(
                first_offending(&t.edges).is_none(),
                "n={}, k={}, seed={}: self-loop or repeated edge", n, k, seed
            );
            for node in 0..n {
                proptest::prop_assert_eq!(
                    t.neighbours(node).len(),
                    k,
                    "n={}, k={}, seed={}, node={}: degree not preserved", n, k, seed, node
                );
            }
        }
    }

    #[test]
    fn a_graph_with_two_disjoint_edges_is_not_connected() {
        let t = Topology {
            n: 4,
            edges: vec![(0, 1), (2, 3)],
        };
        assert!(
            !t.is_connected(),
            "two disjoint pairs must not read as one connected graph"
        );
    }

    #[test]
    fn infeasible_degrees_are_refused_rather_than_approximated() {
        assert!(
            Topology::degree_k(5, 5, 0).is_none(),
            "degree must be below n"
        );
        assert!(Topology::degree_k(5, 3, 0).is_none(), "n*k must be even");
    }
}
