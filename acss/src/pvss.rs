use more_asserts::assert_lt;
use crate::evaluation_domain::{BatchEvaluationDomain, EvaluationDomain};

/// Encodes the *sharing configuration* for a PVSS: i.e., threshold $t$ and the number of players $n$
/// such that any $t$ or more players can reconstruct a dealt secret given a PVSS transcript.
#[derive(Clone)]
pub struct SharingConfiguration {
    /// The reconstruction threshold $t$ that must be exceeded in order to reconstruct the dealt secret; i.e., $t$ or more shares are needed
    pub(crate) t: usize,
    /// The total number of players involved in the PVSS protocol
    pub(crate) n: usize,
    /// Evaluation domain consisting of the $N$th root of unity and other auxiliary information
    /// needed to compute an FFT of size $N$.
    dom: EvaluationDomain,
    /// Batch evaluation domain, consisting of all the $N$th roots of unity (in the scalar field),
    /// where N is the smallest power of two such that n <= N.
    batch_dom: BatchEvaluationDomain,
}


/// An identifier from 0 to n-1 for the n players involved in the PVSS protocol.
#[derive(PartialEq, Eq, Clone)]
pub struct Player {
    /// A number from 0 to n-1.
    pub(crate) id: usize,
}

impl SharingConfiguration {

    /// Creates a new $t$ out of $n$ secret sharing configuration where any subset of $t$ or more
    /// players can reconstruct the secret.
    pub fn new(t: usize, n: usize) -> Self {
        let batch_dom = BatchEvaluationDomain::new(n);
        let dom = batch_dom.get_subdomain(n);
        SharingConfiguration {
            n,
            t,
            dom,
            batch_dom,
        }
    }

    /// Creates a new player ID; a number from 0 to `pp.n - 1` (inclusive).
    pub fn get_player(&self, i: usize) -> Player {
        assert_lt!(i, self.n);

        Player {
            id: i
        }
    }

    /// Returns the threshold $t$. Recall that $\ge t$ shares are needed to reconstruct.
    pub fn get_threshold(&self) -> usize { self.t }

    pub fn get_total_num_players(&self) -> usize { self.n }

    pub fn get_batch_evaluation_domain(&self) -> &BatchEvaluationDomain { &self.batch_dom }

    pub fn get_evaluation_domain(&self) -> &EvaluationDomain { &self.dom }
}
