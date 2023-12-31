use std::ops::Mul;

use blstrs::Scalar;
use ff::Field;
use crate::{evaluation_domain::BatchEvaluationDomain, lagrange::lagrange_coefficients_at_zero};
use super::common::Share;

pub fn reconstruct(shares: &Vec<Share>, players: &Vec<usize>, n:usize) -> (Scalar, Scalar) {
    let batch_dom = BatchEvaluationDomain::new(n);
    let lagr = lagrange_coefficients_at_zero(&batch_dom, players.as_slice());

    let mut s = Scalar::zero();
    let mut r = Scalar::zero();

    let t = shares.len();
    for i in 0..t {
        s += lagr[i].mul(shares[i].share[0]);
        r += lagr[i].mul(shares[i].share[1]);
    }

    (s, r)
}