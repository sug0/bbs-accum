//! Distribute a [`Secret`] across untrusting parties.
//!
//! ## Protocol
//!
//! This protocol is inspired by
//! [the work of Doerner, Kondi et al](https://eprint.iacr.org/2023/602.pdf).
//!
//! The underlying key distribution mechanism is verifiable
//! secret sharing (`t-of-n`) based on Shamir Secret Sharing,
//! which produces key shares and a global public key, computed
//! from commitments of the untrusting parties.
//!
//! Clients requesting [authentication tokens](crate::AuthenticationToken)
//! must query `t` untrusting parties. The returned authentication tokens
//! should be validated with the [global public key of the
//! system](super::Public).
//!
//! ## Networking
//!
//! No networking is performed, this only implements the state machine
//! of the DKG protocol. The network complexity is O(n^2), since each
//! node needs to send a message to the other n-1 nodes.

use alloc::collections::btree_map::BTreeMap;
use alloc::vec::Vec;
use core::num::NonZeroUsize;

use ff::Field;
use group::Group;

use super::{Public, Secret};

/// Error values of various DKG operations.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DkgError {
    /// Threshold f-of-n is invalid.
    InvalidThreshold,
    /// Id of the party is invalid.
    InvalidId,
    /// Not enough shares have been collecteed yet.
    NotEnoughShares,
}

/// Instance of the DKG protocol.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Dkg<E: pairing::Engine> {
    id: NonZeroUsize,
    n: NonZeroUsize,
    // degree t-1 (t coefficients)
    polynomial: Vec<E::Fr>,
    shares: BTreeMap<NonZeroUsize, E::Fr>,
}

/// Initialize an instance of the DKG protocol.
///
/// The callback `sample` is used to sample coefficients
/// of a polynomial at the input degree (0..t).
pub fn init<E, F>(
    id: NonZeroUsize,
    t: NonZeroUsize,
    n: NonZeroUsize,
    mut sample: F,
) -> Result<Dkg<E>, DkgError>
where
    E: pairing::Engine,
    F: FnMut(usize) -> E::Fr,
{
    if t.get() > n.get() {
        return Err(DkgError::InvalidThreshold);
    }
    if id.get() > n.get() {
        return Err(DkgError::InvalidId);
    }

    let polynomial = {
        let mut polynomial = Vec::with_capacity(t.get());

        // sample a random polynomial of degree t-1
        for degree in 0..t.get() {
            polynomial.push(sample(degree));
        }

        polynomial
    };
    let shares = {
        let mut shares = BTreeMap::new();
        shares.insert(
            id,
            eval_polynomial_at::<E>((id.get() as u64).into(), &polynomial),
        );
        shares
    };

    Ok(Dkg {
        id,
        n,
        polynomial,
        shares,
    })
}

impl<E: pairing::Engine> Dkg<E> {
    /// Compute all the secret shares to send to the untrusting parties.
    ///
    /// ## Note
    ///
    /// Each returned value is only supposed to be shared with the
    /// intended untrusting party. Only n - 1 values are returned,
    /// corresponding to the other parties.
    pub fn shares_to_send(&self) -> impl Iterator<Item = (NonZeroUsize, E::Fr)> + '_ {
        (1..=self.n.get()).filter_map(|id| {
            if id != self.id.get() {
                Some((
                    NonZeroUsize::new(id).unwrap(),
                    eval_polynomial_at::<E>((id as u64).into(), &self.polynomial),
                ))
            } else {
                None
            }
        })
    }

    /// Compute the secret share to send to `id`.
    ///
    /// ## Note
    ///
    /// The returned value is only intended to be shared with `id`.
    /// Do not share it with other untrusting parties.
    pub fn share_to_send_to(&self, id: NonZeroUsize) -> Result<E::Fr, DkgError> {
        if id > self.n {
            return Err(DkgError::InvalidId);
        }
        Ok(eval_polynomial_at::<E>(
            (id.get() as u64).into(),
            &self.polynomial,
        ))
    }

    /// Receive a secret share from `id`.
    pub fn receive_share_from(&mut self, id: NonZeroUsize, share: E::Fr) -> Result<(), DkgError> {
        if id > self.n || id == self.id {
            return Err(DkgError::InvalidId);
        }
        self.shares.insert(id, share);
        Ok(())
    }

    /// Check if we have collected all the necessary shares.
    #[inline]
    pub fn has_collected_enough_shares(&self) -> bool {
        self.shares.len() == self.n.get()
    }

    /// Attempt to assemble the DKG secret share.
    ///
    /// ## Note
    ///
    /// This fails if not enough shares have been collected yet.
    pub fn assemble_dkg_secret_share(&self) -> Result<Secret<E>, DkgError> {
        if !self.has_collected_enough_shares() {
            return Err(DkgError::NotEnoughShares);
        }

        Ok(Secret::from_prime_field(
            self.shares
                .values()
                .fold(<E::Fr as Field>::ZERO, |accum, share| accum + share),
        ))
    }
}

/// Assemble the global public key, from a set of t public key shares.
pub fn assemble_public_key<E>(shares: &BTreeMap<NonZeroUsize, Public<E>>) -> Public<E>
where
    E: pairing::Engine,
{
    shares
        .iter()
        .map(|(id, pk_share)| {
            let gamma = lagrange_basis::<E>(*id, shares.keys().copied());

            Public {
                pk_g1: pk_share.pk_g1 * gamma,
                pk_g2: pk_share.pk_g2 * gamma,
            }
        })
        .fold(
            Public {
                pk_g1: E::G1::identity(),
                pk_g2: E::G2::identity(),
            },
            |accum, pk| accum + pk,
        )
}

fn eval_polynomial_at<E>(x: E::Fr, coeffs: &[E::Fr]) -> E::Fr
where
    E: pairing::Engine,
{
    let mut res = coeffs[0];
    let mut pow = <E::Fr as Field>::ONE;

    for coeff in coeffs[1..].iter().copied() {
        pow *= x;
        res += coeff * pow;
    }

    res
}

fn lagrange_basis<E: pairing::Engine>(
    id: NonZeroUsize,
    t_ids: impl IntoIterator<Item = NonZeroUsize>,
) -> E::Fr {
    let id_fr: E::Fr = (id.get() as u64).into();

    t_ids
        .into_iter()
        .filter(|other_id| id != *other_id)
        .map(|other_id| {
            let other_id_fr: E::Fr = (other_id.get() as u64).into();
            (id_fr - other_id_fr).invert().unwrap() * -other_id_fr
        })
        .fold(<E::Fr as Field>::ONE, |accum, term| accum * term)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    #[test]
    fn test_dkg() {
        let mut rng = ChaCha20Rng::from_seed([0xba; 32]);

        let mut dkgs: BTreeMap<_, _> = (1usize..=4)
            .map(|id| {
                (
                    id,
                    init::<blstrs::Bls12, _>(
                        NonZeroUsize::new(id).unwrap(),
                        NonZeroUsize::new(2).unwrap(), // t
                        NonZeroUsize::new(4).unwrap(), // n
                        |_degree| blstrs::Scalar::random(&mut rng),
                    )
                    .unwrap(),
                )
            })
            .collect();

        // simulate sending shares
        for id in 1usize..=4 {
            let shares_to_send = dkgs[&id].shares_to_send().collect::<Vec<_>>();

            for (counterparty_id, share) in shares_to_send {
                dkgs.get_mut(&counterparty_id.get())
                    .unwrap()
                    .receive_share_from(NonZeroUsize::new(id).unwrap(), share)
                    .unwrap();
            }
        }

        // assemble secret shares
        let secret_shares: BTreeMap<_, _> = (1usize..=4)
            .map(|id| (id, dkgs[&id].assemble_dkg_secret_share().unwrap()))
            .collect();

        // compute the global pk
        let public_shares_subset = secret_shares
            .iter()
            .take(2)
            .map(|(id, s)| (NonZeroUsize::new(*id).unwrap(), s.public()))
            .collect();

        let pk = assemble_public_key(&public_shares_subset);

        // compute the global secret key
        let sk = Secret::from_prime_field(secret_shares.into_iter().fold(
            blstrs::Scalar::from(0u64),
            |accum, (id, share)| {
                let id = NonZeroUsize::new(id).unwrap();
                let gamma =
                    lagrange_basis::<blstrs::Bls12>(id, (1..=4).filter_map(NonZeroUsize::new));

                accum + gamma * share.secret
            },
        ));

        // sign a challenge
        let challenge = blstrs::Scalar::random(&mut rng);
        let token = sk.token(challenge).unwrap();

        // verify challenge
        assert!(pk.authenticate(&token));
    }
}
