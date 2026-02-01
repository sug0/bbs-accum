#![no_std]

pub mod authentication;

use ff::Field;
use group::Group;
use group::prime::PrimeCurveAffine;
use pairing::MillerLoopResult;

use self::authentication::{Public, Secret};

/// Assignment of a k:v pair.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Assignment<E: pairing::Engine> {
    key: E::Fr,
    value: E::Fr,
    auth: E::G1,
}

/// Accumulator of k:v pairs.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Accumulator<E: pairing::Engine> {
    accum: E::G1,
}

impl<E: pairing::Engine> Default for Accumulator<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: pairing::Engine> Accumulator<E> {
    /// Create a new [`Accumulator`].
    pub fn new() -> Self {
        Self {
            accum: E::G1::identity(),
        }
    }

    /// Update the accumulator with a new [`Assignment`].
    ///
    /// ## Note
    ///
    /// [Assignments](Assignment) created from different [secrets](self::authentication::Secret)
    /// are homomorphically additive, but it is not correct to add them to
    /// the same [`Accumulator`]!
    pub fn update(&mut self, assignment: &Assignment<E>) {
        self.accum += assignment.auth * assignment.value;
    }
}

impl<E: pairing::MultiMillerLoop> Accumulator<E> {
    /// Check the validity of a [`Proof`] against the current state
    /// of the [`Accumulator`].
    pub fn verify_proof(&self, proof: &Proof<E>) -> bool {
        verify_proof_internal::<E>(
            self.accum,
            proof.auth_g1 * proof.value,
            proof.auth_g2,
            proof.witness,
        )
    }
}

/// Witness built up to a particular assignment.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct FrozenWitness<E: pairing::Engine> {
    witness: E::G1,
}

/// Incrementally built proof of knowledge of a key.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct IncrementalWitness<E: pairing::Engine> {
    key: E::Fr,
    auth: E::G1,
    witness: E::G1,
}

impl<E: pairing::Engine> IncrementalWitness<E> {
    /// Update the incremental witness with a new k:v pair.
    pub fn update(&mut self, assignment: &Assignment<E>) {
        // if inverting succeeds, we implicitly verify that
        // both keys are different, so it's safe to proceed
        // with the witness update
        let Some(key_diff) = (assignment.key - self.key).invert().into_option() else {
            return;
        };

        self.witness += (self.auth - assignment.auth) * (key_diff * assignment.value);
    }

    /// Avoid further updates to this [`IncrementalWitness`].
    pub const fn freeze(self) -> FrozenWitness<E> {
        FrozenWitness {
            witness: self.witness,
        }
    }
}

/// Authentication token created from a [`Secret`]
/// and a given key `k`.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct AuthenticationToken<E: pairing::Engine> {
    key: E::Fr,
    auth_g1: E::G1,
    auth_g2: E::G2,
}

impl<E: pairing::Engine> AuthenticationToken<E> {
    /// Return an empty [`IncrementalWitness`].
    pub fn incremental_witness(self) -> IncrementalWitness<E> {
        IncrementalWitness {
            key: self.key,
            auth: self.auth_g1,
            witness: E::G1::identity(),
        }
    }

    /// Create a new [`UnassignedKey`].
    pub const fn unassigned_key(self) -> UnassignedKey<E> {
        UnassignedKey {
            key: self.key,
            auth: self.auth_g1,
        }
    }
}

impl<E: pairing::MultiMillerLoop> AuthenticationToken<E> {
    /// Checks if an [`AuthenticationToken`] was generated from a given [`Secret`].
    #[inline]
    pub fn authenticate(&self, pk: &Public<E>) -> bool {
        pk.authenticate(self)
    }
}

/// Key that still needs to be assigned a value.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct UnassignedKey<E: pairing::Engine> {
    key: E::Fr,
    auth: E::G1,
}

impl<E: pairing::Engine> UnassignedKey<E> {
    /// Assign zero to this [`UnassignedKey`].
    pub const fn assign_zero(self) -> Assignment<E> {
        self.assign(<E::Fr as Field>::ZERO)
    }

    /// Assign one to this [`UnassignedKey`].
    pub const fn assign_one(self) -> Assignment<E> {
        self.assign(<E::Fr as Field>::ONE)
    }

    /// Assigns a value to this [`UnassignedKey`].
    pub const fn assign(self, value: E::Fr) -> Assignment<E> {
        Assignment {
            key: self.key,
            value,
            auth: self.auth,
        }
    }
}

/// Assign a new k:v pair.
///
/// This operation can fail in the very unlikely scenario that:
///
/// 1. A [`Secret`] is initialized to zero.
/// 2. A zero key value is being set.
#[inline]
pub fn assign<E: pairing::Engine>(
    secret: &Secret<E>,
    key: E::Fr,
    value: E::Fr,
) -> Option<Assignment<E>> {
    secret
        .token(key)
        .into_option()
        .map(|token| token.unassigned_key().assign(value))
}

/// Inclusion or non-inclusion proof of a k:v pair
/// in an [`Accumulator`].
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Proof<E: pairing::Engine> {
    #[allow(dead_code)]
    key: E::Fr,
    value: E::Fr,
    auth_g1: E::G1,
    auth_g2: E::G2,
    witness: E::G1,
}

impl<E: pairing::MultiMillerLoop> Proof<E> {
    /// Check the validity of this [`Proof`] against the current state
    /// of the given [`Accumulator`].
    #[inline]
    pub fn verify(&self, accumulator: &Accumulator<E>) -> bool {
        accumulator.verify_proof(self)
    }

    /// Compress this [`Proof`].
    pub fn compress(&self) -> CompressedProof<E> {
        CompressedProof {
            auth_g1_times_v: self.auth_g1 * self.value,
            auth_g2: self.auth_g2,
            witness: self.witness,
        }
    }
}

/// Compact version of a [`Proof`].
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct CompressedProof<E: pairing::Engine> {
    auth_g1_times_v: E::G1,
    auth_g2: E::G2,
    witness: E::G1,
}

impl<E: pairing::MultiMillerLoop> CompressedProof<E> {
    /// Check the validity of this [`CompressedProof`] against the
    /// current state of the given [`Accumulator`].
    pub fn verify(&self, accum: &Accumulator<E>) -> bool {
        verify_proof_internal::<E>(
            accum.accum,
            self.auth_g1_times_v,
            self.auth_g2,
            self.witness,
        )
    }
}

/// Assemble a new [`Proof`] .
pub const fn assemble_proof<E: pairing::Engine>(
    token: &AuthenticationToken<E>,
    assignment: &Assignment<E>,
    witness: &FrozenWitness<E>,
) -> Proof<E> {
    Proof {
        key: assignment.key,
        value: assignment.value,
        auth_g1: token.auth_g1,
        auth_g2: token.auth_g2,
        witness: witness.witness,
    }
}

#[inline]
fn verify_proof_internal<E: pairing::MultiMillerLoop>(
    accum: E::G1,
    auth_g1_times_v: E::G1,
    auth_g2: E::G2,
    witness: E::G1,
) -> bool {
    let accum_minus_kv = accum - auth_g1_times_v;

    let auth_g2: E::G2Affine = auth_g2.into();
    let auth_g2: E::G2Prepared = auth_g2.into();

    let neg_g2 = (-E::G2Affine::generator()).into();

    E::multi_miller_loop(&[
        (&accum_minus_kv.into(), &auth_g2),
        (&witness.into(), &neg_g2),
    ])
    .final_exponentiation()
    .is_identity()
    .into()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::prelude::rust_2024::*;

    use blstrs::Bls12;

    use super::*;

    #[test]
    fn test_auth() {
        let secret = Secret::<Bls12>::from_prime_field(420u64.into());
        let public = secret.public();

        let tok = secret.token(1u64.into()).unwrap();
        assert!(public.authenticate(&tok));

        let tok = secret.token(2u64.into()).unwrap();
        assert!(public.authenticate(&tok));
    }

    #[test]
    fn test_accum_inclusion() {
        let secret = Secret::<Bls12>::from_prime_field(420u64.into());

        let token_4 = secret.token(4u64.into()).unwrap();
        let token_3 = secret.token(3u64.into()).unwrap();
        let token_2 = secret.token(2u64.into()).unwrap();

        let mut inc_witness_4 = token_4.incremental_witness();
        let mut inc_witness_3 = token_3.incremental_witness();
        let mut inc_witness_2 = token_2.incremental_witness();

        let mut accumulator = Accumulator::new();

        // check that neither 4 nor 3 nor 2 are in the accumulator
        for tok in [&token_4, &token_3, &token_2] {
            let proof = assemble_proof(
                tok,
                &tok.unassigned_key().assign_zero(),
                &tok.incremental_witness().freeze(),
            );
            assert!(accumulator.verify_proof(&proof));
        }

        // add 4:20 to the accumulator
        let assignment = token_4.unassigned_key().assign(20u64.into());
        accumulator.update(&assignment);

        // prove that 4:20 is a valid assignment. we don't need
        // to update inc_witness_4, we only do so if a key different
        // from 4 has been added to the accumulator
        let proof = assemble_proof(&token_4, &assignment, &inc_witness_4.freeze());
        assert!(accumulator.verify_proof(&proof));

        // now let's add a delta of 1, ending up with the assignment 4:21
        let assignment = token_4.unassigned_key().assign(1u64.into());
        accumulator.update(&assignment);

        // 4:1 is **not** a valid assignment
        let proof = assemble_proof(&token_4, &assignment, &inc_witness_4.freeze());
        assert!(!accumulator.verify_proof(&proof));

        // but 4:21 is
        let assignment = token_4.unassigned_key().assign(21u64.into());
        let proof = assemble_proof(&token_4, &assignment, &inc_witness_4.freeze());
        assert!(accumulator.verify_proof(&proof));

        // now let's add a new key to the accumulator, 3:11
        let last_assignment = assignment;
        let assignment = token_3.unassigned_key().assign(11u64.into());
        accumulator.update(&assignment);

        // the proof of 4:21 should fail now, because we haven't
        // updated inc_witness_4
        let proof = assemble_proof(&token_4, &last_assignment, &inc_witness_4.freeze());
        assert!(!accumulator.verify_proof(&proof));

        // as soon as we update inc_witness_4, the proof
        // should be valid
        inc_witness_4.update(&assignment);
        let proof = assemble_proof(&token_4, &last_assignment, &inc_witness_4.freeze());
        assert!(accumulator.verify_proof(&proof));

        // the inclusion proof of 3:11 without
        // updating inc_witness_3 should fail
        let proof = assemble_proof(&token_3, &assignment, &inc_witness_3.freeze());
        assert!(!accumulator.verify_proof(&proof));

        // let's bring inc_witness_3 up to speed
        // and test the proof again
        inc_witness_3.update(&last_assignment);
        let proof = assemble_proof(&token_3, &assignment, &inc_witness_3.freeze());
        assert!(accumulator.verify_proof(&proof));

        // the non-inclusion proof of 2 without
        // updating inc_witness_2 should fail
        let assignment = token_2.unassigned_key().assign_zero();
        let proof = assemble_proof(&token_2, &assignment, &inc_witness_2.freeze());
        assert!(!accumulator.verify_proof(&proof));

        // let's bring inc_witness_2 up to speed
        // and test the proof again
        inc_witness_2.update(&token_4.unassigned_key().assign(21u64.into()));
        inc_witness_2.update(&token_3.unassigned_key().assign(11u64.into()));
        let proof = assemble_proof(&token_2, &assignment, &inc_witness_2.freeze());
        assert!(accumulator.verify_proof(&proof));

        // let's also test a compact proof, for good measure
        assert!(proof.compress().verify(&accumulator));
    }
}
