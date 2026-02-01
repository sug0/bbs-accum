//! Trusted parameters of the accumulator commitment scheme.

use core::ops::Add;

use ff::{Field, PrimeField};
use group::Group;
use group::prime::PrimeCurveAffine;
use pairing::MillerLoopResult;
use rand_core::{CryptoRng, RngCore};
use subtle::CtOption;

use super::AuthenticationToken;

/// Public counterpart of a [`Secret`].
///
/// This is only used to [authenticate keys](Public::authenticate).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Public<E: pairing::Engine> {
    pub(crate) pk_g1: E::G1,
    pub(crate) pk_g2: E::G2,
}

impl<E: pairing::Engine> Add for Public<E> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            pk_g1: self.pk_g1 + rhs.pk_g1,
            pk_g2: self.pk_g2 + rhs.pk_g2,
        }
    }
}

impl<E: pairing::MultiMillerLoop> Public<E> {
    /// Checks if an [`AuthenticationToken`] was generated from a given [`Secret`].
    pub fn authenticate(&self, token: &AuthenticationToken<E>) -> bool {
        let challenge_g1: E::G1Affine = (self.pk_g1 + E::G1::generator() * token.key).into();

        let challenge_g2: E::G2Affine = (self.pk_g2 + E::G2::generator() * token.key).into();
        let challenge_g2: E::G2Prepared = challenge_g2.into();

        let g1 = E::G1Affine::generator();
        let neg_g2 = (-E::G2Affine::generator()).into();

        let auth_g2: E::G2Affine = token.auth_g2.into();
        let auth_g2: E::G2Prepared = auth_g2.into();

        E::multi_miller_loop(&[
            (&challenge_g1, &auth_g2),
            (&token.auth_g1.into(), &challenge_g2),
            // TODO: optimize by changing to 2*GT?
            (&g1, &neg_g2),
            (&g1, &neg_g2),
        ])
        .final_exponentiation()
        .is_identity()
        .into()
    }
}

/// Trusted secret of the accumulator commitment scheme.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Secret<E: pairing::Engine> {
    secret: E::Fr,
}

impl<E: pairing::Engine> Add for Secret<E> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            secret: self.secret + rhs.secret,
        }
    }
}

impl<E: pairing::Engine> Secret<E> {
    /// Create a new [`Secret`] from a raw scalar field element.
    pub const fn from_prime_field(secret: E::Fr) -> Self {
        Self { secret }
    }

    /// Randomly sample a new [`Secret`] from a CSRNG.
    pub fn random<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        Self {
            secret: E::Fr::random(rng),
        }
    }

    /// Parse a [`Secret`] from a byte array.
    pub fn from_bytes(repr: <E::Fr as PrimeField>::Repr) -> Option<Self> {
        E::Fr::from_repr(repr)
            .into_option()
            .map(|secret| Self { secret })
    }

    /// Encode a [`Secret`] to a byte array.
    pub fn to_bytes(&self) -> <E::Fr as PrimeField>::Repr {
        self.secret.to_repr()
    }

    /// Return the public counterpart of this [`Secret`].
    pub fn public(&self) -> Public<E> {
        Public {
            pk_g1: E::G1::generator() * self.secret,
            pk_g2: E::G2::generator() * self.secret,
        }
    }

    /// Retrieve a new authentication token, from the given key.
    pub fn token(&self, key: E::Fr) -> CtOption<AuthenticationToken<E>> {
        (self.secret + key)
            .invert()
            .map(|secret_plus_key| AuthenticationToken {
                key,
                auth_g1: E::G1::generator() * secret_plus_key,
                auth_g2: E::G2::generator() * secret_plus_key,
            })
    }
}
