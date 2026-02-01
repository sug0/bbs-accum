use alloc::vec::Vec;

use ff::PrimeField;
use group::GroupEncoding;

use super::{Accumulator, AuthenticationToken, CompressedProof, IncrementalWitness, Proof, Public};

impl<E: pairing::Engine> Accumulator<E> {
    pub fn from_bytes(repr: &<E::G1 as GroupEncoding>::Repr) -> Option<Self> {
        E::G1::from_bytes(repr)
            .into_option()
            .map(|accum| Self { accum })
    }

    pub fn to_bytes(&self) -> <E::G1 as GroupEncoding>::Repr {
        self.accum.to_bytes()
    }
}

impl<E: pairing::Engine> AuthenticationToken<E> {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let key_len = <E::Fr as PrimeField>::Repr::default().as_ref().len();
        let g1_len = <E::G1 as GroupEncoding>::Repr::default().as_ref().len();
        let g2_len = <E::G2 as GroupEncoding>::Repr::default().as_ref().len();

        if bytes.len() != key_len + g1_len + g2_len {
            return None;
        }

        let (key_bytes, rest) = bytes.split_at(key_len);
        let (g1_bytes, g2_bytes) = rest.split_at(g1_len);

        let mut key_repr = <E::Fr as PrimeField>::Repr::default();
        key_repr.as_mut().copy_from_slice(key_bytes);

        let mut g1_repr = <E::G1 as GroupEncoding>::Repr::default();
        g1_repr.as_mut().copy_from_slice(g1_bytes);

        let mut g2_repr = <E::G2 as GroupEncoding>::Repr::default();
        g2_repr.as_mut().copy_from_slice(g2_bytes);

        let key = E::Fr::from_repr(key_repr).into_option()?;
        let auth_g1 = E::G1::from_bytes(&g1_repr).into_option()?;
        let auth_g2 = E::G2::from_bytes(&g2_repr).into_option()?;

        Some(Self {
            key,
            auth_g1,
            auth_g2,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.key.to_repr().as_ref());
        out.extend_from_slice(self.auth_g1.to_bytes().as_ref());
        out.extend_from_slice(self.auth_g2.to_bytes().as_ref());
        out
    }
}

impl<E: pairing::Engine> IncrementalWitness<E> {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let key_len = <E::Fr as PrimeField>::Repr::default().as_ref().len();
        let g1_len = <E::G1 as GroupEncoding>::Repr::default().as_ref().len();

        if bytes.len() != key_len + g1_len + g1_len {
            return None;
        }

        let (key_bytes, rest) = bytes.split_at(key_len);
        let (auth_bytes, witness_bytes) = rest.split_at(g1_len);

        let mut key_repr = <E::Fr as PrimeField>::Repr::default();
        key_repr.as_mut().copy_from_slice(key_bytes);

        let mut auth_repr = <E::G1 as GroupEncoding>::Repr::default();
        auth_repr.as_mut().copy_from_slice(auth_bytes);

        let mut wit_repr = <E::G1 as GroupEncoding>::Repr::default();
        wit_repr.as_mut().copy_from_slice(witness_bytes);

        let key = E::Fr::from_repr(key_repr).into_option()?;
        let auth = E::G1::from_bytes(&auth_repr).into_option()?;
        let witness = E::G1::from_bytes(&wit_repr).into_option()?;

        Some(Self { key, auth, witness })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.key.to_repr().as_ref());
        out.extend_from_slice(self.auth.to_bytes().as_ref());
        out.extend_from_slice(self.witness.to_bytes().as_ref());
        out
    }
}

impl<E: pairing::Engine> Proof<E> {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let fr_len = <E::Fr as PrimeField>::Repr::default().as_ref().len();
        let g1_len = <E::G1 as GroupEncoding>::Repr::default().as_ref().len();
        let g2_len = <E::G2 as GroupEncoding>::Repr::default().as_ref().len();

        let expected_len = fr_len + fr_len + g1_len + g2_len + g1_len;

        if bytes.len() != expected_len {
            return None;
        }

        let (key_bytes, rest) = bytes.split_at(fr_len);
        let (val_bytes, rest) = rest.split_at(fr_len);
        let (ag1_bytes, rest) = rest.split_at(g1_len);
        let (ag2_bytes, wit_bytes) = rest.split_at(g2_len);

        let mut key_repr = <E::Fr as PrimeField>::Repr::default();
        key_repr.as_mut().copy_from_slice(key_bytes);

        let mut val_repr = <E::Fr as PrimeField>::Repr::default();
        val_repr.as_mut().copy_from_slice(val_bytes);

        let mut ag1_repr = <E::G1 as GroupEncoding>::Repr::default();
        ag1_repr.as_mut().copy_from_slice(ag1_bytes);

        let mut ag2_repr = <E::G2 as GroupEncoding>::Repr::default();
        ag2_repr.as_mut().copy_from_slice(ag2_bytes);

        let mut wit_repr = <E::G1 as GroupEncoding>::Repr::default();
        wit_repr.as_mut().copy_from_slice(wit_bytes);

        let key = E::Fr::from_repr(key_repr).into_option()?;
        let value = E::Fr::from_repr(val_repr).into_option()?;
        let auth_g1 = E::G1::from_bytes(&ag1_repr).into_option()?;
        let auth_g2 = E::G2::from_bytes(&ag2_repr).into_option()?;
        let witness = E::G1::from_bytes(&wit_repr).into_option()?;

        Some(Self {
            key,
            value,
            auth_g1,
            auth_g2,
            witness,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.key.to_repr().as_ref());
        out.extend_from_slice(self.value.to_repr().as_ref());
        out.extend_from_slice(self.auth_g1.to_bytes().as_ref());
        out.extend_from_slice(self.auth_g2.to_bytes().as_ref());
        out.extend_from_slice(self.witness.to_bytes().as_ref());
        out
    }
}

impl<E: pairing::Engine> CompressedProof<E> {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let g1_len = <E::G1 as GroupEncoding>::Repr::default().as_ref().len();
        let g2_len = <E::G2 as GroupEncoding>::Repr::default().as_ref().len();

        if bytes.len() != g1_len + g2_len + g1_len {
            return None;
        }

        let (ag1v_bytes, rest) = bytes.split_at(g1_len);
        let (ag2_bytes, wit_bytes) = rest.split_at(g2_len);

        let mut ag1v_repr = <E::G1 as GroupEncoding>::Repr::default();
        ag1v_repr.as_mut().copy_from_slice(ag1v_bytes);

        let mut ag2_repr = <E::G2 as GroupEncoding>::Repr::default();
        ag2_repr.as_mut().copy_from_slice(ag2_bytes);

        let mut wit_repr = <E::G1 as GroupEncoding>::Repr::default();
        wit_repr.as_mut().copy_from_slice(wit_bytes);

        let auth_g1_times_v = E::G1::from_bytes(&ag1v_repr).into_option()?;
        let auth_g2 = E::G2::from_bytes(&ag2_repr).into_option()?;
        let witness = E::G1::from_bytes(&wit_repr).into_option()?;

        Some(Self {
            auth_g1_times_v,
            auth_g2,
            witness,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.auth_g1_times_v.to_bytes().as_ref());
        out.extend_from_slice(self.auth_g2.to_bytes().as_ref());
        out.extend_from_slice(self.witness.to_bytes().as_ref());
        out
    }
}

impl<E: pairing::Engine> Public<E> {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let g1_len = <E::G1 as GroupEncoding>::Repr::default().as_ref().len();
        let g2_len = <E::G2 as GroupEncoding>::Repr::default().as_ref().len();

        if bytes.len() != g1_len + g2_len {
            return None;
        }

        let (pk_g1_bytes, pk_g2_bytes) = bytes.split_at(g1_len);

        let mut pk_g1_repr = <E::G1 as GroupEncoding>::Repr::default();
        pk_g1_repr.as_mut().copy_from_slice(pk_g1_bytes);

        let mut pk_g2_repr = <E::G2 as GroupEncoding>::Repr::default();
        pk_g2_repr.as_mut().copy_from_slice(pk_g2_bytes);

        let pk_g1 = E::G1::from_bytes(&pk_g1_repr).into_option()?;
        let pk_g2 = E::G2::from_bytes(&pk_g2_repr).into_option()?;

        Some(Self { pk_g1, pk_g2 })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.pk_g1.to_bytes().as_ref());
        out.extend_from_slice(self.pk_g2.to_bytes().as_ref());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::Secret;
    use crate::{Accumulator, assemble_proof};
    use blstrs::Bls12;

    #[test]
    fn test_serialization_roundtrip() {
        let secret = Secret::<Bls12>::from_prime_field(123u64.into());
        let token = secret.token(10u64.into()).unwrap();

        // AuthenticationToken
        let bytes = token.to_bytes();
        let recovered = AuthenticationToken::<Bls12>::from_bytes(&bytes).unwrap();

        {
            let AuthenticationToken {
                key: k1,
                auth_g1: ag1_1,
                auth_g2: ag2_1,
            } = token;
            let AuthenticationToken {
                key: k2,
                auth_g1: ag1_2,
                auth_g2: ag2_2,
            } = recovered;
            assert_eq!(k1, k2);
            assert_eq!(ag1_1, ag1_2);
            assert_eq!(ag2_1, ag2_2);
        }

        // Accumulator
        let mut acc = Accumulator::<Bls12>::new();
        let assignment = token.unassigned_key().assign(50u64.into());
        acc.update(&assignment);

        let bytes = acc.to_bytes();
        let recovered = Accumulator::<Bls12>::from_bytes(&bytes).unwrap();

        {
            let Accumulator { accum: a1 } = acc;
            let Accumulator { accum: a2 } = recovered;
            assert_eq!(a1, a2);
        }

        // IncrementalWitness
        let inc_wit = token.incremental_witness();
        let bytes = inc_wit.to_bytes();
        let recovered = IncrementalWitness::<Bls12>::from_bytes(&bytes).unwrap();

        {
            let IncrementalWitness {
                key: k1,
                auth: a1,
                witness: w1,
            } = inc_wit;
            let IncrementalWitness {
                key: k2,
                auth: a2,
                witness: w2,
            } = recovered;
            assert_eq!(k1, k2);
            assert_eq!(a1, a2);
            assert_eq!(w1, w2);
        }

        // Proof
        let proof = assemble_proof(&token, &assignment, &inc_wit.freeze());
        let bytes = proof.to_bytes();
        let recovered = Proof::<Bls12>::from_bytes(&bytes).unwrap();

        {
            let Proof {
                key: k1,
                value: v1,
                auth_g1: ag1_1,
                auth_g2: ag2_1,
                witness: w1,
            } = proof;
            let Proof {
                key: k2,
                value: v2,
                auth_g1: ag1_2,
                auth_g2: ag2_2,
                witness: w2,
            } = recovered;
            assert_eq!(k1, k2);
            assert_eq!(v1, v2);
            assert_eq!(ag1_1, ag1_2);
            assert_eq!(ag2_1, ag2_2);
            assert_eq!(w1, w2);
        }

        // CompressedProof
        let compressed = proof.compress();
        let bytes = compressed.to_bytes();
        let recovered = CompressedProof::<Bls12>::from_bytes(&bytes).unwrap();

        {
            let CompressedProof {
                auth_g1_times_v: av1,
                auth_g2: ag2_1,
                witness: w1,
            } = compressed;
            let CompressedProof {
                auth_g1_times_v: av2,
                auth_g2: ag2_2,
                witness: w2,
            } = recovered;
            assert_eq!(av1, av2);
            assert_eq!(ag2_1, ag2_2);
            assert_eq!(w1, w2);
        }

        // Public
        let public = secret.public();

        let bytes = public.to_bytes();
        let recovered = Public::<Bls12>::from_bytes(&bytes).unwrap();

        {
            let Public {
                pk_g1: pk_g1_orig,
                pk_g2: pk_g2_orig,
            } = public;
            let Public {
                pk_g1: pk_g1_recovered,
                pk_g2: pk_g2_recovered,
            } = recovered;
            assert_eq!(pk_g1_orig, pk_g1_recovered);
            assert_eq!(pk_g2_orig, pk_g2_recovered);
        }
    }
}
