#![deny(dead_code, unused_variables, missing_docs, unused_doc_comments)]
#![allow(unused)]

/*!
# AES-GCM Authenticated Encryption
AES (Advanced Encryption Standard) is a widely used encryption algorithm for
securing data. AES has several _operator modes_, of which we have selected GCM
(Galois/Counter Mode). GCM combines encryption with authentication.
This ensures that the data is confidential, but also mechanisms to verify that
the data hasn’t been tampered with.

# Large Numbers
Working with large cryptographically secure numbers in Rust involves using
crates that provide efficient, secure, and accurate arithmetic for
numbers far beyond the size of standard primitive data types like u64 or
u128. This is essential in cryptographic contexts where numbers can be
hundreds or even thousands of bits long.

Rust does not provide these capabilities natively for large numbers, so we
are going to use the crates; `num-bigint` and `rug`.
num-bigint is beginner-friendly and well-documented.

We will lean heavily on `Biguint` crate to handle common cryptography primitives
and modular operations, such as:
+ large prime numbers : secure generation of large primes
+ modular arithmetic : a mod n in order to ensure that comps stay inside n
+ modular exponentiation : a^b mod n
+ modulo inverse : computing (x^-1 mod n)

# Notes on the use of S, modular exponentiation by squaring
Computing `x^2 mod p` is generally assumed (TODO: citation needed) to be a
_single operation_ that takes _constant time_. For example, one could just look
up the multiplication table, which has only p^2 entries and can be precomputed.
For further elaborations on this important topic:
1. https://en.m.wikipedia.org/wiki/Exponentiation_by_squaring
2. https://math.stackexchange.com/questions/2944032/
why-is-the-algorithm-for-modular-exponentiation-by-squaring-considered-as-poly-t

# Primality Testing
... TODO: Elaborate on the use of rug.
We use the `rug` crate to perform primatlity testing.

# References:
[1] R. L. Rivest, A. Shamir, and D. A. Wagner. 1996. Time-lock Puzzles and
    Timed-release Crypto. Technical Report. Cambridge, MA, USA.

[2] Timothy C. May. Timed-release crypto, February 1993.
    https://cypherpunks.venona.com/date/1993/02/msg00306.html
    and https://cypherpunks.venona.com/date/1993/02/msg00129.html
*/

////////////////////////////////////////////////////////////////////////////////
// Imports
use aes_gcm::{
    aead::{Aead, OsRng},
    Aes256Gcm, Key, KeyInit, Nonce,
};
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::{thread_rng, RngCore};

////////////////////////////////////////////////////////////////////////////////
// Utilities
// TODO: consider removing this or moving it to a separate module.
/// Utility function which does modular exponentiation of Biguint:
/// a^b mod n == (base^exponent) % n
#[allow(dead_code)]
fn mod_exp(base: &BigUint, exponent: &BigUint, modulo: &BigUint) -> BigUint {
    // TODO: Remove the two lines below if base.modpow is Copy.
    // let mod_exp = base.modpow(exponent, modulo);
    // println!("(a^e) mod n = {}", mod_exp);

    base.modpow(exponent, modulo)
}

/// For primality test we use the classic Rabin-Miller test.
#[derive(PartialEq, Debug)]
pub enum Primality {
    /// The number has been confirmed, deterministically, to be prime.
    Prime,
    /// The number is _only probably_ prime.
    /// Using Rabin-Miller we can get the probability as low as we want, but we
    /// can't get it to 0 (Prime).
    /// For deterministic primality testing, see TODO: wiki link.
    Probable,
    /// The number has been confirmed to be a composite number (i.e. not Prime).
    Composite,
}

////////////////////////////////////////////////////////////////////////////////
/// TimeLockPuzzle
///
/// A tuple which representes the time-lock puzzle in its raw form.
//  TODO: elaborate: Parameters represent: TimeLockPuzzle(n, a, t, CK, CM).
struct TimeLockPuzzle {
    _n: BigUint,
    _a: BigUint,
    _t: BigUint,
    _ck: BigUint,
    _cm: Vec<u8>,
}

////////////////////////////////////////////////////////////////////////////////
/// Capsule
///
/// Consists of a Capsule, which can be thought of as a key chain, and a Puzzle.
/// The Puzzle is an encrypted messagecan stored inside the Capsule.
/// __Defition:__ a solver is anyone, attacker or intended recipient, trying to
/// crack the encryption to get the store message inside.
///
/// TODO: improve wording of the following interface desriptoin:
/// The Capsule has the following interface:
/// +  `.create()`
///     - function will generate private keys `p` and `q`, if provided with:
///     `M`: a message,
///     `a`: a constant,
///     `t` : the desired time lock period, and...
///     `s`: assumed squaring power of the solver
///
/// + `.arm()`
///     - will TODO(zero out the private keys `p` and `q`) that were
///     used during the creation of the puzzle, thereby locking the capsule.
///
/// + `.log()`
///     - a method which will print all the steps which where taken during the
///     creation of the Puzzle.
///
// TODO: turn off pub visibility and confirm that p and q are _NOT_ exported.
pub struct Capsule {
    // TODO: consider creating a Default for Capsule, with a:BigUint::from(2:32)
    p: BigUint,
    q: BigUint,
    a: BigUint,
    tlp: Option<TimeLockPuzzle>,
}

impl Default for Capsule {
    fn default() -> Self {
        Capsule {
            p: Capsule::generate_large_random_prime(256u64),
            q: Capsule::generate_large_random_prime(256u64),
            a: BigUint::from(2u32),
            tlp: None,
        }
    }
}

impl Capsule {
    /// We create a new Capsule with a fresh pair of private keys, p and q.
    pub fn new(&self, bits: u64) -> Self {
        // TODO: verify: do we need to assert bits length > 160 here?
        Capsule {
            p: Capsule::generate_large_random_prime(bits),
            q: Capsule::generate_large_random_prime(bits),
            a: BigUint::from(2u32),
            tlp: None,
        }
    }

    /// Utility function in case we need to generate a new pair of private keys.
    fn generate_new_keypair(&mut self, bits: u64) {
        // TODO: verify: do we need to assert bits length > 160 here?
        self.p = Capsule::generate_large_random_prime(bits);
        self.q = Capsule::generate_large_random_prime(bits);
    }

    /// Function to create a puzzle and store it in the capsule.
    /// TODO: elaborate : tuple (n,a,t,ck, cm) represents a time-lock-puzzle.
    fn create_puzzle(
        &self,
        s: &BigUint,
        t: &BigUint,
        _plaintext: &[u8],
        //) -> (BigUint, BigUint, BigUint, BigUint, Vec<u8>) {
    ) -> TimeLockPuzzle {
        // TODO: improve name of phi_n.
        let n = self.compute_composite(&self.p, &self.q);
        let phi_n = self.phi(&self.p, &self.q);
        let t = self.compute_puzzle_strength(s, t);
        // TODO: consider renaming crypto_system_key to aes_gcm_key
        // to makes it clear that the key is part of the AES-GCM key process.

        // TODO:consider changing the type of crypto_system_key to aes_gcm::Key.
        let (crypto_sys_key, ciphertext) =
            self.compute_cm(_plaintext);
        let cipherkey =
            self.compute_ck(&self.a, &phi_n, &t, &n, &crypto_sys_key);

        // Puzzle created.
        TimeLockPuzzle {
            _n: n,
            _a: self.a.clone(),
            _t: t,
            _ck: cipherkey,
            _cm: ciphertext,
        }
    }
}

impl Capsule {
    // TODO: work on next...
    // lock()
    // open()
    // arm();
    // log();
}

impl Capsule {
    /// Returns a large random number of length based on the number of bits
    /// passed as argument. The bit-size is expressed in u64.
    ///
    /// Large is a subjective term, but for our purposes we want to make sure
    /// that the bits length is at least 160 bits.
    ///
    /// # Examples : exampel of use.
    ///
    /// ```
    /// use timed_release_crypto::Capsule;
    /// use num_bigint::{BigUint, RandBigInt};
    /// // Generate two random 256-bit number.
    /// let p: BigUint = Capsule::generate_large_random_number(256u64);
    /// let q: BigUint = Capsule::generate_large_random_number(256u64);
    /// assert_ne!(p,q);
    /// println!("256-bit Random Number P: {}", p);
    /// println!("256-bit Random Number Q: {}", q);
    /// ```
    ///
    /// Panic : This function will panic if passed a bits value below 160.
    ///
    /// Failure : TODO: consider changing return value to Result<BigUint, Err>.
    ///
    /// TODO: clean up: Require modulo 2^32 - see p3, ref[1]
    pub fn generate_large_random_number(bits: u64) -> BigUint {
        // For Time-Lock-Puzzle purposes we want to work with over 159 bits.
        assert!(bits > 159);

        let mut rng = thread_rng();
        let prime_candidate: BigUint = rng.gen_biguint(bits);
        println!("Generated Large Number: {}", prime_candidate);

        // TODO: remove: rand::thread_rng().gen_bigint(bits)
        prime_candidate
    }

    /// Rudimentary probabilistic primality test using Fermat's Primality Test.
    ///
    /// Fermat's Primality Test checks if:
    /// is a random base number, raised to n-1 modulo n, equal to 1?
    /// If true, then the candidate is probably prime. Please note the word
    /// _probably_! If we want to be 100% sure that the candidate is prime, we
    /// need to use a deterministic, rather than probabilistic primality test.
    ///
    /// A deterministic method may be too slow for our purposes. In that case
    /// an alternative is to use the Rabin-Miller primality test.
    ///
    /// TODO: Look up a deterministic primality-test method.
    /// TODO: consider primality to be a feature.
    fn is_probably_prime(candidate: &BigUint) -> bool {
        // Substep 01: check that the candidate is larger than 1.
        if *candidate <= BigUint::from(1u32) {
            return false;
        }

        // Substep 02: Generate a random base number between [1, candidate).
        // 1 <= base < candidate
        let mut rng = thread_rng();
        let base: BigUint = 
            rng.gen_biguint_range(&BigUint::one(), candidate);

        // Substep 03: Compute the modular: base^(candidate-1) % candidate .
        let result = base.modpow(
            &(candidate - BigUint::one()), 
            candidate
        );

        // Substep 04: If the result is 1 then the candidate is probably prime.
        // TODO: consider returning an enum:
        // Primality::Prime,
        // Primality::Probable,
        // Primality::Composite,
        result.is_one()
    }

    fn generate_large_random_prime(bits: u64) -> BigUint {
        // TODO: Bench this loop to see how long 50 runs take.
        loop {
            let prime_candidate = Self::generate_large_random_number(bits);
            if Self::is_probably_prime(&prime_candidate) {
                return prime_candidate;
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    /// Step 01: Generate (and test for primality) two distinct large secret 
    /// prime numbers `P` and `Q` and multiply them together to form the 
    /// composite `n=pq`.
    ///
    fn compute_composite(&self, p: &BigUint, q: &BigUint) -> BigUint {
        // BigUint will panic if subraction reaches into negative numbers.
        assert!(p >= &BigUint::from(0u32) && q >= &BigUint::from(0u32));

        // Ref: [1] page 3. equation (1): n = p*q
        p * q
    }

    ////////////////////////////////////////////////////////////////////////////
    /// Step 02: Compute the Euler Totient: phi(n) = (P-1)*(Q-1).
    /// TODO: lookup: is it possible to write the congruent equal sign?
    /// The Euler Phi Function is used to ...
    /// The formula `a^{phi(m)} is congruent with 1 (mod m)`.
    /// TODO: Explain the mathematics behind using phi funciton.
    ///
    /// # Panic
    /// BigUnit does not support subtraction resulting in a negative number.
    /// We assert that both arguments are positive, instead of panicking.
    fn phi(&self, p: &BigUint, q: &BigUint) -> BigUint {
        // BigUint will panic if subraction reaches into negative numbers.
        assert!(p >= &BigUint::from(0u32) && q >= &BigUint::from(0u32));

        // Ref: [1] page 3. equation (2): phi(n) = (p-1)*(q-1)
        (p - &BigUint::from(1u32)) * (q - &BigUint::from(1u32))
    }

    ////////////////////////////////////////////////////////////////////////////
    /// Step 03: Compute `t=TS`, where:
    /// + T is the prefered approximate period in seconds that the puzzle should
    /// withstand an attempt to decrypt it.
    /// + S is the number of `squarings modulo n` per second that can be 
    /// performed by the agent (attacker/or intended receiver) trying to decrypt 
    /// the message.
    /// 
    /// TODO: question: what should we base our S value on?
    fn compute_puzzle_strength(&self, s: &BigUint, t: &BigUint) -> BigUint {
        // TODO: consider if S needs to be dealt with here.
        let t = s * t;
        t
    }

    ////////////////////////////////////////////////////////////////////////////
    // Step 04: Generate a `random key K` for a conventional cryptosystem.
    // We're using AES-GCM (with a 256-bit key) via the `aes_gcm` crate.
    // The crate provides AES-256-GCM encryption and decryption capabilities.
    fn compute_cm(&self, plaintext: &[u8]) -> (Key<Aes256Gcm>, Vec<u8>) {
        // Substep 01
        // Generate a random 32-byte (256 bit) key for AES_256.
        // We use `OsRng` to generate cryptographically secure random numbers.
        // Note: Key::<Aes256Gcm> is equal to GenericArray<u8, U32>.
        let key: Key<Aes256Gcm> = Aes256Gcm::generate_key(&mut OsRng);
        println!("Generated Key: {:?}", key);

        // Substep 02
        // We generate a random nonce (Number used ONCE), a random 96-bit
        // (12 bytes, [u8;12]) value, that is used to ensure the uniqueness of our
        // encryption operations.
        //
        // TODO: remove the line below if not needed and tests pass.
        // let mut nonce: BigUint = Nonce::generate(&mut OsRng);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = 
            Nonce::from_slice(&nonce_bytes);
        println!("Generated Nonce: {:?}", nonce);

        // Substep 03
        // Encrypt the message M with key K and encryption algoritym AES-GCM
        // AES-GCM is an excellent tool for encryption, key initialization,
        // and random number generation. We use AES-256-GCM to generate keys of
        // length 256 bits to obtain the cipertext: C_M = AES-GCM(K,M).
        //
        // Initialize the AES-GCM cipher with the generated key.
        // Key: A randomly generated 256-bit key used for encryption/decryption.
        let cipher = Aes256Gcm::new(&key);

        // Substep 04
        // The plaintext message `M` is encrypted into ciphertext form, `CM`.
        // The plaintext needs to be in byte form, for example `b"hello"`.
        // Encrypt the plaintext: CM = AES-GCM(K,M), using the nonce and key.
        println!("Plaintext: {:?}", plaintext);

        let cm = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .expect("Encryption failed");
        println!("Ciphertext: {:?}", cm);

        // TODO: consider returning a Result rather than simply doing an assert
        // to check that CM isn't empty.
        assert!(cm.len() > 0);

        // TODO: does the nonce need to be returned/persisted or can we simply
        // discard it for now?
        (key, cm)
    }

    ////////////////////////////////////////////////////////////////////////////
    // Step 05: Pick a random `a module n`, with 1 < a < n, and compute
    // TODO: see which arguments that are actually needed.
    fn compute_ck(
        &self,
        a: &BigUint,
        phi_n: &BigUint,
        t: &BigUint,
        n: &BigUint,
        k: &Key<Aes256Gcm>,
    ) -> BigUint {
        // TODO: consider moving `a` into a global const or part of Capsule.
        // Note: According to Ref. [1] page.4: "Indeed, in practice choosing a
        // fixed value of `a=2` should be safe with high probability".
        //let a: BigUint = BigUint::from(2u32);
        
        // Substep 01
        // Ref: [1] page 4. equation (6): e = 2^t (mod phi(n))
        // TODO: remove line below once confirmed line underneath is correct.
        let e: BigUint = a.modpow(t, phi_n);

        // Substep 02
        // Ref: [1] page 4. equation (7): b = a^e (mod n)
        // TODO: remove line below, once confirmed line underneath is correct.
        let b: BigUint = a.modpow(&e, n);

        // Substep 03
        // Encryption of the public key K is done by computing:
        // Ref: [1] page 4. equation (5): C_K = K + a^2^t (mod n)
        //
        // I faced some challenges here so I'm documenting clarifications.
        // The passed crypto_system_key `k` is of type Key<Aes256Gcm> and is
        // essentially an array of bytes, (GenericArray<u8, U32>).
        // 
        // Before we can perform the operation K + a^2^t (mod n), 
        // where a^2^t is of type BigUint, we need to convert k:Key<Aes256Gcm> 
        // into k:BigUint.
        //
        // We can use the `.as_slice()` method to get the raw byte array,
        // and then use BigUint::from_bytes_be to convert it into a BigUint.
        let ck = (BigUint::from_bytes_be(k.as_slice()) + b) % n;

        ck
    }
} // Capsule

////////////////////////////////////////////////////////////////////////////////
// Tests
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_phi() {
        let p = BigUint::from(631u32);
        let q = BigUint::from(2153u32);
        let c = Capsule::default();

        assert_eq!(c.phi(&p, &q), BigUint::from(1355760u32));
    }

    #[test]
    fn test_bit_size_of_generated_number() {
        let bits = 256;
        let p = Capsule::generate_large_random_number(bits);

        // Check the number of bits
        let num_bits = p.bits();
        assert!(
            num_bits <= bits && num_bits > bits - 8,
            "The number of bits ({}) is not in the expected range for {} bits.",
            num_bits, bits
        );
    }

    #[test]
    fn test_randomness_of_generated_numbers() {
        let bits = 256;
        let p = Capsule::generate_large_random_number(bits);
        let q = Capsule::generate_large_random_number(bits);

        // TODO: instead of pannicking - simply rerun the generation.
        assert_ne!(
            p, q,
            "The two generated numbers are the same, which is very unlikely."
        );
    }

    #[test]
    fn test_compute_composite() {

        let capsule = Capsule {
            p: BigUint::one(),
            q: BigUint::one(),
            a: BigUint::from(2u32),
            tlp: None,
        };

        // Test values for p and q
        let p = BigUint::from(13u32);
        let q = BigUint::from(17u32);
        // Compute the composite
        let result = capsule.compute_composite(&p, &q);
        // Expected result
        let expected = p.clone() * q.clone();
        // Assert the result matches the expected value
        assert_eq!(result, expected, "The computed composite is incorrect");
    }
}

// END
////////////////////////////////////////////////////////////////////////////////