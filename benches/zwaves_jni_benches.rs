#![feature(test)]

extern crate test;
extern crate zwaves_jni;

use base64::{decode, encode};
use test::Bencher;
use zwaves_jni::*;

use pairing::bn256::*;
use pairing::{CurveProjective, Engine};

use ff::{Field, PrimeField, PrimeFieldRepr};

use zwaves_jni::verifier::Proof;

use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Read, Write};
use std::{io, iter, mem};

use zwaves_jni::serialization::{read_fr_repr_be, read_fr_vec};
use zwaves_jni::verifier::{verify_proof, TruncatedVerifyingKey};

use rand::{Rand, SeedableRng, XorShiftRng};
use serialization::write_fr_iter;
use std::io::Cursor;

fn bench_groth16_verify(b: &mut Bencher, ninputs: usize) {
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    const SAMPLES: usize = 1000;

    let v = (0..SAMPLES)
        .map(|_| {
            let vk = TruncatedVerifyingKey::<Bn256> {
                alpha_g1: G1::rand(&mut rng).into_affine(),
                beta_g2: G2::rand(&mut rng).into_affine(),
                gamma_g2: G2::rand(&mut rng).into_affine(),
                delta_g2: G2::rand(&mut rng).into_affine(),
                ic: (0..ninputs + 1)
                    .map(|_| G1::rand(&mut rng).into_affine())
                    .collect::<Vec<_>>(),
            };
            let mut vk_buff = Cursor::new(Vec::<u8>::new());
            vk.write(&mut vk_buff).unwrap();

            let proof = Proof::<Bn256> {
                a: G1::rand(&mut rng).into_affine(),
                b: G2::rand(&mut rng).into_affine(),
                c: G1::rand(&mut rng).into_affine(),
            };
            let mut proof_buff = Cursor::new(Vec::<u8>::new());
            proof.write(&mut proof_buff).unwrap();

            let inputs = (0..ninputs).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            let mut inputs_buff = vec![0u8; 32 * ninputs];
            write_fr_iter(inputs.iter(), &mut inputs_buff).unwrap();
            (
                base64::encode(vk_buff.get_ref()),
                base64::encode(proof_buff.get_ref()),
                base64::encode(&inputs_buff),
            )
        })
        .collect::<Vec<_>>();

    let mut n: usize = 0;

    b.iter(|| {
        let (vk, proof, inputs) = v[n].clone();
        n = (n + 1) % SAMPLES;
        let vk = decode(vk.as_str()).unwrap();
        let proof = decode(proof.as_str()).unwrap();
        let inputs = decode(inputs.as_str()).unwrap();
        groth16_verify(&vk, &proof, &inputs)
    });
}

#[bench]
fn bench_groth16_verify_0(b: &mut Bencher) {
    bench_groth16_verify(b, 0);
}

#[bench]
fn bench_groth16_verify_1(b: &mut Bencher) {
    bench_groth16_verify(b, 1);
}

#[bench]
fn bench_groth16_verify_2(b: &mut Bencher) {
    bench_groth16_verify(b, 2);
}

#[bench]
fn bench_groth16_verify_3(b: &mut Bencher) {
    bench_groth16_verify(b, 3);
}

#[bench]
fn bench_groth16_verify_4(b: &mut Bencher) {
    bench_groth16_verify(b, 4);
}

#[bench]
fn bench_groth16_verify_5(b: &mut Bencher) {
    bench_groth16_verify(b, 5);
}

#[bench]
fn bench_groth16_verify_6(b: &mut Bencher) {
    bench_groth16_verify(b, 6);
}

#[bench]
fn bench_groth16_verify_7(b: &mut Bencher) {
    bench_groth16_verify(b, 7);
}

#[bench]
fn bench_groth16_verify_8(b: &mut Bencher) {
    bench_groth16_verify(b, 8);
}

#[bench]
fn bench_groth16_verify_9(b: &mut Bencher) {
    bench_groth16_verify(b, 9);
}

#[bench]
fn bench_groth16_verify_10(b: &mut Bencher) {
    bench_groth16_verify(b, 10);
}

#[bench]
fn bench_groth16_verify_11(b: &mut Bencher) {
    bench_groth16_verify(b, 11);
}

#[bench]
fn bench_groth16_verify_12(b: &mut Bencher) {
    bench_groth16_verify(b, 12);
}

#[bench]
fn bench_groth16_verify_13(b: &mut Bencher) {
    bench_groth16_verify(b, 13);
}

#[bench]
fn bench_groth16_verify_14(b: &mut Bencher) {
    bench_groth16_verify(b, 14);
}

#[bench]
fn bench_groth16_verify_15(b: &mut Bencher) {
    bench_groth16_verify(b, 15);
}

#[bench]
fn bench_groth16_verify_16(b: &mut Bencher) {
    bench_groth16_verify(b, 16);
}
