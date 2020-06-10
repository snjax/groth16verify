pub mod serialization;
pub mod verifier;

use jni::objects::{JClass, JObject, JValue};
use jni::sys::{jboolean, jbyteArray, jlong};
use jni::JNIEnv;

use ff::{Field, PrimeField, PrimeFieldRepr};
use pairing::bn256::{Bn256, Fr, FrRepr};
use pairing::Engine;

use crate::verifier::Proof;

use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Read, Write};
use std::{io, iter, mem};

use crate::serialization::{read_fr_repr_be, read_fr_vec};
use crate::verifier::{verify_proof, TruncatedVerifyingKey};

fn parse_jni_bytes(env: &JNIEnv, jv: jbyteArray) -> Vec<u8> {
    let v_len = env.get_array_length(jv).unwrap() as usize;
    let mut v = vec![0i8; v_len];
    env.get_byte_array_region(jv, 0, &mut v[..]).unwrap();

    unsafe {
        let ptr = v.as_mut_ptr();
        let len = v.len();
        let cap = v.capacity();
        mem::forget(v);
        Vec::from_raw_parts(ptr as *mut u8, len, cap)
    }
}

pub fn groth16_verify(vk: &[u8], proof: &[u8], inputs: &[u8]) -> io::Result<u8> {
    let buff_vk_len = vk.len();
    let buff_proof_len = proof.len();
    let buff_inputs_len = inputs.len();

    if (buff_vk_len % 32 != 0) || (buff_inputs_len % 32 != 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wrong buffer length",
        ));
    }

    let inputs_len = buff_inputs_len / 32;

    if ((buff_vk_len / 32) != (inputs_len + 8)) || (buff_proof_len != 128) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wrong buffer length",
        ));
    }

    let vk = TruncatedVerifyingKey::<Bn256>::read(vk)?;
    let proof = Proof::<Bn256>::read(proof)?;
    let inputs = read_fr_vec::<Fr>(inputs)?;

    if (inputs.len() != inputs_len) || (vk.ic.len() != (inputs_len + 1)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wrong buffer parsing",
        ));
    }

    Ok(verify_proof(&vk, &proof, inputs.as_slice())
        .map(|r| r as u8)
        .unwrap_or(0))
}

#[no_mangle]
pub extern "system" fn Java_com_wavesplatform_zwaves_bn256_Groth16_verify(
    env: JNIEnv,
    class: JClass,
    jvk: jbyteArray,
    jproof: jbyteArray,
    jinputs: jbyteArray,
) -> jboolean {
    let vk = parse_jni_bytes(&env, jvk);
    let proof = parse_jni_bytes(&env, jproof);
    let inputs = parse_jni_bytes(&env, jinputs);

    groth16_verify(&vk, &proof, &inputs).unwrap_or(0u8)
}

#[cfg(test)]
mod local_tests {
    use super::*;
    use base64::decode;

    use pairing::bn256::*;
    use pairing::{CurveProjective, Engine};

    #[test]
    fn test_groth16_verify_binaries_ok() {
        let (vk, proof, inputs) = ("LDCJzjgi5HtcHEXHfU8TZz+ZUHD2ZwsQ7JIEvzdMPYKYs9SoGkKUmg1yya4TE0Ms7x+KOJ4Ze/CPfKp2s5jbniFNM71N/YlHVbNkytLtQi1DzReSh9SNBsvskdY5mavQJe+67PuPVEYnx+lJ97qIG8243njZbGWPqUJ2Vqj49NAunhqX+eIkK3zAB3IPWls3gruzX2t9wrmyE9cVVvf1kgWx63PsQV37qdH0KcFRpCH89k4TPS6fLmqdFxX3YGHCGFTpr6tLogvjbUFJPT98kJ/xck0C0B/s8PTVKdao4VQHT4DBIO8+GB3CQVh6VV4EcMLtDWWNxF4yloAlKcFT0Q4AzJSimpFqd/SwSz9Pb7uk5srte3nwphVamC+fHlJt", "GQPBoHuCPcIosF+WZKE5jZV13Ib4EdjLnABncpSHcMKBZl0LhllnPxcuzExIQwhxcfXvFFAjlnDGpKauQ9OQsjBKUBsdBZnGiV2Sg4TSdyHuLo2AbRRqJN0IV3iH3On8I4ngnL30ZAxVyGQH2EK58aUZGxMbbXGR9pQdh99QaiE=", "IfZhAypdtgvecKDWzVyRuvXatmFf2ZYcMWVkCJ0/MQo=");

        let vk = decode(vk).unwrap();
        let proof = decode(proof).unwrap();
        let inputs = decode(inputs).unwrap();

        let res = groth16_verify(&vk, &proof, &inputs).unwrap_or(0) != 0;
        assert!(res, "groth16_verify should be true");
    }
}
