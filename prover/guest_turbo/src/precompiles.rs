// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#[no_mangle]
pub extern "C" fn rust_point_evaluation(
    commitment_bytes: &[u8; 48],
    z_bytes: &[u8; 32],
    y_bytes: &[u8; 32],
    proof_bytes: &[u8; 48],
) -> bool {
    use bls12_381::{fp::Fp, fp2::Fp2, pairing, G1Affine, G2Affine, Scalar};

    static KZG_SETUP_G2_1: G2Affine = G2Affine {
        x: Fp2 {
            c0: Fp::from_raw_unchecked([
                0x6120a2099b0379f9,
                0xa2df815cb8210e4e,
                0xcb57be5577bd3d4f,
                0x62da0ea89a0c93f8,
                0x02e0ee16968e150d,
                0x171f09aea833acd5,
            ]),
            c1: Fp::from_raw_unchecked([
                0x11a3670749dfd455,
                0x04991d7b3abffadc,
                0x85446a8e14437f41,
                0x27174e7b4e76e3f2,
                0x7bfa6dd397f60a20,
                0x02fcc329ac07080f,
            ]),
        },
        y: Fp2 {
            c0: Fp::from_raw_unchecked([
                0xaa130838793b2317,
                0xe236dd220f891637,
                0x6502782925760980,
                0xd05c25f60557ec89,
                0x6095767a44064474,
                0x185693917080d405,
            ]),
            c1: Fp::from_raw_unchecked([
                0x549f9e175b03dc0a,
                0x32c0c95a77106cfe,
                0x64a74eae5705d080,
                0x53deeaf56659ed9e,
                0x09a1d368508afb93,
                0x12cf3a4525b5e9bd,
            ]),
        },
        infinity: unsafe { core::mem::transmute(0u8) },
    };

    let z_bytes_le = {
        let mut z_le = *z_bytes;
        z_le.reverse();
        z_le
    };
    let z_opt = Scalar::from_bytes(&z_bytes_le);
    if z_opt.is_none().into() {
        return false;
    }
    let z = z_opt.unwrap();

    let y_bytes_le = {
        let mut y_le = *y_bytes;
        y_le.reverse();
        y_le
    };
    let y_opt = Scalar::from_bytes(&y_bytes_le);
    if y_opt.is_none().into() {
        return false;
    }
    let y = y_opt.unwrap();

    let commitment_opt = G1Affine::from_compressed(commitment_bytes);
    if commitment_opt.is_none().into() {
        return false;
    }
    let commitment = commitment_opt.unwrap();

    let proof_opt = G1Affine::from_compressed(proof_bytes);
    if proof_opt.is_none().into() {
        return false;
    }
    let proof = proof_opt.unwrap();

    let g2_x = G2Affine::generator() * z;
    let x_minus_z = KZG_SETUP_G2_1 - g2_x;
    let g1_y = G1Affine::generator() * y;
    let p_minus_y = commitment - g1_y;

    let p_minus_y_affine = G1Affine::from(p_minus_y);
    let x_minus_z_affine = G2Affine::from(x_minus_z);

    let p1 = pairing(&p_minus_y_affine, &G2Affine::generator());
    let p2 = pairing(&proof, &x_minus_z_affine);
    p1 == p2
}
