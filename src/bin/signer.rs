/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2023 Wojtek Porczyk <woju@invisiblethingslab.com>
 */

use openssl::bn::BigNum;

use std::io::{Read, Write};
use std::convert::TryInto;

const SGX_RSA_KEY_SIZE: u32 = 3072;
const SGX_RSA_PUBLIC_EXPONENT: u32 = 3;

fn main() {
    let mut data = [0u8; 256];
    std::io::stdin().lock().read_exact(&mut data).unwrap_or_else(|err| {
        eprintln!("error reading data: {}", err);
        std::process::exit(1);
    });

    let rsa = openssl::rsa::Rsa::generate_with_e(
        SGX_RSA_KEY_SIZE,
        &BigNum::from_u32(SGX_RSA_PUBLIC_EXPONENT).unwrap()
    ).unwrap_or_else(|err| {
        eprintln!("failed to generate RSA private key: {}", err);
        std::process::exit(1);
    });

    let mut modulus = rsa.n().to_vec();
    modulus.splice(..0, std::iter::repeat(0u8).take(384 - modulus.len()));
    let modulus: [u8; 384] = modulus.try_into().unwrap();
    let modulus_le: Vec<u8> = modulus.iter().copied().rev().collect();
    let modulus_le: [u8; 384] = modulus_le.try_into().unwrap();

    let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
    let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &pkey)
        .unwrap();
    signer.set_rsa_padding(openssl::rsa::Padding::PKCS1).unwrap();

    let mut signature = [0u8; 384];
    signer.update(&data).unwrap();
    signer.sign(&mut signature).unwrap();

    let mrsigner = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), &modulus_le)
        .unwrap();
    let mut user_report_data = [0u8; 64];
    user_report_data[0..32].copy_from_slice(&mrsigner);

    let quote = match std::fs::write("/dev/attestation/user_report_data", user_report_data) {
        Err(err) => {
            eprintln!("failed to write user_report_data: {}; returning 0 quote", err);
            vec![0u8; 1]
        }
        Ok(_) => {
            std::fs::read("/dev/attestation/quote").unwrap_or_else(|err| {
                eprintln!("failed to read quote: {}", err);
                std::process::exit(1);
            })
        }
    };

    let mut stdout = std::io::stdout();
    stdout.write(&modulus).unwrap();
    stdout.write(&signature).unwrap();
    stdout.write(&quote).unwrap();
}
