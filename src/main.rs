use soroban_auth::Identifier as IdentifierValue;
use soroban_sdk::{
    bytes, bytesn, symbol,
    testutils::{Ledger, LedgerInfo},
    BigInt, Env,
};
use stellar_strkey::*;
extern crate ed25519_dalek;

mod ed25519_utils {

    use soroban_sdk::Env;

    use soroban_sdk::{testutils::ed25519::Sign, Bytes, IntoVal};

    use soroban_auth::{
        testutils::ed25519::Identifier, Identifier as IdentifierValue, SignaturePayload,
    };

    use core::fmt::Debug;

    extern crate ed25519_dalek;
    extern crate std;

    pub fn generate(
        env: &Env,
    ) -> (
        IdentifierValue,
        Bytes,
        impl soroban_auth::testutils::ed25519::Identifier
            + Sign<SignaturePayload, Signature = [u8; 64]>
            + Debug,
    ) {
        let signer = ed25519_dalek::Keypair::generate(&mut rand::thread_rng());
        (
            IdentifierValue::Ed25519(signer.public.as_bytes().into_val(env)),
            signer.to_bytes().into_val(env),
            signer,
        )
    }

    pub fn build_kp(
        env: &Env,
        public: &[u8],
        secret: &[u8],
    ) -> (
        IdentifierValue,
        impl soroban_auth::testutils::ed25519::Identifier
            + Sign<SignaturePayload, Signature = [u8; 64]>
            + Debug,
    ) {
        let kp = ed25519_dalek::Keypair {
            secret: ed25519_dalek::SecretKey::from_bytes(secret).unwrap(),
            public: ed25519_dalek::PublicKey::from_bytes(public).unwrap(),
        };

        (kp.identifier(env), kp)
    }
}

fn main() {
    let env = build_env("Standalone Network ; February 2017".to_string());

    let public_encoded = "GA63NQJB6SXHDVOI3NXP4GM3K5MB4KLTX6R4YK2KKXY4DM27ZNUOVJYY".to_string();
    let secret_encoded = "SC2ZVG244UNKKBEKAQLEFAS2AU4XGEX5TXCXBTJZ6DXVU5MJ4E4FRKF4".to_string();

    let (kp_id, kp) = ed25519_utils::build_kp(
        &env,
        &decode_pub(public_encoded),
        &decode_secret(secret_encoded),
    );

    let contract_id =
        bytesn!(&env, 0x9c17051a8d43f2e1e062e69980df8b41ebbf55a50065daee59c8b7a4720b10f8);
    let action = symbol!("change");
    let args = (
        bytes!(&env, 0x68656c6c6f),
        bytes!(&env, 0x68656c6c6f),
        BigInt::zero(&env),
    );

    let sig = soroban_auth::testutils::ed25519::sign(&env, &kp, &contract_id, action, args);
    std::println!("{:?}", sig);
}

fn build_env(passphrase: String) -> Env {
    let env = Env::default();

    env.ledger().set(LedgerInfo {
        timestamp: 1668106305,
        protocol_version: 20,
        sequence_number: 10,
        network_passphrase: passphrase.as_bytes().to_vec(),
        base_reserve: 10,
    });

    env
}

fn log_pubkey(id: IdentifierValue) {
    let user_account_id = match id {
        IdentifierValue::Ed25519(bytes) => bytes,
        _ => panic!("not ed25519"),
    };

    std::println!(
        "{:?}",
        &Strkey::PublicKeyEd25519(StrkeyPublicKeyEd25519(user_account_id.to_array())).to_string(),
    )
}

fn log_secret(secret: [u8; 32]) {
    std::println!(
        "{:?}",
        &Strkey::PrivateKeyEd25519(StrkeyPrivateKeyEd25519(secret)).to_string(),
    )
}

fn decode_pub(public: String) -> [u8; 32] {
    let pub_key = StrkeyPublicKeyEd25519::from_string(&public).unwrap();
    pub_key.0
}

fn decode_secret(secret: String) -> [u8; 32] {
    let secret_key = StrkeyPrivateKeyEd25519::from_string(&secret).unwrap();
    secret_key.0
}
