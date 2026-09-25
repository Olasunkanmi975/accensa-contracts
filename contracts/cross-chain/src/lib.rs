#![no_std]

use accensa_common::Error;
use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, Env};
pub use wormhole::{
    hash_vaa_body, parse_vaa, pubkey_to_address, verify_vaa, GuardianAddress, GuardianSet,
    GuardianSignature, ParsedVaa, VaaBody,
};

pub mod wormhole;

#[cfg(test)]
mod wormhole_test;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Admin,
    GuardianSet(u32),
    CurrentGuardianSetIndex,
}

#[contract]
pub struct CrossChainBridge;

#[contractimpl]
impl CrossChainBridge {
    /// Initialize the cross-chain verifier bridge contract with an admin.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::CurrentGuardianSetIndex, &0u32);

        Ok(())
    }

    /// Set an active Wormhole GuardianSet (admin only).
    pub fn set_guardian_set(env: Env, admin: Address, set: GuardianSet) -> Result<(), Error> {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if admin != stored_admin {
            return Err(Error::Unauthorized);
        }

        let idx = set.index;
        env.storage()
            .instance()
            .set(&DataKey::GuardianSet(idx), &set);
        env.storage()
            .instance()
            .set(&DataKey::CurrentGuardianSetIndex, &idx);

        Ok(())
    }

    /// Get a stored GuardianSet by index.
    pub fn get_guardian_set(env: Env, index: u32) -> Option<GuardianSet> {
        env.storage().instance().get(&DataKey::GuardianSet(index))
    }

    /// Get the current active GuardianSet index.
    pub fn get_current_guardian_set_index(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::CurrentGuardianSetIndex)
            .unwrap_or(0)
    }

    /// Verify a Wormhole VAA and extract its cross-chain payload.
    pub fn verify_and_parse_vaa(env: Env, vaa_bytes: Bytes) -> Result<VaaBody, Error> {
        let parsed = wormhole::parse_vaa(&env, &vaa_bytes)?;
        let guardian_set = Self::get_guardian_set(env.clone(), parsed.guardian_set_index)
            .ok_or(Error::RootNotFound)?;
        wormhole::verify_vaa(&env, &parsed, &guardian_set)?;
        Ok(parsed.body)
    }

    /// Get the contract admin address.
    pub fn get_admin(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)
    }
}
