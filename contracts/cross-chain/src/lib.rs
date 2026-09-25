#![no_std]

use accensa_common::Error;
pub use outbound::{EvmAddress, OutboundBridgePayload};
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod outbound;
#[cfg(test)]
mod test;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Admin,
    Token,
    DestinationChainId,
    NextSequence,
    Paused,
}

#[contract]
pub struct CrossChainBridge;

#[contractimpl]
impl CrossChainBridge {
    /// Initialize the cross-chain bridge with admin, wrapped token address,
    /// and destination EVM chain ID.
    pub fn initialize(
        env: Env,
        admin: Address,
        token: Address,
        destination_chain_id: u32,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Token, &token);
        env.storage()
            .instance()
            .set(&DataKey::DestinationChainId, &destination_chain_id);
        env.storage().instance().set(&DataKey::NextSequence, &1u64);
        env.storage().instance().set(&DataKey::Paused, &false);

        Ok(())
    }

    /// Withdraw settled Soroban balance directly to an EVM chain by burning
    /// the wrapped asset and emitting a bridge request (issue #456).
    pub fn withdraw_to_evm(
        env: Env,
        caller: Address,
        evm_address: EvmAddress,
        amount: i128,
    ) -> Result<u64, Error> {
        if Self::is_paused(&env) {
            return Err(Error::Paused);
        }

        let token: Address = env
            .storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(Error::NotInitialized)?;

        let destination_chain_id: u32 = env
            .storage()
            .instance()
            .get(&DataKey::DestinationChainId)
            .ok_or(Error::NotInitialized)?;

        let sequence: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextSequence)
            .unwrap_or(1);

        outbound::execute_withdrawal_to_evm(
            &env,
            &caller,
            &token,
            &evm_address,
            amount,
            destination_chain_id,
            sequence,
        )?;

        env.storage()
            .instance()
            .set(&DataKey::NextSequence, &(sequence + 1));

        Ok(sequence)
    }

    /// Pause the bridge contract (admin only).
    pub fn pause(env: Env, admin: Address) -> Result<(), Error> {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if admin != stored_admin {
            return Err(Error::Unauthorized);
        }
        env.storage().instance().set(&DataKey::Paused, &true);
        Ok(())
    }

    /// Unpause the bridge contract (admin only).
    pub fn unpause(env: Env, admin: Address) -> Result<(), Error> {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if admin != stored_admin {
            return Err(Error::Unauthorized);
        }
        env.storage().instance().set(&DataKey::Paused, &false);
        Ok(())
    }

    pub fn is_paused(env: &Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    pub fn get_token(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(Error::NotInitialized)
    }

    pub fn get_destination_chain_id(env: Env) -> Result<u32, Error> {
        env.storage()
            .instance()
            .get(&DataKey::DestinationChainId)
            .ok_or(Error::NotInitialized)
    }

    pub fn get_next_sequence(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::NextSequence)
            .unwrap_or(1)
    }

    pub fn get_admin(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)
    }
}
