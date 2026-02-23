use crate::{AccessLevel, RecordType, Role, VerificationStatus};
use soroban_sdk::{symbol_short, Address, Env, String};

/// Event published when the contract is initialized.
#[soroban_sdk::contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitializedEvent {
    pub admin: Address,
    pub timestamp: u64,
}

/// Event published when a new user is registered.
#[soroban_sdk::contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserRegisteredEvent {
    pub user: Address,
    pub role: Role,
    pub name: String,
    pub timestamp: u64,
}

/// Event published when a new vision record is added.
#[soroban_sdk::contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordAddedEvent {
    pub record_id: u64,
    pub patient: Address,
    pub provider: Address,
    pub record_type: RecordType,
    pub timestamp: u64,
}

/// Event published when access is granted to a record.
#[soroban_sdk::contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessGrantedEvent {
    pub patient: Address,
    pub grantee: Address,
    pub level: AccessLevel,
    pub duration_seconds: u64,
    pub expires_at: u64,
    pub timestamp: u64,
}

/// Event published when access is revoked.
#[soroban_sdk::contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRevokedEvent {
    pub patient: Address,
    pub grantee: Address,
    pub timestamp: u64,
}

pub fn publish_initialized(env: &Env, admin: Address) {
    let topics = (symbol_short!("INIT"),);
    let data = InitializedEvent {
        admin,
        timestamp: env.ledger().timestamp(),
    };
    env.events().publish(topics, data);
}

pub fn publish_user_registered(env: &Env, user: Address, role: Role, name: String) {
    let topics = (symbol_short!("USR_REG"), user.clone());
    let data = UserRegisteredEvent {
        user,
        role,
        name,
        timestamp: env.ledger().timestamp(),
    };
    env.events().publish(topics, data);
}

pub fn publish_record_added(
    env: &Env,
    record_id: u64,
    patient: Address,
    provider: Address,
    record_type: RecordType,
) {
    let topics = (symbol_short!("REC_ADD"), patient.clone(), provider.clone());
    let data = RecordAddedEvent {
        record_id,
        patient,
        provider,
        record_type,
        timestamp: env.ledger().timestamp(),
    };
    env.events().publish(topics, data);
}

pub fn publish_access_granted(
    env: &Env,
    patient: Address,
    grantee: Address,
    level: AccessLevel,
    duration_seconds: u64,
    expires_at: u64,
) {
    let topics = (symbol_short!("ACC_GRT"), patient.clone(), grantee.clone());
    let data = AccessGrantedEvent {
        patient,
        grantee,
        level,
        duration_seconds,
        expires_at,
        timestamp: env.ledger().timestamp(),
    };
    env.events().publish(topics, data);
}

pub fn publish_access_revoked(env: &Env, patient: Address, grantee: Address) {
    let topics = (symbol_short!("ACC_REV"), patient.clone(), grantee.clone());
    let data = AccessRevokedEvent {
        patient,
        grantee,
        timestamp: env.ledger().timestamp(),
    };
    env.events().publish(topics, data);
}

#[soroban_sdk::contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRegisteredEvent {
    pub provider: Address,
    pub name: String,
    pub provider_id: u64,
    pub timestamp: u64,
}

#[soroban_sdk::contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderVerifiedEvent {
    pub provider: Address,
    pub verifier: Address,
    pub status: VerificationStatus,
    pub timestamp: u64,
}

#[soroban_sdk::contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderUpdatedEvent {
    pub provider: Address,
    pub timestamp: u64,
}

pub fn publish_provider_registered(env: &Env, provider: Address, name: String, provider_id: u64) {
    let topics = (symbol_short!("PROV_REG"), provider.clone());
    let data = ProviderRegisteredEvent {
        provider,
        name,
        provider_id,
        timestamp: env.ledger().timestamp(),
    };
    env.events().publish(topics, data);
}

pub fn publish_provider_verified(
    env: &Env,
    provider: Address,
    verifier: Address,
    status: VerificationStatus,
) {
    let topics = (
        symbol_short!("PROV_VER"),
        provider.clone(),
        verifier.clone(),
    );
    let data = ProviderVerifiedEvent {
        provider,
        verifier,
        status,
        timestamp: env.ledger().timestamp(),
    };
    env.events().publish(topics, data);
}

pub fn publish_provider_updated(env: &Env, provider: Address) {
    let topics = (symbol_short!("PROV_UPD"), provider.clone());
    let data = ProviderUpdatedEvent {
        provider,
        timestamp: env.ledger().timestamp(),
    };
    env.events().publish(topics, data);
}
