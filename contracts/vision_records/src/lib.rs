#![no_std]
pub mod rbac;

pub mod events;
pub mod provider;

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, Env, String, Symbol, Vec,
};

pub use provider::{Certification, License, Location, Provider, VerificationStatus};

/// Storage keys for the contract
const ADMIN: Symbol = symbol_short!("ADMIN");
const INITIALIZED: Symbol = symbol_short!("INIT");

pub use rbac::{Permission, Role};

/// Access levels for record sharing
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessLevel {
    None,
    Read,
    Write,
    Full,
}

/// Vision record types
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordType {
    Examination,
    Prescription,
    Diagnosis,
    Treatment,
    Surgery,
    LabResult,
}

/// User information structure
#[contracttype]
#[derive(Clone, Debug)]
pub struct User {
    pub address: Address,
    pub role: Role,
    pub name: String,
    pub registered_at: u64,
    pub is_active: bool,
}

/// Vision record structure
#[contracttype]
#[derive(Clone, Debug)]
pub struct VisionRecord {
    pub id: u64,
    pub patient: Address,
    pub provider: Address,
    pub record_type: RecordType,
    pub data_hash: String,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Access grant structure
#[contracttype]
#[derive(Clone, Debug)]
pub struct AccessGrant {
    pub patient: Address,
    pub grantee: Address,
    pub level: AccessLevel,
    pub granted_at: u64,
    pub expires_at: u64,
}

/// Contract errors
/// Contract errors
#[soroban_sdk::contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ContractError {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    Unauthorized = 3,
    UserNotFound = 4,
    RecordNotFound = 5,
    InvalidInput = 6,
    AccessDenied = 7,
    Paused = 8,
    ProviderNotFound = 9,
    ProviderAlreadyRegistered = 10,
    InvalidVerificationStatus = 11,
}

#[contract]
pub struct VisionRecordsContract;

#[contractimpl]
impl VisionRecordsContract {
    /// Initialize the contract with an admin address
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        if env.storage().instance().has(&INITIALIZED) {
            return Err(ContractError::AlreadyInitialized);
        }

        // admin.require_auth();

        env.storage().instance().set(&ADMIN, &admin);
        env.storage().instance().set(&INITIALIZED, &true);
        rbac::assign_role(&env, admin.clone(), Role::Admin, 0);

        // Bootstrap the admin with the Admin role so they can register other users
        rbac::assign_role(&env, admin.clone(), Role::Admin, 0);

        events::publish_initialized(&env, admin);

        Ok(())
    }

    /// Get the admin address
    pub fn get_admin(env: Env) -> Result<Address, ContractError> {
        env.storage()
            .instance()
            .get(&ADMIN)
            .ok_or(ContractError::NotInitialized)
    }

    /// Check if the contract is initialized
    pub fn is_initialized(env: Env) -> bool {
        env.storage().instance().has(&INITIALIZED)
    }

    /// Register a new user
    pub fn register_user(
        env: Env,
        caller: Address,
        user: Address,
        role: Role,
        name: String,
    ) -> Result<(), ContractError> {
        caller.require_auth();

        if !rbac::has_permission(&env, &caller, &Permission::ManageUsers) {
            return Err(ContractError::Unauthorized);
        }

        let user_data = User {
            address: user.clone(),
            role: role.clone(),
            name: name.clone(),
            registered_at: env.ledger().timestamp(),
            is_active: true,
        };

        let key = (symbol_short!("USER"), user.clone());
        env.storage().persistent().set(&key, &user_data);
        rbac::assign_role(&env, user.clone(), role.clone(), 0);

        rbac::assign_role(&env, user.clone(), role.clone(), 0);

        // Assign the role in the RBAC system
        rbac::assign_role(&env, user.clone(), role.clone(), 0);

        events::publish_user_registered(&env, user, role, name);

        Ok(())
    }

    /// Get user information
    pub fn get_user(env: Env, user: Address) -> Result<User, ContractError> {
        let key = (symbol_short!("USER"), user);
        env.storage()
            .persistent()
            .get(&key)
            .ok_or(ContractError::UserNotFound)
    }

    /// Add a vision record
    #[allow(clippy::arithmetic_side_effects)]
    pub fn add_record(
        env: Env,
        caller: Address,
        patient: Address,
        provider: Address,
        record_type: RecordType,
        data_hash: String,
    ) -> Result<u64, ContractError> {
        caller.require_auth();

        let has_perm = if caller == provider {
            rbac::has_permission(&env, &caller, &Permission::WriteRecord)
        } else {
            rbac::has_delegated_permission(&env, &provider, &caller, &Permission::WriteRecord)
        };

        if !has_perm && !rbac::has_permission(&env, &caller, &Permission::SystemAdmin) {
            return Err(ContractError::Unauthorized);
        }

        // Generate record ID
        let counter_key = symbol_short!("REC_CTR");
        let record_id: u64 = env.storage().instance().get(&counter_key).unwrap_or(0) + 1;
        env.storage().instance().set(&counter_key, &record_id);

        let record = VisionRecord {
            id: record_id,
            patient: patient.clone(),
            provider: provider.clone(),
            record_type: record_type.clone(),
            data_hash,
            created_at: env.ledger().timestamp(),
            updated_at: env.ledger().timestamp(),
        };

        let key = (symbol_short!("RECORD"), record_id);
        env.storage().persistent().set(&key, &record);

        // Add to patient's record list
        let patient_key = (symbol_short!("PAT_REC"), patient.clone());
        let mut patient_records: Vec<u64> = env
            .storage()
            .persistent()
            .get(&patient_key)
            .unwrap_or(Vec::new(&env));
        patient_records.push_back(record_id);
        env.storage()
            .persistent()
            .set(&patient_key, &patient_records);

        events::publish_record_added(&env, record_id, patient, provider, record_type);

        Ok(record_id)
    }

    /// Get a vision record by ID
    pub fn get_record(env: Env, record_id: u64) -> Result<VisionRecord, ContractError> {
        let key = (symbol_short!("RECORD"), record_id);
        env.storage()
            .persistent()
            .get(&key)
            .ok_or(ContractError::RecordNotFound)
    }

    /// Get all records for a patient
    pub fn get_patient_records(env: Env, patient: Address) -> Vec<u64> {
        let key = (symbol_short!("PAT_REC"), patient);
        env.storage()
            .persistent()
            .get(&key)
            .unwrap_or(Vec::new(&env))
    }

    /// Grant access to a user
    #[allow(clippy::arithmetic_side_effects)]
    pub fn grant_access(
        env: Env,
        caller: Address,
        patient: Address,
        grantee: Address,
        level: AccessLevel,
        duration_seconds: u64,
    ) -> Result<(), ContractError> {
        caller.require_auth();

        let has_perm = if caller == patient {
            true // Patient manages own access
        } else {
            rbac::has_delegated_permission(&env, &patient, &caller, &Permission::ManageAccess)
                || rbac::has_permission(&env, &caller, &Permission::SystemAdmin)
        };

        if !has_perm {
            return Err(ContractError::Unauthorized);
        }

        let expires_at = env.ledger().timestamp() + duration_seconds;
        let grant = AccessGrant {
            patient: patient.clone(),
            grantee: grantee.clone(),
            level: level.clone(),
            granted_at: env.ledger().timestamp(),
            expires_at,
        };

        let key = (symbol_short!("ACCESS"), patient.clone(), grantee.clone());
        env.storage().persistent().set(&key, &grant);

        events::publish_access_granted(&env, patient, grantee, level, duration_seconds, expires_at);

        Ok(())
    }

    /// Check access level
    pub fn check_access(env: Env, patient: Address, grantee: Address) -> AccessLevel {
        let key = (symbol_short!("ACCESS"), patient, grantee);

        if let Some(grant) = env.storage().persistent().get::<_, AccessGrant>(&key) {
            if grant.expires_at > env.ledger().timestamp() {
                return grant.level;
            }
        }

        AccessLevel::None
    }

    /// Revoke access
    pub fn revoke_access(
        env: Env,
        patient: Address,
        grantee: Address,
    ) -> Result<(), ContractError> {
        patient.require_auth();

        let key = (symbol_short!("ACCESS"), patient.clone(), grantee.clone());
        env.storage().persistent().remove(&key);

        events::publish_access_revoked(&env, patient, grantee);

        Ok(())
    }

    /// Get the total number of records
    pub fn get_record_count(env: Env) -> u64 {
        let counter_key = symbol_short!("REC_CTR");
        env.storage().instance().get(&counter_key).unwrap_or(0)
    }

    /// Contract version
    pub fn version() -> u32 {
        1
    }

    // ======================== RBAC Endpoints ========================

    pub fn grant_custom_permission(
        env: Env,
        caller: Address,
        user: Address,
        permission: Permission,
    ) -> Result<(), ContractError> {
        caller.require_auth();
        if !rbac::has_permission(&env, &caller, &Permission::ManageUsers) {
            return Err(ContractError::Unauthorized);
        }
        rbac::grant_custom_permission(&env, user, permission)
            .map_err(|_| ContractError::UserNotFound)?;
        Ok(())
    }

    pub fn revoke_custom_permission(
        env: Env,
        caller: Address,
        user: Address,
        permission: Permission,
    ) -> Result<(), ContractError> {
        caller.require_auth();
        if !rbac::has_permission(&env, &caller, &Permission::ManageUsers) {
            return Err(ContractError::Unauthorized);
        }
        rbac::revoke_custom_permission(&env, user, permission)
            .map_err(|_| ContractError::UserNotFound)?;
        Ok(())
    }

    pub fn delegate_role(
        env: Env,
        delegator: Address,
        delegatee: Address,
        role: Role,
        expires_at: u64,
    ) -> Result<(), ContractError> {
        delegator.require_auth();
        rbac::delegate_role(&env, delegator, delegatee, role, expires_at);
        Ok(())
    }

    pub fn check_permission(env: Env, user: Address, permission: Permission) -> bool {
        rbac::has_permission(&env, &user, &permission)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_provider(
        env: Env,
        caller: Address,
        provider: Address,
        name: String,
        licenses: Vec<License>,
        specialties: Vec<String>,
        certifications: Vec<Certification>,
        locations: Vec<Location>,
    ) -> Result<u64, ContractError> {
        caller.require_auth();

        if !rbac::has_permission(&env, &caller, &Permission::ManageUsers) {
            return Err(ContractError::Unauthorized);
        }

        if provider::get_provider(&env, &provider).is_some() {
            return Err(ContractError::ProviderAlreadyRegistered);
        }

        let provider_id = provider::increment_provider_counter(&env);
        provider::add_provider_id(&env, provider_id, &provider);

        let provider_data = Provider {
            address: provider.clone(),
            name: name.clone(),
            licenses: licenses.clone(),
            specialties: specialties.clone(),
            certifications: certifications.clone(),
            locations: locations.clone(),
            verification_status: VerificationStatus::Pending,
            registered_at: env.ledger().timestamp(),
            verified_at: None,
            verified_by: None,
            is_active: true,
        };

        provider::set_provider(&env, &provider_data);

        for specialty in specialties.iter() {
            provider::add_provider_to_specialty_index(&env, &specialty, &provider);
        }

        events::publish_provider_registered(&env, provider.clone(), name, provider_id);

        Ok(provider_id)
    }

    pub fn verify_provider(
        env: Env,
        caller: Address,
        provider: Address,
        status: VerificationStatus,
    ) -> Result<(), ContractError> {
        caller.require_auth();

        if !rbac::has_permission(&env, &caller, &Permission::ManageUsers) {
            return Err(ContractError::Unauthorized);
        }

        let mut provider_data =
            provider::get_provider(&env, &provider).ok_or(ContractError::ProviderNotFound)?;

        if status == VerificationStatus::Pending {
            return Err(ContractError::InvalidVerificationStatus);
        }

        provider_data.verification_status = status.clone();
        provider_data.verified_at = Some(env.ledger().timestamp());
        provider_data.verified_by = Some(caller.clone());

        provider::set_provider(&env, &provider_data);

        events::publish_provider_verified(&env, provider, caller, status);

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_provider(
        env: Env,
        caller: Address,
        provider: Address,
        name: Option<String>,
        licenses: Option<Vec<License>>,
        specialties: Option<Vec<String>>,
        certifications: Option<Vec<Certification>>,
        locations: Option<Vec<Location>>,
    ) -> Result<(), ContractError> {
        caller.require_auth();

        if caller != provider && !rbac::has_permission(&env, &caller, &Permission::ManageUsers) {
            return Err(ContractError::Unauthorized);
        }

        let mut provider_data =
            provider::get_provider(&env, &provider).ok_or(ContractError::ProviderNotFound)?;

        if let Some(new_name) = name {
            provider_data.name = new_name;
        }

        if let Some(new_licenses) = licenses {
            provider_data.licenses = new_licenses;
        }

        if let Some(new_specialties) = specialties {
            for old_specialty in provider_data.specialties.iter() {
                provider::remove_provider_from_specialty_index(&env, &old_specialty, &provider);
            }
            provider_data.specialties = new_specialties.clone();
            for specialty in new_specialties.iter() {
                provider::add_provider_to_specialty_index(&env, &specialty, &provider);
            }
        }

        if let Some(new_certifications) = certifications {
            provider_data.certifications = new_certifications;
        }

        if let Some(new_locations) = locations {
            provider_data.locations = new_locations;
        }

        provider::set_provider(&env, &provider_data);

        events::publish_provider_updated(&env, provider);

        Ok(())
    }

    pub fn get_provider(env: Env, provider: Address) -> Result<Provider, ContractError> {
        provider::get_provider(&env, &provider).ok_or(ContractError::ProviderNotFound)
    }

    pub fn search_providers_by_specialty(env: Env, specialty: String) -> Vec<Address> {
        provider::get_providers_by_specialty(&env, &specialty)
    }

    pub fn search_providers_by_status(env: Env, status: VerificationStatus) -> Vec<Address> {
        let all_ids = provider::get_all_provider_ids(&env);
        let mut result = Vec::new(&env);

        for i in 0..all_ids.len() {
            if let Some(id) = all_ids.get(i) {
                if let Some(provider_addr) = Self::get_provider_address_by_id(&env, id) {
                    if let Ok(provider_data) =
                        Self::get_provider(env.clone(), provider_addr.clone())
                    {
                        if provider_data.verification_status == status && provider_data.is_active {
                            result.push_back(provider_addr);
                        }
                    }
                }
            }
        }

        result
    }

    pub fn get_provider_count(env: Env) -> u64 {
        provider::get_provider_counter(&env)
    }

    fn get_provider_address_by_id(env: &Env, provider_id: u64) -> Option<Address> {
        let id_key = (symbol_short!("PROV_ID"), provider_id);
        env.storage().persistent().get(&id_key)
    }
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod test_rbac;
