#![allow(clippy::unwrap_used, clippy::expect_used)]

extern crate std;

use soroban_sdk::{testutils::Address as _, Address, Env};

use ai_integration::{AiIntegrationContract, AiIntegrationContractClient, AiIntegrationError};

fn setup() -> (Env, AiIntegrationContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(AiIntegrationContract, ());
    let client = AiIntegrationContractClient::new(&env, &contract_id);

    (env, client)
}

#[test]
fn test_double_reinitialization_reverts_and_does_not_overwrite_state() {
    let (env, client) = setup();

    let admin_1 = Address::generate(&env);
    let admin_2 = Address::generate(&env);

    client.initialize(&admin_1, &6_000);

    // Second initialization attempt must fail with a typed error.
    assert_eq!(
        client.try_initialize(&admin_2, &1_000),
        Err(Ok(AiIntegrationError::AlreadyInitialized))
    );

    // Ensure the initial state constraints remain unchanged.
    assert_eq!(client.get_admin(), admin_1);
    assert_eq!(client.get_anomaly_threshold(), 6_000);
}

#[test]
fn test_reinitialization_does_not_leak_other_validation_errors() {
    let (env, client) = setup();

    let admin_1 = Address::generate(&env);
    let admin_2 = Address::generate(&env);

    client.initialize(&admin_1, &6_000);

    // Even if the second init passes an invalid threshold, it must still fail
    // as AlreadyInitialized (init cannot be bypassed by triggering other checks).
    assert_eq!(
        client.try_initialize(&admin_2, &10_001),
        Err(Ok(AiIntegrationError::AlreadyInitialized))
    );

    assert_eq!(client.get_admin(), admin_1);
    assert_eq!(client.get_anomaly_threshold(), 6_000);
}
