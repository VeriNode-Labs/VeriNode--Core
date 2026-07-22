use soroban_sdk::{Address, Env, String, Symbol};
use soroban_sdk::testutils::{Address as _, Ledger};
use sorosusu_contracts::{SoroSusu, SoroSusuClient, DataKey, LeniencyVote, LeniencyRequestStatus, MemberStatus};

#[soroban_sdk::contract]
pub struct MockNft;

#[soroban_sdk::contractimpl]
impl MockNft {
    pub fn mint(_env: Env, _to: soroban_sdk::Address, _id: u128) {}
    pub fn burn(_env: Env, _from: soroban_sdk::Address, _id: u128) {}
}

#[test]
fn test_request_leniency() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let requester = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create circle
    let circle_id = client.create_circle(
        &creator,
        &100_000_0, // 100 XLM
        &5u32,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Join circle
    client.join_circle(&requester, &circle_id, &1u32, &None);
    
    // Request leniency
    let reason = String::from_str(&env, "Medical emergency - need extra time");
    client.request_leniency(&requester, &circle_id, &reason);
    
    // Verify request was created
    let request = client.get_leniency_request(&circle_id, &requester);
    assert_eq!(request.requester, requester);
    assert_eq!(request.circle_id, circle_id);
    assert_eq!(request.status, LeniencyRequestStatus::Pending);
    assert_eq!(request.extension_hours, 48);
    assert_eq!(request.approve_votes, 0);
    assert_eq!(request.reject_votes, 0);
}

#[test]
fn test_vote_on_leniency_approval() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let requester = Address::generate(&env);
    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);
    let voter3 = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create circle
    let circle_id = client.create_circle(
        &creator,
        &100_000_0,
        &5u32,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Join circle
    client.join_circle(&requester, &circle_id, &1u32, &None);
    client.join_circle(&voter1, &circle_id, &1u32, &None);
    client.join_circle(&voter2, &circle_id, &1u32, &None);
    client.join_circle(&voter3, &circle_id, &1u32, &None);
    
    // Request leniency
    let reason = String::from_str(&env, "Need extra time for payment");
    client.request_leniency(&requester, &circle_id, &reason);
    
    // Vote to approve (need majority of 3 other members = 2 votes)
    client.vote_on_leniency(&voter1, &circle_id, &requester, &LeniencyVote::Approve);
    client.vote_on_leniency(&voter2, &circle_id, &requester, &LeniencyVote::Approve);
    
    // Verify request was approved
    let request = client.get_leniency_request(&circle_id, &requester);
    assert_eq!(request.status, LeniencyRequestStatus::Approved);
    assert_eq!(request.approve_votes, 2);
    assert_eq!(request.reject_votes, 0);
    
    // Verify grace period was applied
    env.as_contract(&contract_id, || {
        let circle_key = DataKey::Circle(circle_id);
        let circle = env.storage().instance().get::<_, sorosusu_contracts::CircleInfo>(&circle_key).unwrap();
        assert!(circle.grace_period_end.is_some());
        assert_eq!(circle.grace_period_end.unwrap(), circle.deadline_timestamp + 172800);
    });
}

#[test]
fn test_vote_on_leniency_rejection() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let requester = Address::generate(&env);
    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);
    let voter3 = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create circle
    let circle_id = client.create_circle(
        &creator,
        &100_000_0,
        &5u32,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Join circle
    client.join_circle(&requester, &circle_id, &1u32, &None);
    client.join_circle(&voter1, &circle_id, &1u32, &None);
    client.join_circle(&voter2, &circle_id, &1u32, &None);
    client.join_circle(&voter3, &circle_id, &1u32, &None);
    
    // Request leniency
    let reason = String::from_str(&env, "Need extra time");
    client.request_leniency(&requester, &circle_id, &reason);
    
    // Vote to reject (need majority of 3 other members = 2 votes)
    client.vote_on_leniency(&voter1, &circle_id, &requester, &LeniencyVote::Reject);
    client.vote_on_leniency(&voter2, &circle_id, &requester, &LeniencyVote::Reject);
    
    // Verify request was rejected
    let request = client.get_leniency_request(&circle_id, &requester);
    assert_eq!(request.status, LeniencyRequestStatus::Rejected);
    assert_eq!(request.approve_votes, 0);
    assert_eq!(request.reject_votes, 2);
}

#[test]
fn test_cannot_vote_for_own_request() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let requester = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create circle
    let circle_id = client.create_circle(
        &creator,
        &100_000_0,
        &5u32,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Join circle
    client.join_circle(&requester, &circle_id, &1u32, &None);
    
    // Request leniency
    let reason = String::from_str(&env, "Need extra time");
    client.request_leniency(&requester, &circle_id, &reason);
    
    // Try to vote for own request - should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.vote_on_leniency(&requester, &circle_id, &requester, &LeniencyVote::Approve);
    }));
    assert!(result.is_err());
}

#[test]
fn test_double_voting_prevention() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let requester = Address::generate(&env);
    let voter = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create circle
    let circle_id = client.create_circle(
        &creator,
        &100_000_0,
        &5u32,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Join circle
    client.join_circle(&requester, &circle_id, &1u32, &None);
    client.join_circle(&voter, &circle_id, &1u32, &None);
    
    // Request leniency
    let reason = String::from_str(&env, "Need extra time");
    client.request_leniency(&requester, &circle_id, &reason);
    
    // Vote once
    client.vote_on_leniency(&voter, &circle_id, &requester, &LeniencyVote::Approve);
    
    // Try to vote again - should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.vote_on_leniency(&voter, &circle_id, &requester, &LeniencyVote::Approve);
    }));
    assert!(result.is_err());
}

#[test]
fn test_social_capital_tracking() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let requester = Address::generate(&env);
    let voter = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create circle
    let circle_id = client.create_circle(
        &creator,
        &100_000_0,
        &5u32,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Join circle
    client.join_circle(&requester, &circle_id, &1u32, &None);
    client.join_circle(&voter, &circle_id, &1u32, &None);
    
    // Request leniency
    let reason = String::from_str(&env, "Need extra time");
    client.request_leniency(&requester, &circle_id, &reason);
    
    // Vote to approve
    client.vote_on_leniency(&voter, &circle_id, &requester, &LeniencyVote::Approve);
    
    // Check voter's social capital increased
    let voter_social = client.get_social_capital(&voter, &circle_id);
    assert_eq!(voter_social.leniency_given, 1);
    assert_eq!(voter_social.voting_participation, 1);
    assert_eq!(voter_social.trust_score, 52); // 50 + 2 for approving
    
    // Check requester's social capital after approval
    let requester_social = client.get_social_capital(&requester, &circle_id);
    assert_eq!(requester_social.leniency_received, 1);
    assert_eq!(requester_social.trust_score, 55); // 50 + 5 for receiving leniency
}

#[test]
fn test_leniency_stats_tracking() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let requester1 = Address::generate(&env);
    let requester2 = Address::generate(&env);
    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create circle
    let circle_id = client.create_circle(
        &creator,
        &100_000_0,
        &5u32,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Join circle
    client.join_circle(&requester1, &circle_id, &1u32, &None);
    client.join_circle(&requester2, &circle_id, &1u32, &None);
    client.join_circle(&voter1, &circle_id, &1u32, &None);
    client.join_circle(&voter2, &circle_id, &1u32, &None);
    
    // Request leniency for requester1
    let reason1 = String::from_str(&env, "Medical emergency");
    client.request_leniency(&requester1, &circle_id, &reason1);
    client.vote_on_leniency(&voter1, &circle_id, &requester1, &LeniencyVote::Approve);
    client.vote_on_leniency(&voter2, &circle_id, &requester1, &LeniencyVote::Approve);
    
    // Request leniency for requester2
    let reason2 = String::from_str(&env, "Need extra time");
    client.request_leniency(&requester2, &circle_id, &reason2);
    client.vote_on_leniency(&voter1, &circle_id, &requester2, &LeniencyVote::Reject);
    client.vote_on_leniency(&voter2, &circle_id, &requester2, &LeniencyVote::Reject);
    
    // Check stats
    let stats = client.get_leniency_stats(&circle_id);
    assert_eq!(stats.total_requests, 2);
    assert_eq!(stats.approved_requests, 1);
    assert_eq!(stats.rejected_requests, 1);
    assert_eq!(stats.expired_requests, 0);
    assert_eq!(stats.average_participation, 2); // 2 votes per request
}

#[test]
fn test_grace_period_prevents_late_fees() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let requester = Address::generate(&env);
    let voter = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create circle with short deadline for testing
    let circle_id = client.create_circle(
        &creator,
        &100_000_0,
        &5u32,
        &token,
        &3600u64, // 1 hour deadline
        &100u32,
        &nft_contract,
    );
    
    // Join circle
    client.join_circle(&requester, &circle_id, &1u32, &None);
    client.join_circle(&voter, &circle_id, &1u32, &None);
    
    // Request leniency
    let reason = String::from_str(&env, "Need extra time");
    client.request_leniency(&requester, &circle_id, &reason);
    client.vote_on_leniency(&voter, &circle_id, &requester, &LeniencyVote::Approve);
    
    // Advance time past original deadline but within grace period
    env.ledger().set_timestamp(env.ledger().timestamp() + 7200); // 2 hours later
    
    // Verify grace period is active
    env.as_contract(&contract_id, || {
        let circle_key = DataKey::Circle(circle_id);
        let circle = env.storage().instance().get::<_, sorosusu_contracts::CircleInfo>(&circle_key).unwrap();
        assert!(circle.grace_period_end.is_some());
        assert!(env.ledger().timestamp() < circle.grace_period_end.unwrap());
    });
    
    // In a real test with token contracts, deposit would succeed without late fees
    // This test verifies the grace period logic is working
}

#[test]
fn test_voting_period_expiration() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let requester = Address::generate(&env);
    let voter = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create circle
    let circle_id = client.create_circle(
        &creator,
        &100_000_0,
        &5u32,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Join circle
    client.join_circle(&requester, &circle_id, &1u32, &None);
    client.join_circle(&voter, &circle_id, &1u32, &None);
    
    // Request leniency
    let reason = String::from_str(&env, "Need extra time");
    client.request_leniency(&requester, &circle_id, &reason);
    
    // Advance time past voting period
    env.ledger().set_timestamp(env.ledger().timestamp() + 90000); // 25 hours later
    
    // Try to vote - should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.vote_on_leniency(&voter, &circle_id, &requester, &LeniencyVote::Approve);
    }));
    assert!(result.is_err());
    
    // Finalize the expired vote
    client.finalize_leniency_vote(&admin, &circle_id, &requester);
    
    // Verify request expired
    let request = client.get_leniency_request(&circle_id, &requester);
    assert_eq!(request.status, LeniencyRequestStatus::Expired);
}

#[test]
fn test_minimum_participation_requirement() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let requester = Address::generate(&env);
    let voter = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create circle with 5 members
    let circle_id = client.create_circle(
        &creator,
        &100_000_0,
        &5u32,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Join circle (only 2 members total for this test)
    client.join_circle(&requester, &circle_id, &1u32, &None);
    client.join_circle(&voter, &circle_id, &1u32, &None);
    
    // Request leniency
    let reason = String::from_str(&env, "Need extra time");
    client.request_leniency(&requester, &circle_id, &reason);
    
    // Only one vote (need 50% participation of 1 other member = 1 vote minimum)
    client.vote_on_leniency(&voter, &circle_id, &requester, &LeniencyVote::Approve);
    
    // This should be sufficient for approval with 100% approval rate
    let request = client.get_leniency_request(&circle_id, &requester);
    assert_eq!(request.status, LeniencyRequestStatus::Approved);
}
