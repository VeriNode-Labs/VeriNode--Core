use soroban_sdk::{Address, Env, String, Symbol};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::testutils::Ledger;
use sorosusu_contracts::{SoroSusu, SoroSusuClient, DataKey, ProposalType, ProposalStatus, QuadraticVoteChoice};

#[soroban_sdk::contract]
pub struct MockNft;

#[soroban_sdk::contractimpl]
impl MockNft {
    pub fn mint(_env: Env, _to: soroban_sdk::Address, _id: u128) {}
    pub fn burn(_env: Env, _from: soroban_sdk::Address, _id: u128) {}
}

#[test]
fn test_quadratic_voting_enabled_for_large_groups() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let creator2 = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create large group (>= 10 members) - quadratic voting should be enabled
    let circle_id = client.create_circle(
        &creator,
        &10_000_0, // 10 XLM
        &15u32,      // 15 members
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Verify quadratic voting is enabled
    env.as_contract(&contract_id, || {
        let circle_key = DataKey::Circle(circle_id);
        let circle = env.storage().instance().get::<_, sorosusu_contracts::CircleInfo>(&circle_key).unwrap();
        assert!(circle.quadratic_voting_enabled);
    });
    
    // Create small group (< 10 members) - quadratic voting should be disabled
    let small_circle_id = client.create_circle(
        &creator2,
        &10_000_0,
        &5u32,       // 5 members
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Verify quadratic voting is disabled
    env.as_contract(&contract_id, || {
        let small_circle_key = DataKey::Circle(small_circle_id);
        let small_circle = env.storage().instance().get::<_, sorosusu_contracts::CircleInfo>(&small_circle_key).unwrap();
        assert!(!small_circle.quadratic_voting_enabled);
    });
}

#[test]
fn test_create_proposal() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let proposer = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create large group
    let circle_id = client.create_circle(
        &creator,
        &10_000_0,
        &15u32,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Join circle
    client.join_circle(&proposer, &circle_id, &1u32, &None);
    
    // Create proposal
    let title = String::from_str(&env, "Reduce late fee to 0.5%");
    let description = String::from_str(&env, "Proposal to reduce late fee from 1% to 0.5%");
    let execution_data = String::from_str(&env, "{\"late_fee_bps\": 50}");
    
    let proposal_id = client.create_proposal(
        &proposer,
        &circle_id,
        &ProposalType::ChangeLateFee,
        &title,
        &description,
        &execution_data,
    );
    
    // Verify proposal was created
    let proposal = client.get_proposal(&proposal_id);
    assert_eq!(proposal.proposer, proposer);
    assert_eq!(proposal.circle_id, circle_id);
    assert_eq!(proposal.proposal_type, ProposalType::ChangeLateFee);
    assert_eq!(proposal.status, ProposalStatus::Active);
    assert_eq!(proposal.for_votes, 0);
    assert_eq!(proposal.against_votes, 0);
}

#[test]
fn test_create_proposal_fails_for_small_groups() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let proposer = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create small group
    let circle_id = client.create_circle(
        &creator,
        &10_000_0,
        &5u32, // Small group
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Join circle
    client.join_circle(&proposer, &circle_id, &1u32, &None);
    
    // Try to create proposal - should fail
    let title = String::from_str(&env, "Test proposal");
    let description = String::from_str(&env, "Test description");
    let execution_data = String::from_str(&env, "{}");
    
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.create_proposal(&proposer, &circle_id, &ProposalType::ChangeLateFee, &title, &description, &execution_data);
    }));
    assert!(result.is_err());
}

#[test]
fn test_voting_power_calculation() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let member = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create circle
    let circle_id = client.create_circle(
        &creator,
        &10_000_0,
        &15u32,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Join circle
    client.join_circle(&member, &circle_id, &1u32, &None);
    
    // Update voting power with different token balances
    client.update_voting_power(&member, &circle_id, &1_000_000_0); // 100 XLM
    let voting_power = client.get_voting_power(&member, &circle_id);
    assert_eq!(voting_power.token_balance, 1_000_000_0);
    assert!(voting_power.quadratic_power > 0);
    
    // Test with zero balance
    client.update_voting_power(&member, &circle_id, &0);
    let zero_power = client.get_voting_power(&member, &circle_id);
    assert_eq!(zero_power.token_balance, 0);
    assert_eq!(zero_power.quadratic_power, 0);
}

#[test]
fn test_quadratic_vote_cost_calculation() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let proposer = Address::generate(&env);
    let voter = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create large group
    let circle_id = client.create_circle(
        &creator,
        &10_000_0,
        &15u32,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Join circle
    client.join_circle(&proposer, &circle_id, &1u32, &None);
    client.join_circle(&voter, &circle_id, &1u32, &None);
    
    // Create proposal
    let title = String::from_str(&env, "Test proposal");
    let description = String::from_str(&env, "Test description");
    let execution_data = String::from_str(&env, "{}");
    
    let proposal_id = client.create_proposal(
        &proposer,
        &circle_id,
        &ProposalType::ChangeLateFee,
        &title,
        &description,
        &execution_data,
    );
    
    // Set up voting power (enough for weight 10 vote: 10^2 = 100 voting power needed)
    client.update_voting_power(&voter, &circle_id, &10_000_000_0); // High balance for sufficient power
    
    // Vote with weight 10 (cost = 10^2 = 100)
    client.quadratic_vote(&voter, &proposal_id, &10u32, &QuadraticVoteChoice::For);
    
    // Verify vote was recorded
    let proposal = client.get_proposal(&proposal_id);
    assert_eq!(proposal.for_votes, 100); // 10^2 = 100
    assert_eq!(proposal.against_votes, 0);
    assert!(proposal.total_voting_power > 0);
}

#[test]
fn test_insufficient_voting_power() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let proposer = Address::generate(&env);
    let voter = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create large group
    let circle_id = client.create_circle(
        &creator,
        &10_000_0,
        &15u32,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Join circle
    client.join_circle(&proposer, &circle_id, &1u32, &None);
    client.join_circle(&voter, &circle_id, &1u32, &None);
    
    // Create proposal
    let title = String::from_str(&env, "Test proposal");
    let description = String::from_str(&env, "Test description");
    let execution_data = String::from_str(&env, "{}");
    
    let proposal_id = client.create_proposal(
        &proposer,
        &circle_id,
        &ProposalType::ChangeLateFee,
        &title,
        &description,
        &execution_data,
    );
    
    // Set low voting power (only enough for weight 5 vote: 5^2 = 25)
    client.update_voting_power(&voter, &circle_id, &25_000);
    
    // Try to vote with weight 10 (cost = 10^2 = 100) - should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.quadratic_vote(&voter, &proposal_id, &10u32, &QuadraticVoteChoice::For);
    }));
    assert!(result.is_err());
    
    // But voting with weight 5 should work (cost = 5^2 = 25)
    client.quadratic_vote(&voter, &proposal_id, &5u32, &QuadraticVoteChoice::For);
    
    let proposal = client.get_proposal(&proposal_id);
    assert_eq!(proposal.for_votes, 25); // 5^2 = 25
}

#[test]
fn test_double_voting_prevention() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let proposer = Address::generate(&env);
    let voter = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create large group
    let circle_id = client.create_circle(
        &creator,
        &10_000_0,
        &15u32,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Join circle
    client.join_circle(&proposer, &circle_id, &1u32, &None);
    client.join_circle(&voter, &circle_id, &1u32, &None);
    
    // Create proposal
    let title = String::from_str(&env, "Test proposal");
    let description = String::from_str(&env, "Test description");
    let execution_data = String::from_str(&env, "{}");
    
    let proposal_id = client.create_proposal(
        &proposer,
        &circle_id,
        &ProposalType::ChangeLateFee,
        &title,
        &description,
        &execution_data,
    );
    
    // Set up voting power
    client.update_voting_power(&voter, &circle_id, &10_000_000_0);
    
    // Vote once
    client.quadratic_vote(&voter, &proposal_id, &5u32, &QuadraticVoteChoice::For);
    
    // Try to vote again - should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.quadratic_vote(&voter, &proposal_id, &3u32, &QuadraticVoteChoice::Against);
    }));
    assert!(result.is_err());
}

#[test]
fn test_quorum_requirement() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let proposer = Address::generate(&env);
    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create large group
    let circle_id = client.create_circle(
        &creator,
        &10_000_0,
        &15u32,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Join circle
    client.join_circle(&proposer, &circle_id, &1u32, &None);
    client.join_circle(&voter1, &circle_id, &1u32, &None);
    client.join_circle(&voter2, &circle_id, &1u32, &None);
    
    // Create proposal
    let title = String::from_str(&env, "Test proposal");
    let description = String::from_str(&env, "Test description");
    let execution_data = String::from_str(&env, "{}");
    
    let proposal_id = client.create_proposal(
        &proposer,
        &circle_id,
        &ProposalType::ChangeLateFee,
        &title,
        &description,
        &execution_data,
    );
    
    // Add dummy members to reach 15 total members
    for _ in 0..12 {
        let dummy = Address::generate(&env);
        client.join_circle(&dummy, &circle_id, &1u32, &None);
    }
    
    // Set up voting power
    client.update_voting_power(&voter1, &circle_id, &1_000_000_0);
    client.update_voting_power(&voter2, &circle_id, &1_000_000_0);
    
    // Vote with low participation (should not meet quorum)
    client.quadratic_vote(&voter1, &proposal_id, &2u32, &QuadraticVoteChoice::For); // Cost: 4
    
    let proposal = client.get_proposal(&proposal_id);
    assert!(!proposal.quorum_met); // Should not meet 40% quorum
    
    // Add more votes to meet quorum
    client.quadratic_vote(&voter2, &proposal_id, &3u32, &QuadraticVoteChoice::For); // Cost: 9
    
    let updated_proposal = client.get_proposal(&proposal_id);
    assert_eq!(updated_proposal.for_votes, 13); // 4 + 9
    assert!(updated_proposal.quorum_met); // Should now meet quorum
}

#[test]
fn test_proposal_execution() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let proposer = Address::generate(&env);
    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);
    let voter3 = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create large group
    let circle_id = client.create_circle(
        &creator,
        &10_000_0,
        &15u32,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Join circle
    client.join_circle(&proposer, &circle_id, &1u32, &None);
    client.join_circle(&voter1, &circle_id, &1u32, &None);
    client.join_circle(&voter2, &circle_id, &1u32, &None);
    client.join_circle(&voter3, &circle_id, &1u32, &None);
    
    // Create proposal
    let title = String::from_str(&env, "Test proposal");
    let description = String::from_str(&env, "Test description");
    let execution_data = String::from_str(&env, "{}");
    
    let proposal_id = client.create_proposal(
        &proposer,
        &circle_id,
        &ProposalType::ChangeLateFee,
        &title,
        &description,
        &execution_data,
    );
    
    // Set up voting power
    client.update_voting_power(&voter1, &circle_id, &10_000_000_0);
    client.update_voting_power(&voter2, &circle_id, &10_000_000_0);
    client.update_voting_power(&voter3, &circle_id, &10_000_000_0);
    
    // Vote for approval (need 60% supermajority)
    client.quadratic_vote(&voter1, &proposal_id, &10u32, &QuadraticVoteChoice::For);  // Cost: 100
    client.quadratic_vote(&voter2, &proposal_id, &8u32, &QuadraticVoteChoice::For);   // Cost: 64
    client.quadratic_vote(&voter3, &proposal_id, &2u32, &QuadraticVoteChoice::Against); // Cost: 4
    
    // Advance time past voting period
    env.ledger().set_timestamp(env.ledger().timestamp() + 700000); // 8+ days later
    
    // Execute proposal
    client.execute_proposal(&admin, &proposal_id);
    
    // Verify proposal was approved and executed
    let proposal = client.get_proposal(&proposal_id);
    assert_eq!(proposal.status, ProposalStatus::Executed);
    assert_eq!(proposal.for_votes, 164); // 100 + 64
    assert_eq!(proposal.against_votes, 4);
    
    // Check stats
    let stats = client.get_proposal_stats(&circle_id);
    assert_eq!(stats.executed_proposals, 1);
    assert_eq!(stats.approved_proposals, 1);
}

#[test]
fn test_proposal_rejection_insufficient_majority() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let proposer = Address::generate(&env);
    let voter1 = Address::generate(&env);
    let voter2 = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create large group
    let circle_id = client.create_circle(
        &creator,
        &10_000_0,
        &15u32,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Join circle
    client.join_circle(&proposer, &circle_id, &1u32, &None);
    client.join_circle(&voter1, &circle_id, &1u32, &None);
    client.join_circle(&voter2, &circle_id, &1u32, &None);
    
    // Create proposal
    let title = String::from_str(&env, "Test proposal");
    let description = String::from_str(&env, "Test description");
    let execution_data = String::from_str(&env, "{}");
    
    let proposal_id = client.create_proposal(
        &proposer,
        &circle_id,
        &ProposalType::ChangeLateFee,
        &title,
        &description,
        &execution_data,
    );
    
    // Set up voting power
    client.update_voting_power(&voter1, &circle_id, &10_000_000_0);
    client.update_voting_power(&voter2, &circle_id, &10_000_000_0);
    
    // Vote with insufficient majority (need 60%, only get 50%)
    client.quadratic_vote(&voter1, &proposal_id, &10u32, &QuadraticVoteChoice::For);  // Cost: 100
    client.quadratic_vote(&voter2, &proposal_id, &10u32, &QuadraticVoteChoice::Against); // Cost: 100
    
    // Advance time past voting period
    env.ledger().set_timestamp(env.ledger().timestamp() + 700000);
    
    // Execute proposal
    client.execute_proposal(&admin, &proposal_id);
    
    // Verify proposal was rejected (50% < 60% required)
    let proposal = client.get_proposal(&proposal_id);
    assert_eq!(proposal.status, ProposalStatus::Rejected);
    assert_eq!(proposal.for_votes, 100);
    assert_eq!(proposal.against_votes, 100);
    
    // Check stats
    let stats = client.get_proposal_stats(&circle_id);
    assert_eq!(stats.rejected_proposals, 1);
}

#[test]
fn test_max_vote_weight_enforcement() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let proposer = Address::generate(&env);
    let voter = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_contract = env.register_contract(None, MockNft);
    
    // Initialize contract
    client.init(&admin);
    
    // Create large group
    let circle_id = client.create_circle(
        &creator,
        &10_000_0,
        &15u32,
        &token,
        &86400u64,
        &100u32,
        &nft_contract,
    );
    
    // Join circle
    client.join_circle(&proposer, &circle_id, &1u32, &None);
    client.join_circle(&voter, &circle_id, &1u32, &None);
    
    // Create proposal
    let title = String::from_str(&env, "Test proposal");
    let description = String::from_str(&env, "Test description");
    let execution_data = String::from_str(&env, "{}");
    
    let proposal_id = client.create_proposal(
        &proposer,
        &circle_id,
        &ProposalType::ChangeLateFee,
        &title,
        &description,
        &execution_data,
    );
    
    // Set up high voting power
    client.update_voting_power(&voter, &circle_id, &100_000_000_0);
    
    // Try to vote with weight > MAX_VOTE_WEIGHT (100) - should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.quadratic_vote(&voter, &proposal_id, &150u32, &QuadraticVoteChoice::For);
    }));
    assert!(result.is_err());
    
    // Voting with max weight should work
    client.quadratic_vote(&voter, &proposal_id, &100u32, &QuadraticVoteChoice::For);
    
    let proposal = client.get_proposal(&proposal_id);
    assert_eq!(proposal.for_votes, 10000); // 100^2 = 10000
}
