use soroban_sdk::{Address, Env, String, contract, contractimpl};
use soroban_sdk::testutils::Address as _;
use sorosusu_contracts::{SoroSusu, SoroSusuClient, LeniencyVote, LeniencyRequestStatus};

#[contract]
pub struct MockNft;

#[contractimpl]
impl MockNft {
    pub fn mint(_env: Env, _to: Address, _id: u128) {}
    pub fn burn(_env: Env, _from: Address, _id: u128) {}
}

#[test]
fn test_request_leniency() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_id = env.register_contract(None, MockNft);
    client.init(&admin);

    let requester = Address::generate(&env);
    let circle_id = client.create_circle(&creator, &1000, &5, &token, &86400, &100, &nft_id);
    client.join_circle(&requester, &circle_id, &1, &None);
    client.request_leniency(&requester, &circle_id, &String::from_str(&env, "Reason"));
    let request = client.get_leniency_request(&circle_id, &requester);
    assert_eq!(request.status, LeniencyRequestStatus::Pending);
}

#[test]
fn test_vote_on_leniency_approval() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);
    let client = SoroSusuClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let token = Address::generate(&env);
    let nft_id = env.register_contract(None, MockNft);
    client.init(&admin);

    let requester = Address::generate(&env);
    let voter = Address::generate(&env);
    let circle_id = client.create_circle(&creator, &1000, &2, &token, &86400, &100, &nft_id);
    client.join_circle(&requester, &circle_id, &1, &None);
    client.join_circle(&voter, &circle_id, &1, &None);
    client.request_leniency(&requester, &circle_id, &String::from_str(&env, "Reason"));
    client.vote_on_leniency(&voter, &circle_id, &requester, &LeniencyVote::Approve);
    let request = client.get_leniency_request(&circle_id, &requester);
    assert_eq!(request.status, LeniencyRequestStatus::Approved);
}
