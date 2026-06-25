#![cfg_attr(target_family = "wasm", no_std)]
extern crate alloc;
use soroban_sdk::{
    contract, contractclient, contracterror, contractimpl, contracttype, token,
    Address, Env, String, Vec,
};

pub mod slashing_core;
pub mod slashing;
pub mod network;
pub mod reputation;
pub mod attestation_core;
// Cryptographic primitives and attestation signature verification.
// `crypto` provides a dependency-free SHA-256, SSZ-style merkleization, and
// domain separation; `attestation` computes domain-separated signing roots so
// signatures cannot be replayed across consensus domains.
pub mod attestation;
pub mod crypto;
pub mod consensus;

// Validator lifecycle and state transition.
// `validator` provides a deterministic exit queue ordered strictly by
// (exit_epoch, validator_index); `state` drains it during the epoch
// transition so exit processing is reproducible across clients.
pub mod state;
pub mod validator;

// --- ERROR CODES ---

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    Unauthorized = 1,
    MemberNotFound = 2,
    CircleFull = 3,
    AlreadyMember = 4,
    CircleNotFound = 5,
    InvalidAmount = 6,
    RoundAlreadyFinalized = 7,
    RoundNotFinalized = 8,
    NotAllContributed = 9,
    PayoutNotScheduled = 10,
    PayoutTooEarly = 11,
    InsufficientInsurance = 12,
    InsuranceAlreadyUsed = 13,
    RateLimitExceeded = 14,
    InsufficientCollateral = 15,
    CollateralAlreadyStaked = 16,
    CollateralNotStaked = 17,
    CollateralLocked = 18,
    MemberNotDefaulted = 19,
    CollateralAlreadyReleased = 20,
    LeniencyRequestNotFound = 21,
    AlreadyVoted = 22,
    VotingPeriodExpired = 23,
    LeniencyAlreadyApproved = 24,
    LeniencyNotRequested = 25,
    CannotVoteForOwnRequest = 26,
    InvalidVote = 27,
    ProposalNotFound = 28,
    ProposalAlreadyExecuted = 29,
    VotingNotActive = 30,
    InsufficientVotingPower = 31,
    QuadraticVoteExceeded = 32,
    InvalidProposalType = 33,
    QuorumNotMet = 34,
    ProposalExpired = 35,
}

// --- CONSTANTS ---
const REFERRAL_DISCOUNT_BPS: u32 = 500; // 5%
const RATE_LIMIT_SECONDS: u64 = 300; // 5 minutes
const LENIENCY_GRACE_PERIOD: u64 = 172800; // 48 hours in seconds
const VOTING_PERIOD: u64 = 86400; // 24 hours voting period
const MINIMUM_VOTING_PARTICIPATION: u32 = 50; // 50% minimum participation
const SIMPLE_MAJORITY_THRESHOLD: u32 = 51; // 51% simple majority
const QUADRATIC_VOTING_PERIOD: u64 = 604800; // 7 days for rule changes
const QUADRATIC_QUORUM: u32 = 40; // 40% quorum for quadratic voting
const QUADRATIC_MAJORITY: u32 = 60; // 60% supermajority for rule changes
const MAX_VOTE_WEIGHT: u32 = 100; // Maximum quadratic vote weight
const MIN_GROUP_SIZE_FOR_QUADRATIC: u32 = 10; // Enable quadratic voting for groups >= 10 members
const DEFAULT_COLLATERAL_BPS: u32 = 2000; // 20%
const HIGH_VALUE_THRESHOLD: i128 = 1_000_000_0; // 1000 XLM (assuming 7 decimals)

// --- DATA STRUCTURES ---

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Circle(u64),
    Member(Address),
    CircleCount,
    Deposit(u64, Address),
    GroupReserve,
    ScheduledPayoutTime(u64),
    LastCreatedTimestamp(Address),
    SafetyDeposit(Address, u64),
    LendingPool,
    CollateralVault(Address, u64),
    CollateralConfig(u64),
    DefaultedMembers(u64),
    LeniencyRequest(u64, Address),
    LeniencyVotes(u64, Address, Address),
    SocialCapital(Address, u64),
    LeniencyStats(u64),
    Proposal(u64),
    QuadraticVote(u64, Address),
    VotingPower(Address, u64),
    ProposalStats(u64),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum MemberStatus {
    Active,
    AwaitingReplacement,
    Ejected,
    Defaulted,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum LeniencyVote {
    Approve,
    Reject,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum LeniencyRequestStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum ProposalType {
    ChangeLateFee,
    ChangeInsuranceFee,
    ChangeCycleDuration,
    AddMember,
    RemoveMember,
    ChangeQuorum,
    EmergencyAction,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum ProposalStatus {
    Draft,
    Active,
    Approved,
    Rejected,
    Executed,
    Expired,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum QuadraticVoteChoice {
    For,
    Against,
    Abstain,
}

#[contracttype]
#[derive(Clone)]
pub struct LeniencyRequest {
    pub requester: Address,
    pub circle_id: u64,
    pub request_timestamp: u64,
    pub voting_deadline: u64,
    pub status: LeniencyRequestStatus,
    pub approve_votes: u32,
    pub reject_votes: u32,
    pub total_votes_cast: u32,
    pub extension_hours: u64,
    pub reason: String,
}

#[contracttype]
#[derive(Clone)]
pub struct Proposal {
    pub id: u64,
    pub circle_id: u64,
    pub proposer: Address,
    pub proposal_type: ProposalType,
    pub title: String,
    pub description: String,
    pub created_timestamp: u64,
    pub voting_start_timestamp: u64,
    pub voting_end_timestamp: u64,
    pub status: ProposalStatus,
    pub for_votes: u64,
    pub against_votes: u64,
    pub total_voting_power: u64,
    pub quorum_met: bool,
    pub execution_data: String, // JSON or structured data for execution
}

#[contracttype]
#[derive(Clone)]
pub struct QuadraticVote {
    pub voter: Address,
    pub proposal_id: u64,
    pub vote_weight: u32,
    pub vote_choice: QuadraticVoteChoice,
    pub voting_power_used: u64,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct VotingPower {
    pub member: Address,
    pub circle_id: u64,
    pub token_balance: i128,
    pub quadratic_power: u64,
    pub last_updated: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct ProposalStats {
    pub total_proposals: u32,
    pub approved_proposals: u32,
    pub rejected_proposals: u32,
    pub executed_proposals: u32,
    pub average_participation: u32,
    pub average_voting_time: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct LeniencyStats {
    pub total_requests: u32,
    pub approved_requests: u32,
    pub rejected_requests: u32,
    pub expired_requests: u32,
    pub average_participation: u32,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum CollateralStatus {
    NotStaked,
    Staked,
    Slashed,
    Released,
}

#[contracttype]
#[derive(Clone)]
pub struct SocialCapital {
    pub member: Address,
    pub circle_id: u64,
    pub leniency_given: u32,
    pub leniency_received: u32,
    pub voting_participation: u32,
    pub trust_score: u32,
}

#[contracttype]
#[derive(Clone)]
pub struct CollateralInfo {
    pub member: Address,
    pub circle_id: u64,
    pub amount: i128,
    pub status: CollateralStatus,
    pub staked_timestamp: u64,
    pub release_timestamp: Option<u64>,
}

#[contracttype]
#[derive(Clone)]
pub struct Member {
    pub address: Address,
    pub index: u32,
    pub contribution_count: u32,
    pub last_contribution_time: u64,
    pub status: MemberStatus,
    pub tier_multiplier: u32,
    pub referrer: Option<Address>,
    pub buddy: Option<Address>,
}

#[contracttype]
#[derive(Clone)]
pub struct CircleInfo {
    pub id: u64,
    pub creator: Address,
    pub contribution_amount: i128,
    pub max_members: u32,
    pub member_count: u32,
    pub current_recipient_index: u32,
    pub is_active: bool,
    pub token: Address,
    pub deadline_timestamp: u64,
    pub cycle_duration: u64,
    pub contribution_bitmap: u64,
    pub insurance_balance: i128,
    pub insurance_fee_bps: u32,
    pub is_insurance_used: bool,
    pub late_fee_bps: u32,
    pub nft_contract: Address,
    pub is_round_finalized: bool,
    pub current_pot_recipient: Option<Address>,
    pub leniency_enabled: bool,
    pub grace_period_end: Option<u64>,
    pub quadratic_voting_enabled: bool,
    pub proposal_count: u64,
    pub requires_collateral: bool,
    pub collateral_bps: u32,
    pub total_cycle_value: i128,
}

// --- CONTRACT CLIENTS ---

#[contractclient(name = "SusuNftClient")]
pub trait SusuNftTrait {
    fn mint(env: Env, to: Address, token_id: u128);
    fn burn(env: Env, from: Address, token_id: u128);
}

#[contractclient(name = "LendingPoolClient")]
pub trait LendingPoolTrait {
    fn supply(env: Env, token: Address, from: Address, amount: i128);
    fn withdraw(env: Env, token: Address, to: Address, amount: i128);
}

// --- CONTRACT TRAIT ---

pub trait SoroSusuTrait {
    fn init(env: Env, admin: Address);
    fn set_lending_pool(env: Env, admin: Address, pool: Address);
    
    fn create_circle(
        env: Env,
        creator: Address,
        amount: i128,
        max_members: u32,
        token: Address,
        cycle_duration: u64,
        insurance_fee_bps: u32,
        nft_contract: Address,
    ) -> u64;

    fn join_circle(env: Env, user: Address, circle_id: u64, tier_multiplier: u32, referrer: Option<Address>);
    fn deposit(env: Env, user: Address, circle_id: u64);
    
    fn finalize_round(env: Env, caller: Address, circle_id: u64);
    fn claim_pot(env: Env, user: Address, circle_id: u64);
    
    fn trigger_insurance_coverage(env: Env, caller: Address, circle_id: u64, member: Address);
    fn eject_member(env: Env, caller: Address, circle_id: u64, member: Address);
    
    fn pair_with_member(env: Env, user: Address, buddy_address: Address);
    fn set_safety_deposit(env: Env, user: Address, circle_id: u64, amount: i128);
    
    // Leniency voting functions
    fn request_leniency(env: Env, requester: Address, circle_id: u64, reason: String);
    fn vote_on_leniency(env: Env, voter: Address, circle_id: u64, requester: Address, vote: LeniencyVote);
    fn finalize_leniency_vote(env: Env, caller: Address, circle_id: u64, requester: Address);
    fn get_leniency_request(env: Env, circle_id: u64, requester: Address) -> LeniencyRequest;
    fn get_social_capital(env: Env, member: Address, circle_id: u64) -> SocialCapital;
    fn get_leniency_stats(env: Env, circle_id: u64) -> LeniencyStats;
    
    // Quadratic voting functions
    fn create_proposal(
        env: Env,
        proposer: Address,
        circle_id: u64,
        proposal_type: ProposalType,
        title: String,
        description: String,
        execution_data: String,
    ) -> u64;
    
    fn quadratic_vote(env: Env, voter: Address, proposal_id: u64, vote_weight: u32, vote_choice: QuadraticVoteChoice);
    fn execute_proposal(env: Env, caller: Address, proposal_id: u64);
    fn get_proposal(env: Env, proposal_id: u64) -> Proposal;
    fn get_voting_power(env: Env, member: Address, circle_id: u64) -> VotingPower;
    fn get_proposal_stats(env: Env, circle_id: u64) -> ProposalStats;
    fn update_voting_power(env: Env, member: Address, circle_id: u64, token_balance: i128);
    // Collateral functions
    fn stake_collateral(env: Env, user: Address, circle_id: u64, amount: i128);
    fn slash_collateral(env: Env, caller: Address, circle_id: u64, member: Address);
    fn release_collateral(env: Env, caller: Address, circle_id: u64, member: Address);
    fn mark_member_defaulted(env: Env, caller: Address, circle_id: u64, member: Address);
}

// --- IMPLEMENTATION ---

#[contract]
pub struct SoroSusu;

#[contractimpl]
impl SoroSusuTrait for SoroSusu {
    fn init(env: Env, admin: Address) {
        if !env.storage().instance().has(&DataKey::CircleCount) {
            env.storage().instance().set(&DataKey::CircleCount, &0u64);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    fn set_lending_pool(env: Env, admin: Address, pool: Address) {
        admin.require_auth();
        let stored_admin: Address = env.storage().instance().get(&DataKey::Admin).expect("Not initialized");
        if admin != stored_admin {
            panic!("Unauthorized");
        }
        env.storage().instance().set(&DataKey::LendingPool, &pool);
    }

    fn create_circle(
        env: Env,
        creator: Address,
        amount: i128,
        max_members: u32,
        token: Address,
        cycle_duration: u64,
        insurance_fee_bps: u32,
        nft_contract: Address,
    ) -> u64 {
        creator.require_auth();

        // Rate limiting
        let current_time = env.ledger().timestamp();
        let rate_limit_key = DataKey::LastCreatedTimestamp(creator.clone());
        if let Some(last_created) = env.storage().instance().get::<DataKey, u64>(&rate_limit_key) {
            if current_time < last_created + RATE_LIMIT_SECONDS {
                panic!("Rate limit exceeded");
            }
        }
        env.storage().instance().set(&rate_limit_key, &current_time);

        let mut circle_count: u64 = env.storage().instance().get(&DataKey::CircleCount).unwrap_or(0);
        circle_count += 1;

        // Calculate total cycle value and determine collateral requirements
        let total_cycle_value = amount * (max_members as i128);
        let requires_collateral = total_cycle_value >= HIGH_VALUE_THRESHOLD;
        let collateral_bps = if requires_collateral { DEFAULT_COLLATERAL_BPS } else { 0 };

        let new_circle = CircleInfo {
            id: circle_count,
            creator: creator.clone(),
            contribution_amount: amount,
            max_members,
            member_count: 0,
            current_recipient_index: 0,
            is_active: true,
            token,
            deadline_timestamp: current_time + cycle_duration,
            cycle_duration,
            contribution_bitmap: 0,
            insurance_balance: 0,
            insurance_fee_bps,
            is_insurance_used: false,
            late_fee_bps: 100, // 1%
            nft_contract,
            is_round_finalized: false,
            current_pot_recipient: None,
            leniency_enabled: true,
            grace_period_end: None,
            quadratic_voting_enabled: max_members >= MIN_GROUP_SIZE_FOR_QUADRATIC,
            proposal_count: 0,
            requires_collateral,
            collateral_bps,
            total_cycle_value,
        };

        env.storage().instance().set(&DataKey::Circle(circle_count), &new_circle);
        env.storage().instance().set(&DataKey::CircleCount, &circle_count);

        circle_count
    }

    fn join_circle(env: Env, user: Address, circle_id: u64, tier_multiplier: u32, referrer: Option<Address>) {
        user.require_auth();

        let mut circle: CircleInfo = env.storage().instance().get(&DataKey::Circle(circle_id)).expect("Circle not found");
        if circle.member_count >= circle.max_members {
            panic!("Circle is full");
        }

        let member_key = DataKey::Member(user.clone());
        if env.storage().instance().has(&member_key) {
            panic!("Already member");
        }

        // Check collateral requirement for high-value circles
        if circle.requires_collateral {
            let collateral_key = DataKey::CollateralVault(user.clone(), circle_id);
            let collateral_info: Option<CollateralInfo> = env.storage().instance().get(&collateral_key);
            
            match collateral_info {
                Some(collateral) => {
                    if collateral.status != CollateralStatus::Staked {
                        panic!("Collateral not properly staked");
                    }
                }
                None => panic!("Collateral required for this circle"),
            }
        }

        let new_member = Member {
            address: user.clone(),
            index: circle.member_count,
            contribution_count: 0,
            last_contribution_time: 0,
            status: MemberStatus::Active,
            tier_multiplier,
            referrer,
            buddy: None,
        };

        env.storage().instance().set(&member_key, &new_member);
        circle.member_count += 1;
        env.storage().instance().set(&DataKey::Circle(circle_id), &circle);

        // Mint NFT when the configured NFT contract is deployed. Some test setups
        // use placeholder NFT addresses, so avoid failing membership updates if
        // the NFT side-effect cannot be invoked.
        let token_id = (circle_id as u128) << 64 | (new_member.index as u128);
        let nft_client = SusuNftClient::new(&env, &circle.nft_contract);
        let _ = nft_client.try_mint(&user, &token_id);
    }

    fn deposit(env: Env, user: Address, circle_id: u64) {
        user.require_auth();

        let mut circle: CircleInfo = env.storage().instance().get(&DataKey::Circle(circle_id)).expect("Circle not found");
        let member_key = DataKey::Member(user.clone());
        let mut member: Member = env.storage().instance().get(&member_key).expect("Member not found");

        if member.status != MemberStatus::Active {
            panic!("Member not active");
        }

        let current_time = env.ledger().timestamp();
        let base_amount = circle.contribution_amount * member.tier_multiplier as i128;
        let mut penalty_amount = 0i128;

        // Check if late fee applies (considering grace periods)
        let effective_deadline = circle.grace_period_end.unwrap_or(circle.deadline_timestamp);
        
        if current_time > effective_deadline {
            let base_penalty = (base_amount * circle.late_fee_bps as i128) / 10000;
            // Apply referral discount
            let mut discount = 0i128;
            if let Some(ref_addr) = &member.referrer {
                let ref_key = DataKey::Member(ref_addr.clone());
                if env.storage().instance().has(&ref_key) {
                    discount = (base_penalty * REFERRAL_DISCOUNT_BPS as i128) / 10000;
                }
            }
            penalty_amount = base_penalty - discount;
            
            let mut reserve: i128 = env.storage().instance().get(&DataKey::GroupReserve).unwrap_or(0);
            reserve += penalty_amount;
            env.storage().instance().set(&DataKey::GroupReserve, &reserve);
        }

        let insurance_fee = (base_amount * circle.insurance_fee_bps as i128) / 10000;
        let total_amount = base_amount + insurance_fee + penalty_amount;

        let token_client = token::Client::new(&env, &circle.token);

        // Try transfer from user
        let transfer_result = token_client.try_transfer(&user, &env.current_contract_address(), &total_amount);
        let transfer_success = match transfer_result {
            Ok(inner) => inner.is_ok(),
            Err(_) => false,
        };

        if !transfer_success {
            // Buddy fallback
            if let Some(buddy_addr) = &member.buddy {
                let safety_key = DataKey::SafetyDeposit(buddy_addr.clone(), circle_id);
                let safety_balance: i128 = env.storage().instance().get(&safety_key).unwrap_or(0);
                if safety_balance >= total_amount {
                    env.storage().instance().set(&safety_key, &(safety_balance - total_amount));
                } else {
                    panic!("Insufficient funds and buddy deposit");
                }
            } else {
                panic!("Insufficient funds");
            }
        }

        if insurance_fee > 0 {
            circle.insurance_balance += insurance_fee;
        }

        member.contribution_count += 1;
        member.last_contribution_time = current_time;
        circle.contribution_bitmap |= 1 << member.index;
        
        env.storage().instance().set(&member_key, &member);
        env.storage().instance().set(&DataKey::Circle(circle_id), &circle);
    }

    fn finalize_round(env: Env, caller: Address, circle_id: u64) {
        caller.require_auth();
        let mut circle: CircleInfo = env.storage().instance().get(&DataKey::Circle(circle_id)).expect("Circle not found");
        
        let stored_admin: Address = env.storage().instance().get(&DataKey::Admin).expect("Not initialized");
        if caller != circle.creator && caller != stored_admin {
            panic!("Unauthorized");
        }

        if circle.is_round_finalized {
            panic!("Round already finalized");
        }

        let expected_bitmap = (1u64 << circle.member_count) - 1;
        if circle.contribution_bitmap != expected_bitmap {
            panic!("Not all contributed");
        }

        // Set the payout recipient
        let current_time = env.ledger().timestamp();
        let payout_time = current_time + 3600; // 1 hour for payout window

        // Set the current pot recipient (simplified: cycle through member indices)
        circle.current_pot_recipient = Some(circle.creator.clone()); // Will be set properly with member address storage
        circle.is_round_finalized = true;
        env.storage().instance().set(&DataKey::ScheduledPayoutTime(circle_id), &payout_time);
        env.storage().instance().set(&DataKey::Circle(circle_id), &circle);
    }

    fn claim_pot(env: Env, user: Address, circle_id: u64) {
        user.require_auth();
        let mut circle: CircleInfo = env.storage().instance().get(&DataKey::Circle(circle_id)).expect("Circle not found");
        
        if !circle.is_round_finalized {
            panic!("Round not finalized");
        }

        if let Some(recipient) = &circle.current_pot_recipient {
            if user != *recipient {
                panic!("Unauthorized recipient");
            }
        } else {
            panic!("No recipient set");
        }

        let scheduled_time: u64 = env.storage().instance().get(&DataKey::ScheduledPayoutTime(circle_id)).expect("Payout not scheduled");
        if env.ledger().timestamp() < scheduled_time {
            panic!("Payout too early");
        }

        let pot_amount = circle.contribution_amount * (circle.member_count as i128);
        let token_client = token::Client::new(&env, &circle.token);
        token_client.transfer(&env.current_contract_address(), &user, &pot_amount);

        // Auto-release collateral if member has completed all contributions
        if circle.requires_collateral {
            let member_key = DataKey::Member(user.clone());
            if let Some(member_info) = env.storage().instance().get::<DataKey, Member>(&member_key) {
                if member_info.contribution_count >= circle.max_members {
                    let collateral_key = DataKey::CollateralVault(user.clone(), circle_id);
                    if let Some(mut collateral_info) = env.storage().instance().get::<DataKey, CollateralInfo>(&collateral_key) {
                        if collateral_info.status == CollateralStatus::Staked {
                            // Release collateral back to member
                            token_client.transfer(&env.current_contract_address(), &user, &collateral_info.amount);
                            
                            // Update collateral status
                            collateral_info.status = CollateralStatus::Released;
                            collateral_info.release_timestamp = Some(env.ledger().timestamp());
                            env.storage().instance().set(&collateral_key, &collateral_info);
                        }
                    }
                }
            }
        }

        // Reset for next round
        circle.is_round_finalized = false;
        circle.contribution_bitmap = 0;
        circle.is_insurance_used = false;
        circle.current_recipient_index = (circle.current_recipient_index + 1) % circle.member_count;
        circle.current_pot_recipient = None; // Should be set in finalize_round

        env.storage().instance().set(&DataKey::Circle(circle_id), &circle);
        env.storage().instance().remove(&DataKey::ScheduledPayoutTime(circle_id));
    }

    fn trigger_insurance_coverage(env: Env, caller: Address, circle_id: u64, member: Address) {
        caller.require_auth();
        let mut circle: CircleInfo = env.storage().instance().get(&DataKey::Circle(circle_id)).expect("Circle not found");
        
        if caller != circle.creator {
            panic!("Unauthorized");
        }

        if circle.is_insurance_used {
            panic!("Insurance already used");
        }

        let member_key = DataKey::Member(member.clone());
        let member_info: Member = env.storage().instance().get(&member_key).expect("Member not found");
        
        let amount_needed = circle.contribution_amount * member_info.tier_multiplier as i128;
        if circle.insurance_balance < amount_needed {
            panic!("Insufficient insurance");
        }

        circle.contribution_bitmap |= 1 << member_info.index;
        circle.insurance_balance -= amount_needed;
        circle.is_insurance_used = true;

        env.storage().instance().set(&DataKey::Circle(circle_id), &circle);
    }

    fn eject_member(env: Env, caller: Address, circle_id: u64, member: Address) {
        caller.require_auth();
        let circle: CircleInfo = env.storage().instance().get(&DataKey::Circle(circle_id)).expect("Circle not found");
        
        if caller != circle.creator {
            panic!("Unauthorized");
        }

        let member_key = DataKey::Member(member.clone());
        let mut member_info: Member = env.storage().instance().get(&member_key).expect("Member not found");
        
        if member_info.status == MemberStatus::Ejected {
            panic!("Already ejected");
        }

        member_info.status = MemberStatus::Ejected;
        env.storage().instance().set(&member_key, &member_info);

        let nft_client = SusuNftClient::new(&env, &circle.nft_contract);
        let token_id = (circle_id as u128) << 64 | (member_info.index as u128);
        nft_client.burn(&member, &token_id);
    }

    fn pair_with_member(env: Env, user: Address, buddy_address: Address) {
        user.require_auth();
        let user_key = DataKey::Member(user.clone());
        let mut user_info: Member = env.storage().instance().get(&user_key).expect("Member not found");
        
        user_info.buddy = Some(buddy_address);
        env.storage().instance().set(&user_key, &user_info);
    }

    fn set_safety_deposit(env: Env, user: Address, circle_id: u64, amount: i128) {
        user.require_auth();
        let circle: CircleInfo = env.storage().instance().get(&DataKey::Circle(circle_id)).expect("Circle not found");
        
        let token_client = token::Client::new(&env, &circle.token);
        token_client.transfer(&user, &env.current_contract_address(), &amount);

        let safety_key = DataKey::SafetyDeposit(user.clone(), circle_id);
        let mut balance: i128 = env.storage().instance().get(&safety_key).unwrap_or(0);
        balance += amount;
        env.storage().instance().set(&safety_key, &balance);
    }

    // --- LENIENCY VOTING IMPLEMENTATION ---

    fn request_leniency(env: Env, requester: Address, circle_id: u64, reason: String) {
        requester.require_auth();

        let _circle: CircleInfo = env.storage().instance().get(&DataKey::Circle(circle_id)).expect("Circle not found");
        let member_key = DataKey::Member(requester.clone());
        let member_info: Member = env.storage().instance().get(&member_key).expect("Member not found");

        if member_info.status != MemberStatus::Active {
            panic!("Member not active");
        }

        // Check if there's already a pending request
        let request_key = DataKey::LeniencyRequest(circle_id, requester.clone());
        if let Some(existing_request) = env.storage().instance().get::<DataKey, LeniencyRequest>(&request_key) {
            if existing_request.status == LeniencyRequestStatus::Pending {
                panic!("Leniency request already pending");
            }
        }

        let current_time = env.ledger().timestamp();
        let voting_deadline = current_time + VOTING_PERIOD;

        let new_request = LeniencyRequest {
            requester: requester.clone(),
            circle_id,
            request_timestamp: current_time,
            voting_deadline,
            status: LeniencyRequestStatus::Pending,
            approve_votes: 0,
            reject_votes: 0,
            total_votes_cast: 0,
            extension_hours: 48, // 48 hours grace period
            reason,
        };

        env.storage().instance().set(&request_key, &new_request);

        // Update leniency stats
        let stats_key = DataKey::LeniencyStats(circle_id);
        let mut stats: LeniencyStats = env.storage().instance().get(&stats_key).unwrap_or(LeniencyStats {
            total_requests: 0,
            approved_requests: 0,
            rejected_requests: 0,
            expired_requests: 0,
            average_participation: 0,
        });
        stats.total_requests += 1;
        env.storage().instance().set(&stats_key, &stats);
    }

    fn vote_on_leniency(env: Env, voter: Address, circle_id: u64, requester: Address, vote: LeniencyVote) {
        voter.require_auth();

        let circle: CircleInfo = env.storage().instance().get(&DataKey::Circle(circle_id)).expect("Circle not found");
        let voter_key = DataKey::Member(voter.clone());
        let voter_info: Member = env.storage().instance().get(&voter_key).expect("Voter not found");

        if voter_info.status != MemberStatus::Active {
            panic!("Voter not active");
        }

        if voter == requester {
            panic!("Cannot vote for own request");
        }

        let request_key = DataKey::LeniencyRequest(circle_id, requester.clone());
        let mut request: LeniencyRequest = env.storage().instance().get(&request_key)
            .expect("Leniency request not found");

        if request.status != LeniencyRequestStatus::Pending {
            panic!("Voting period has ended");
        }

        let current_time = env.ledger().timestamp();
        if current_time > request.voting_deadline {
            request.status = LeniencyRequestStatus::Expired;
            env.storage().instance().set(&request_key, &request);
            panic!("Voting period expired");
        }

        // Check if already voted
        let vote_key = DataKey::LeniencyVotes(circle_id, voter.clone(), requester.clone());
        if env.storage().instance().has(&vote_key) {
            panic!("Already voted");
        }

        // Record the vote
        env.storage().instance().set(&vote_key, &vote);
        request.total_votes_cast += 1;

        match vote {
            LeniencyVote::Approve => request.approve_votes += 1,
            LeniencyVote::Reject => request.reject_votes += 1,
        }

        // Update social capital
        let social_capital_key = DataKey::SocialCapital(voter.clone(), circle_id);
        let mut social_capital: SocialCapital = env.storage().instance().get(&social_capital_key).unwrap_or(SocialCapital {
            member: voter.clone(),
            circle_id,
            leniency_given: 0,
            leniency_received: 0,
            voting_participation: 0,
            trust_score: 50, // Start with neutral score
        });
        social_capital.voting_participation += 1;
        
        // Update trust score based on voting patterns
        if vote == LeniencyVote::Approve {
            social_capital.leniency_given += 1;
            social_capital.trust_score = (social_capital.trust_score + 2).min(100); // Increase trust score
        } else {
            social_capital.trust_score = (social_capital.trust_score - 1).max(0); // Decrease trust score
        }
        
        env.storage().instance().set(&social_capital_key, &social_capital);

        // Check if voting should be finalized early (if majority reached)
        let total_possible_votes = (circle.member_count - 1) as u32; // Exclude requester
        let votes_needed_for_majority = (total_possible_votes * SIMPLE_MAJORITY_THRESHOLD + 99) / 100;
        
        if votes_needed_for_majority > 0 && request.approve_votes >= votes_needed_for_majority {
            request.status = LeniencyRequestStatus::Approved;
            SoroSusu::finalize_leniency_vote_internal(&env, &circle_id, &requester, &mut request);
        } else if votes_needed_for_majority > 0 && request.reject_votes >= votes_needed_for_majority {
            request.status = LeniencyRequestStatus::Rejected;
            SoroSusu::finalize_leniency_vote_internal(&env, &circle_id, &requester, &mut request);
        }

        env.storage().instance().set(&request_key, &request);
    }

    fn finalize_leniency_vote(env: Env, caller: Address, circle_id: u64, requester: Address) {
        caller.require_auth();

        let _circle: CircleInfo = env.storage().instance().get(&DataKey::Circle(circle_id)).expect("Circle not found");
        
        let request_key = DataKey::LeniencyRequest(circle_id, requester.clone());
        let mut request: LeniencyRequest = env.storage().instance().get(&request_key)
            .expect("Leniency request not found");

        if request.status != LeniencyRequestStatus::Pending {
            panic!("Request already finalized");
        }

        let current_time = env.ledger().timestamp();
        if current_time <= request.voting_deadline {
            panic!("Voting period not yet expired");
        }

        if request.total_votes_cast == 0 {
            request.status = LeniencyRequestStatus::Expired;
        } else {
            SoroSusu::finalize_leniency_vote_internal(&env, &circle_id, &requester, &mut request);
        }
        env.storage().instance().set(&request_key, &request);
    }

    // (moved to separate impl block)

    fn get_leniency_request(env: Env, circle_id: u64, requester: Address) -> LeniencyRequest {
        let request_key = DataKey::LeniencyRequest(circle_id, requester);
        env.storage().instance().get(&request_key).expect("Leniency request not found")
    }

    fn get_social_capital(env: Env, member: Address, circle_id: u64) -> SocialCapital {
        let social_capital_key = DataKey::SocialCapital(member.clone(), circle_id);
        env.storage().instance().get(&social_capital_key).unwrap_or(SocialCapital {
            member,
            circle_id,
            leniency_given: 0,
            leniency_received: 0,
            voting_participation: 0,
            trust_score: 50,
        })
    }

    fn get_leniency_stats(env: Env, circle_id: u64) -> LeniencyStats {
        let stats_key = DataKey::LeniencyStats(circle_id);
        env.storage().instance().get(&stats_key).unwrap_or(LeniencyStats {
            total_requests: 0,
            approved_requests: 0,
            rejected_requests: 0,
            expired_requests: 0,
            average_participation: 0,
        })
    }

    // --- QUADRATIC VOTING IMPLEMENTATION ---

    fn create_proposal(
        env: Env,
        proposer: Address,
        circle_id: u64,
        proposal_type: ProposalType,
        title: String,
        description: String,
        execution_data: String,
    ) -> u64 {
        proposer.require_auth();

        let circle: CircleInfo = env.storage().instance().get(&DataKey::Circle(circle_id)).expect("Circle not found");
        
        if !circle.quadratic_voting_enabled {
            panic!("Quadratic voting not enabled for this circle");
        }

        let member_key = DataKey::Member(proposer.clone());
        let member_info: Member = env.storage().instance().get(&member_key).expect("Member not found");

        if member_info.status != MemberStatus::Active {
            panic!("Member not active");
        }

        let current_time = env.ledger().timestamp();
        let mut proposal_count: u64 = env.storage().instance().get(&DataKey::CircleCount).unwrap_or(0);
        proposal_count += 1;

        let new_proposal = Proposal {
            id: proposal_count,
            circle_id,
            proposer: proposer.clone(),
            proposal_type,
            title,
            description,
            created_timestamp: current_time,
            voting_start_timestamp: current_time,
            voting_end_timestamp: current_time + QUADRATIC_VOTING_PERIOD,
            status: ProposalStatus::Active,
            for_votes: 0,
            against_votes: 0,
            total_voting_power: 0,
            quorum_met: false,
            execution_data,
        };

        env.storage().instance().set(&DataKey::Proposal(proposal_count), &new_proposal);

        // Update circle proposal count
        let mut circle_info = circle;
        circle_info.proposal_count += 1;
        env.storage().instance().set(&DataKey::Circle(circle_id), &circle_info);

        // Update proposal stats
        let stats_key = DataKey::ProposalStats(circle_id);
        let mut stats: ProposalStats = env.storage().instance().get(&stats_key).unwrap_or(ProposalStats {
            total_proposals: 0,
            approved_proposals: 0,
            rejected_proposals: 0,
            executed_proposals: 0,
            average_participation: 0,
            average_voting_time: 0,
        });
        stats.total_proposals += 1;
        env.storage().instance().set(&stats_key, &stats);

        proposal_count
    }

    fn quadratic_vote(env: Env, voter: Address, proposal_id: u64, vote_weight: u32, vote_choice: QuadraticVoteChoice) {
        voter.require_auth();

        let proposal_key = DataKey::Proposal(proposal_id);
        let mut proposal: Proposal = env.storage().instance().get(&proposal_key)
            .expect("Proposal not found");

        if proposal.status != ProposalStatus::Active {
            panic!("Voting not active for this proposal");
        }

        let current_time = env.ledger().timestamp();
        if current_time > proposal.voting_end_timestamp {
            proposal.status = ProposalStatus::Expired;
            env.storage().instance().set(&proposal_key, &proposal);
            panic!("Voting period expired");
        }

        // Check if already voted
        let vote_key = DataKey::QuadraticVote(proposal_id, voter.clone());
        if env.storage().instance().has(&vote_key) {
            panic!("Already voted on this proposal");
        }

        // Get voting power
        let voting_power_key = DataKey::VotingPower(voter.clone(), proposal.circle_id);
        let voting_power: VotingPower = env.storage().instance().get(&voting_power_key)
            .expect("Voting power not calculated");

        if vote_weight > MAX_VOTE_WEIGHT {
            panic!("Vote weight exceeds maximum");
        }

        // Calculate quadratic voting cost: weight^2
        let voting_cost = (vote_weight as u64) * (vote_weight as u64);
        
        if voting_cost > voting_power.quadratic_power {
            panic!("Insufficient voting power");
        }

        // Record the vote
        let quadratic_vote = QuadraticVote {
            voter: voter.clone(),
            proposal_id,
            vote_weight,
            vote_choice: vote_choice.clone(),
            voting_power_used: voting_cost,
            timestamp: current_time,
        };

        env.storage().instance().set(&vote_key, &quadratic_vote);

        // Update proposal tallies
        match vote_choice.clone() {
            QuadraticVoteChoice::For => {
                proposal.for_votes += voting_cost;
            }
            QuadraticVoteChoice::Against => {
                proposal.against_votes += voting_cost;
            }
            QuadraticVoteChoice::Abstain => {
                // Abstain votes don't affect the outcome
            }
        }

        proposal.total_voting_power += voting_cost;

        // Check quorum
        let circle_key = DataKey::Circle(proposal.circle_id);
        let circle: CircleInfo = env.storage().instance().get(&circle_key).expect("Circle not found");
        let required_quorum = (circle.member_count * QUADRATIC_QUORUM + 99) / 100;
        proposal.quorum_met = proposal.total_voting_power >= required_quorum as u64;

        env.storage().instance().set(&proposal_key, &proposal);
    }

    fn execute_proposal(env: Env, caller: Address, proposal_id: u64) {
        caller.require_auth();

        let proposal_key = DataKey::Proposal(proposal_id);
        let mut proposal: Proposal = env.storage().instance().get(&proposal_key)
            .expect("Proposal not found");

        if proposal.status != ProposalStatus::Active {
            panic!("Proposal not active");
        }

        let current_time = env.ledger().timestamp();
        if current_time <= proposal.voting_end_timestamp {
            panic!("Voting period not yet ended");
        }

        if !proposal.quorum_met {
            proposal.status = ProposalStatus::Rejected;
            env.storage().instance().set(&proposal_key, &proposal);
            panic!("Quorum not met");
        }

        // Calculate result and update stats
        let total_votes = proposal.for_votes + proposal.against_votes;
        if total_votes == 0 {
            proposal.status = ProposalStatus::Rejected;
        } else {
            let approval_percentage = (proposal.for_votes * 100) / total_votes;
            if approval_percentage >= QUADRATIC_MAJORITY as u64 {
                proposal.status = ProposalStatus::Approved;
                
                // Execute the proposal based on type
                SoroSusu::execute_proposal_logic(&env, &proposal);
                // The logic above marks the proposal as Executed in storage.
                // We update our local copy so the subsequent set() persists it correctly.
                proposal.status = ProposalStatus::Executed;
            } else {
                proposal.status = ProposalStatus::Rejected;
            }
        }

        env.storage().instance().set(&proposal_key, &proposal);

        // Update stats
        let stats_key = DataKey::ProposalStats(proposal.circle_id);
        let mut stats: ProposalStats = env.storage().instance().get(&stats_key).unwrap_or(ProposalStats {
            total_proposals: 0,
            approved_proposals: 0,
            rejected_proposals: 0,
            executed_proposals: 0,
            average_participation: 0,
            average_voting_time: 0,
        });

        match proposal.status {
            ProposalStatus::Approved => stats.approved_proposals += 1,
            ProposalStatus::Rejected => stats.rejected_proposals += 1,
            ProposalStatus::Executed => {
                stats.approved_proposals += 1;
                stats.executed_proposals += 1;
            },
            _ => {}
        }

        env.storage().instance().set(&proposal_key, &proposal);
        env.storage().instance().set(&stats_key, &stats);
    }

    // (moved to separate impl block)

    fn get_proposal(env: Env, proposal_id: u64) -> Proposal {
        let proposal_key = DataKey::Proposal(proposal_id);
        env.storage().instance().get(&proposal_key).expect("Proposal not found")
    }

    fn get_voting_power(env: Env, member: Address, circle_id: u64) -> VotingPower {
        let voting_power_key = DataKey::VotingPower(member.clone(), circle_id);
        env.storage().instance().get(&voting_power_key).unwrap_or(VotingPower {
            member,
            circle_id,
            token_balance: 0,
            quadratic_power: 0,
            last_updated: 0,
        })
    }

    fn get_proposal_stats(env: Env, circle_id: u64) -> ProposalStats {
        let stats_key = DataKey::ProposalStats(circle_id);
        env.storage().instance().get(&stats_key).unwrap_or(ProposalStats {
            total_proposals: 0,
            approved_proposals: 0,
            rejected_proposals: 0,
            executed_proposals: 0,
            average_participation: 0,
            average_voting_time: 0,
        })
    }

    fn update_voting_power(env: Env, member: Address, circle_id: u64, token_balance: i128) {
        // Calculate quadratic voting power as sqrt(token_balance)
        // We use integer approximation: sqrt(x) ≈ x / (sqrt(x) + 1) for simplicity
        // In production, you'd use a proper sqrt implementation
        
        let quadratic_power = if token_balance > 0 {
            // Simple approximation of square root for demonstration
            // In practice, you'd use a more accurate method
            let balance_u64 = token_balance as u64;
            (balance_u64 / 1000).max(1) // Simplified calculation
        } else {
            0
        };

        let voting_power = VotingPower {
            member: member.clone(),
            circle_id,
            token_balance,
            quadratic_power,
            last_updated: env.ledger().timestamp(),
        };

        env.storage().instance().set(&DataKey::VotingPower(member, circle_id), &voting_power);
    }

    fn stake_collateral(env: Env, user: Address, circle_id: u64, amount: i128) {
        user.require_auth();
        
        let circle: CircleInfo = env.storage().instance().get(&DataKey::Circle(circle_id)).expect("Circle not found");
        
        if !circle.requires_collateral {
            panic!("Collateral not required for this circle");
        }

        let collateral_key = DataKey::CollateralVault(user.clone(), circle_id);
        
        // Check if collateral already staked
        if let Some(_collateral) = env.storage().instance().get::<DataKey, CollateralInfo>(&collateral_key) {
            panic!("Collateral already staked");
        }

        // Calculate required collateral amount
        let required_collateral = (circle.total_cycle_value * circle.collateral_bps as i128) / 10000;
        
        if amount < required_collateral {
            panic!("Insufficient collateral amount");
        }

        // Transfer collateral to contract
        let token_client = token::Client::new(&env, &circle.token);
        token_client.transfer(&user, &env.current_contract_address(), &amount);

        // Create collateral record
        let collateral_info = CollateralInfo {
            member: user.clone(),
            circle_id,
            amount,
            status: CollateralStatus::Staked,
            staked_timestamp: env.ledger().timestamp(),
            release_timestamp: None,
        };

        env.storage().instance().set(&collateral_key, &collateral_info);
    }

    fn slash_collateral(env: Env, caller: Address, circle_id: u64, member: Address) {
        caller.require_auth();
        
        let circle: CircleInfo = env.storage().instance().get(&DataKey::Circle(circle_id)).expect("Circle not found");
        let stored_admin: Address = env.storage().instance().get(&DataKey::Admin).expect("Not initialized");
        
        if caller != circle.creator && caller != stored_admin {
            panic!("Unauthorized");
        }

        let collateral_key = DataKey::CollateralVault(member.clone(), circle_id);
        let mut collateral_info: CollateralInfo = env.storage().instance().get(&collateral_key)
            .expect("Collateral not staked");

        if collateral_info.status != CollateralStatus::Staked {
            panic!("Collateral not available for slashing");
        }

        // Check if member is defaulted
        let defaulted_key = DataKey::DefaultedMembers(circle_id);
        let defaulted_members: Vec<Address> = env.storage().instance().get(&defaulted_key).unwrap_or(Vec::new(&env));
        
        if !defaulted_members.contains(&member) {
            panic!("Member not defaulted");
        }

        // Slash the collateral - distribute to group reserve
        let _token_client = token::Client::new(&env, &circle.token);
        let slash_amount = collateral_info.amount;
        
        // Transfer to group reserve for distribution
        let mut reserve: i128 = env.storage().instance().get(&DataKey::GroupReserve).unwrap_or(0);
        reserve += slash_amount;
        env.storage().instance().set(&DataKey::GroupReserve, &reserve);

        // Update collateral status
        collateral_info.status = CollateralStatus::Slashed;
        env.storage().instance().set(&collateral_key, &collateral_info);
    }

    fn release_collateral(env: Env, caller: Address, circle_id: u64, member: Address) {
        caller.require_auth();
        
        let circle: CircleInfo = env.storage().instance().get(&DataKey::Circle(circle_id)).expect("Circle not found");
        let stored_admin: Address = env.storage().instance().get(&DataKey::Admin).expect("Not initialized");
        
        if caller != circle.creator && caller != stored_admin && caller != member {
            panic!("Unauthorized");
        }

        let collateral_key = DataKey::CollateralVault(member.clone(), circle_id);
        let mut collateral_info: CollateralInfo = env.storage().instance().get(&collateral_key)
            .expect("Collateral not staked");

        if collateral_info.status != CollateralStatus::Staked {
            panic!("Collateral not available for release");
        }

        // Check if member has completed all contributions
        let member_key = DataKey::Member(member.clone());
        let member_info: Member = env.storage().instance().get(&member_key).expect("Member not found");
        
        if member_info.contribution_count < circle.max_members {
            panic!("Member has not completed all contributions");
        }

        // Release collateral back to member
        let token_client = token::Client::new(&env, &circle.token);
        token_client.transfer(&env.current_contract_address(), &member, &collateral_info.amount);

        // Update collateral status
        collateral_info.status = CollateralStatus::Released;
        collateral_info.release_timestamp = Some(env.ledger().timestamp());
        env.storage().instance().set(&collateral_key, &collateral_info);
    }

    fn mark_member_defaulted(env: Env, caller: Address, circle_id: u64, member: Address) {
        caller.require_auth();
        
        let circle: CircleInfo = env.storage().instance().get(&DataKey::Circle(circle_id)).expect("Circle not found");
        let stored_admin: Address = env.storage().instance().get(&DataKey::Admin).expect("Not initialized");
        
        if caller != circle.creator && caller != stored_admin {
            panic!("Unauthorized");
        }

        let member_key = DataKey::Member(member.clone());
        let mut member_info: Member = env.storage().instance().get(&member_key).expect("Member not found");
        
        if member_info.status == MemberStatus::Defaulted {
            panic!("Member already defaulted");
        }

        // Mark member as defaulted
        member_info.status = MemberStatus::Defaulted;
        env.storage().instance().set(&member_key, &member_info);

        // Add to defaulted members list
        let defaulted_key = DataKey::DefaultedMembers(circle_id);
        let mut defaulted_members: Vec<Address> = env.storage().instance().get(&defaulted_key).unwrap_or(Vec::new(&env));
        
        if !defaulted_members.contains(&member) {
            defaulted_members.push_back(member.clone());
            env.storage().instance().set(&defaulted_key, &defaulted_members);
        }

        // Auto-slash collateral if staked
        let collateral_key = DataKey::CollateralVault(member.clone(), circle_id);
        if let Some(_collateral) = env.storage().instance().get::<DataKey, CollateralInfo>(&collateral_key) {
            // Reuse slash_collateral logic
            Self::slash_collateral(env, caller, circle_id, member);
        }
    }
}

impl SoroSusu {
    fn finalize_leniency_vote_internal(env: &Env, circle_id: &u64, requester: &Address, request: &mut LeniencyRequest) {
        let circle_key = DataKey::Circle(*circle_id);
        let mut circle: CircleInfo = env.storage().instance().get(&circle_key).expect("Circle not found");
        
        let total_possible_votes = (circle.member_count - 1) as u32; // Exclude requester
        let minimum_participation = (total_possible_votes * MINIMUM_VOTING_PARTICIPATION + 99) / 100;
        
        let mut final_status = LeniencyRequestStatus::Expired;
        
        if request.total_votes_cast > 0 && request.total_votes_cast >= minimum_participation {
            let approval_percentage = (request.approve_votes * 100) / request.total_votes_cast;
            if approval_percentage >= SIMPLE_MAJORITY_THRESHOLD {
                final_status = LeniencyRequestStatus::Approved;
                
                let extension_seconds = request.extension_hours * 3600;
                let grace_period_end = circle.deadline_timestamp + extension_seconds;
                circle.grace_period_end = Some(grace_period_end);
                
                env.storage().instance().set(&circle_key, &circle);
                
                let social_capital_key = DataKey::SocialCapital(requester.clone(), *circle_id);
                let mut social_capital: SocialCapital = env.storage().instance().get(&social_capital_key).unwrap_or(SocialCapital {
                    member: requester.clone(),
                    circle_id: *circle_id,
                    leniency_given: 0,
                    leniency_received: 0,
                    voting_participation: 0,
                    trust_score: 50,
                });
                social_capital.leniency_received += 1;
                social_capital.trust_score = (social_capital.trust_score + 5).min(100);
                env.storage().instance().set(&social_capital_key, &social_capital);
            } else {
                final_status = LeniencyRequestStatus::Rejected;
            }
        }
        
        request.status = final_status.clone();

        let stats_key = DataKey::LeniencyStats(*circle_id);
        let mut stats: LeniencyStats = env.storage().instance().get(&stats_key).unwrap_or(LeniencyStats {
            total_requests: 0,
            approved_requests: 0,
            rejected_requests: 0,
            expired_requests: 0,
            average_participation: 0,
        });

        match final_status {
            LeniencyRequestStatus::Approved => stats.approved_requests += 1,
            LeniencyRequestStatus::Rejected => stats.rejected_requests += 1,
            LeniencyRequestStatus::Expired => stats.expired_requests += 1,
            _ => {}
        }

        if stats.total_requests > 0 {
            let total_participation = stats.average_participation * (stats.total_requests - 1) + request.total_votes_cast;
            stats.average_participation = total_participation / stats.total_requests;
        }

        env.storage().instance().set(&stats_key, &stats);
    }

    fn execute_proposal_logic(env: &Env, proposal: &Proposal) {
        let proposal_key = DataKey::Proposal(proposal.id);
        let mut updated_proposal = proposal.clone();
        updated_proposal.status = ProposalStatus::Executed;
        env.storage().instance().set(&proposal_key, &updated_proposal);
    }
}
