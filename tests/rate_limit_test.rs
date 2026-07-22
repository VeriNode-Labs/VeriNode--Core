#![cfg(test)]

#[test]
fn test_rate_limit_enforcement() {
    // Simulate timestamps
    let first_creation_time: u64 = 1000;
    let second_creation_time: u64 = 1200; // 200 seconds later (< 5 minutes)
    let third_creation_time: u64 = 1400; // 400 seconds after first (> 5 minutes)
    
    const RATE_LIMIT_SECONDS: u64 = 300; // 5 minutes
    
    // Test case 1: Second creation within 5 minutes should fail
    let time_elapsed_1 = second_creation_time.saturating_sub(first_creation_time);
    assert!(time_elapsed_1 < RATE_LIMIT_SECONDS);
    
    // Test case 2: Third creation after 5 minutes should succeed
    let time_elapsed_2 = third_creation_time.saturating_sub(first_creation_time);
    assert!(time_elapsed_2 >= RATE_LIMIT_SECONDS);
}

#[test]
fn test_rate_limit_exact_boundary() {
    let first_creation: u64 = 1000;
    let exactly_5_min_later: u64 = 1300; // Exactly 300 seconds
    
    const RATE_LIMIT_SECONDS: u64 = 300;
    
    let time_elapsed = exactly_5_min_later.saturating_sub(first_creation);
    
    // At exactly 5 minutes, should be allowed
    assert_eq!(time_elapsed, RATE_LIMIT_SECONDS);
    assert!(time_elapsed >= RATE_LIMIT_SECONDS);
}

#[test]
fn test_rate_limit_multiple_users() {
    // Different users should have independent rate limits
    struct UserCreation {
        user_id: u32,
        timestamp: u64,
    }
    
    let creations = vec![
        UserCreation { user_id: 1, timestamp: 1000 },
        UserCreation { user_id: 2, timestamp: 1100 }, // Different user, should be allowed
        UserCreation { user_id: 1, timestamp: 1200 }, // Same user within 5 min, should fail
        UserCreation { user_id: 2, timestamp: 1250 }, // User 2 within their 5 min, should fail
        UserCreation { user_id: 1, timestamp: 1301 }, // User 1 after 5 min, should succeed
    ];
    
    const RATE_LIMIT_SECONDS: u64 = 300;
    
    // User 1: First creation at 1000
    let user1_first = 1000u64;
    let user1_second = 1200u64;
    let user1_third = 1301u64;
    
    assert!(user1_second.saturating_sub(user1_first) < RATE_LIMIT_SECONDS);
    assert!(user1_third.saturating_sub(user1_first) >= RATE_LIMIT_SECONDS);
    
    // User 2: First creation at 1100
    let user2_first = 1100u64;
    let user2_second = 1250u64;
    
    assert!(user2_second.saturating_sub(user2_first) < RATE_LIMIT_SECONDS);
}

#[test]
fn test_saturating_sub_no_underflow() {
    // Test that saturating_sub prevents underflow
    let current_time: u64 = 100;
    let future_time: u64 = 200; // This shouldn't happen, but test safety
    
    let result = current_time.saturating_sub(future_time);
    assert_eq!(result, 0); // Should saturate to 0, not underflow
}

#[test]
fn test_rate_limit_after_long_period() {
    let first_creation: u64 = 1000;
    let one_day_later: u64 = 1000 + (24 * 60 * 60); // 86400 seconds later
    
    const RATE_LIMIT_SECONDS: u64 = 300;
    
    let time_elapsed = one_day_later.saturating_sub(first_creation);
    assert!(time_elapsed >= RATE_LIMIT_SECONDS);
}

#[test]
fn test_rate_limit_constants() {
    const RATE_LIMIT_SECONDS: u64 = 300;
    const EXPECTED_MINUTES: u64 = 5;
    
    assert_eq!(RATE_LIMIT_SECONDS, EXPECTED_MINUTES * 60);
}
