use soroban_sdk::{contracttype, Env};

/// Storage key for reentrancy guard status
#[contracttype]
#[derive(Clone)]
pub enum ReentrancyGuardKey {
    /// Tracks whether a contract is currently executing a protected function
    Entered,
}

/// Reentrancy guard implementation following OpenZeppelin pattern.
/// 
/// This guard protects against reentrancy attacks by tracking whether
/// a protected function is currently being executed. If a reentrant call
/// is detected, it will panic.
/// 
/// # Usage
/// 
/// ```ignore
/// let guard = ReentrancyGuard::new(env);
/// // Protected code here
/// // Guard automatically clears when dropped
/// ```
pub struct ReentrancyGuard<'a> {
    env: &'a Env,
}

impl<'a> ReentrancyGuard<'a> {
    /// Creates a new reentrancy guard. Panics if a reentrant call is detected.
    /// 
    /// # Panics
    /// 
    /// Panics with "ReentrancyGuard: reentrant call" if the guard is already active.
    pub fn new(env: &'a Env) -> Self {
        let entered: bool = env
            .storage()
            .instance()
            .get(&ReentrancyGuardKey::Entered)
            .unwrap_or(false);

        if entered {
            panic!("ReentrancyGuard: reentrant call");
        }

        // Set the entered flag
        env.storage()
            .instance()
            .set(&ReentrancyGuardKey::Entered, &true);

        Self { env }
    }

    /// Manually releases the guard. This is called automatically on drop,
    /// but can be called explicitly if needed.
    pub fn release(&self) {
        self.env
            .storage()
            .instance()
            .set(&ReentrancyGuardKey::Entered, &false);
    }
}

impl<'a> Drop for ReentrancyGuard<'a> {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SoroSusu;
    use soroban_sdk::Env;

    #[test]
    fn test_reentrancy_guard_allows_first_call() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SoroSusu);
        env.as_contract(&contract_id, || {
            let _guard = ReentrancyGuard::new(&env);
            // Should not panic
        });
    }

    #[test]
    #[should_panic(expected = "ReentrancyGuard: reentrant call")]
    fn test_reentrancy_guard_blocks_reentrant_call() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SoroSusu);
        env.as_contract(&contract_id, || {
            let _guard1 = ReentrancyGuard::new(&env);
            let _guard2 = ReentrancyGuard::new(&env); // Should panic
        });
    }

    #[test]
    fn test_reentrancy_guard_allows_after_drop() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SoroSusu);
        env.as_contract(&contract_id, || {
            {
                let _guard = ReentrancyGuard::new(&env);
            } // Guard dropped here
            let _guard2 = ReentrancyGuard::new(&env); // Should not panic
        });
    }

    #[test]
    fn test_reentrancy_guard_manual_release() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SoroSusu);
        env.as_contract(&contract_id, || {
            let guard = ReentrancyGuard::new(&env);
            guard.release();
            let _guard2 = ReentrancyGuard::new(&env); // Should not panic
        });
    }
}
