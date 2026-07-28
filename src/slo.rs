//! Service Level Objective (SLO) monitoring and burn-rate alert helpers.
//!
//! This module contains deterministic, allocation-light primitives that every
//! VeriNode service can use to evaluate SLO compliance from rolling-window
//! counters. It intentionally keeps the core math in pure Rust so contracts,
//! off-chain indexers, alert managers, and dashboard exporters all evaluate the
//! same thresholds.

use soroban_sdk::{contracttype, symbol_short, Env, Symbol};

/// Critical-path latency SLO: P99 below 100 ms.
pub const CRITICAL_PATH_P99_TARGET_MS: u64 = 100;
/// Platform availability objective expressed in basis points (99.99%).
pub const AVAILABILITY_TARGET_BPS: u32 = 9_999;
/// Maximum allowed error budget burn rate before paging.
pub const DEFAULT_PAGE_BURN_RATE_X100: u64 = 1_400;
/// Maximum allowed error budget burn rate before opening a warning ticket.
pub const DEFAULT_TICKET_BURN_RATE_X100: u64 = 200;

const SLO_PREFIX: Symbol = symbol_short!("slo");

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SloSignal {
    Healthy,
    Ticket,
    Page,
}

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SloTarget {
    pub availability_bps: u32,
    pub latency_p99_ms: u64,
    pub page_burn_rate_x100: u64,
    pub ticket_burn_rate_x100: u64,
}

impl SloTarget {
    pub const fn default_system() -> Self {
        Self {
            availability_bps: AVAILABILITY_TARGET_BPS,
            latency_p99_ms: CRITICAL_PATH_P99_TARGET_MS,
            page_burn_rate_x100: DEFAULT_PAGE_BURN_RATE_X100,
            ticket_burn_rate_x100: DEFAULT_TICKET_BURN_RATE_X100,
        }
    }

    pub const fn error_budget_bps(&self) -> u32 {
        10_000u32.saturating_sub(self.availability_bps)
    }
}

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SloWindow {
    pub total_requests: u64,
    pub failed_requests: u64,
    pub latency_p99_ms: u64,
}

impl SloWindow {
    pub const fn empty(latency_p99_ms: u64) -> Self {
        Self {
            total_requests: 0,
            failed_requests: 0,
            latency_p99_ms,
        }
    }

    pub fn observed_error_bps(&self) -> u64 {
        if self.total_requests == 0 {
            return 0;
        }

        ((self.failed_requests as u128 * 10_000u128) / self.total_requests as u128) as u64
    }

    /// Returns burn rate multiplied by 100 to preserve two decimal places.
    pub fn burn_rate_x100(&self, target: &SloTarget) -> u64 {
        let budget_bps = target.error_budget_bps() as u128;
        if budget_bps == 0 {
            return if self.failed_requests == 0 {
                0
            } else {
                u64::MAX
            };
        }

        ((self.observed_error_bps() as u128 * 100u128) / budget_bps) as u64
    }

    pub fn latency_violates(&self, target: &SloTarget) -> bool {
        self.latency_p99_ms > target.latency_p99_ms
    }
}

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SloEvaluation {
    pub signal: SloSignal,
    pub burn_rate_x100: u64,
    pub observed_error_bps: u64,
    pub latency_violation: bool,
}

/// Evaluates a rolling window against the system SLO.
pub fn evaluate_window(window: &SloWindow, target: &SloTarget) -> SloEvaluation {
    let burn_rate_x100 = window.burn_rate_x100(target);
    let latency_violation = window.latency_violates(target);
    let signal = if burn_rate_x100 >= target.page_burn_rate_x100 || latency_violation {
        SloSignal::Page
    } else if burn_rate_x100 >= target.ticket_burn_rate_x100 {
        SloSignal::Ticket
    } else {
        SloSignal::Healthy
    };

    SloEvaluation {
        signal,
        burn_rate_x100,
        observed_error_bps: window.observed_error_bps(),
        latency_violation,
    }
}

/// Publishes compact metrics for off-chain monitoring, alerting, dashboards,
/// canary analysis, and runbook automation.
pub fn publish_slo_evaluation(env: &Env, service_id: u32, evaluation: &SloEvaluation) {
    env.events().publish(
        (SLO_PREFIX, symbol_short!("eval")),
        (
            service_id,
            evaluation.observed_error_bps,
            evaluation.burn_rate_x100,
            evaluation.latency_violation,
            evaluation.signal,
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_target_matches_issue_bounds() {
        let target = SloTarget::default_system();
        assert_eq!(target.availability_bps, 9_999);
        assert_eq!(target.error_budget_bps(), 1);
        assert_eq!(target.latency_p99_ms, 100);
    }

    #[test]
    fn healthy_when_no_error_budget_or_latency_violation() {
        let target = SloTarget::default_system();
        let window = SloWindow {
            total_requests: 1_000_000,
            failed_requests: 0,
            latency_p99_ms: 80,
        };
        assert_eq!(evaluate_window(&window, &target).signal, SloSignal::Healthy);
    }

    #[test]
    fn tickets_on_moderate_burn_rate() {
        let target = SloTarget::default_system();
        let window = SloWindow {
            total_requests: 1_000_000,
            failed_requests: 200,
            latency_p99_ms: 90,
        };
        let evaluation = evaluate_window(&window, &target);
        assert_eq!(evaluation.observed_error_bps, 2);
        assert_eq!(evaluation.burn_rate_x100, 200);
        assert_eq!(evaluation.signal, SloSignal::Ticket);
    }

    #[test]
    fn pages_on_fast_burn_rate() {
        let target = SloTarget::default_system();
        let window = SloWindow {
            total_requests: 1_000_000,
            failed_requests: 1_400,
            latency_p99_ms: 90,
        };
        assert_eq!(evaluate_window(&window, &target).signal, SloSignal::Page);
    }

    #[test]
    fn pages_on_latency_violation_even_without_errors() {
        let target = SloTarget::default_system();
        let window = SloWindow {
            total_requests: 10_000,
            failed_requests: 0,
            latency_p99_ms: 101,
        };
        let evaluation = evaluate_window(&window, &target);
        assert!(evaluation.latency_violation);
        assert_eq!(evaluation.signal, SloSignal::Page);
    }
}
