//! Incident response runbook automation and PagerDuty event preparation.
//!
//! This module is intentionally deterministic and side-effect free: it selects
//! runbooks, builds PagerDuty Events API payloads, and records deployment-gate
//! decisions without performing network I/O. Keeping network delivery in the
//! operator keeps critical contract/client paths small and makes the logic easy
//! to unit-test and security-review.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// P99 latency budget for critical incident automation paths, in milliseconds.
pub const CRITICAL_PATH_P99_BUDGET_MS: u64 = 100;

/// Availability target expressed in basis points (99.99%).
pub const AVAILABILITY_TARGET_BPS: u32 = 9_999;

/// Minimum canary success rate required before promoting a deployment.
pub const MIN_CANARY_SUCCESS_RATE_BPS: u32 = 9_995;

/// Incident severity used to choose escalation and rollout behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum IncidentSeverity {
    Sev1,
    Sev2,
    Sev3,
    Sev4,
}

impl IncidentSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sev1 => "sev1",
            Self::Sev2 => "sev2",
            Self::Sev3 => "sev3",
            Self::Sev4 => "sev4",
        }
    }

    pub fn is_page_required(self) -> bool {
        matches!(self, Self::Sev1 | Self::Sev2)
    }
}

/// PagerDuty Events API action for a deduplication key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagerDutyAction {
    Trigger,
    Acknowledge,
    Resolve,
}

impl PagerDutyAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trigger => "trigger",
            Self::Acknowledge => "acknowledge",
            Self::Resolve => "resolve",
        }
    }
}

/// A runbook selected for an incident.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunbookStep {
    pub name: String,
    pub command: String,
    pub rollback_command: String,
    pub critical: bool,
}

/// Incident signal provided by monitoring/alerting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncidentSignal {
    pub service: String,
    pub summary: String,
    pub severity: IncidentSeverity,
    pub metric: String,
    pub observed_value: u64,
    pub threshold: u64,
}

/// PagerDuty event payload data. Operators can serialize this into the Events
/// API v2 JSON shape using their HTTP client of choice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PagerDutyEvent {
    pub routing_key: String,
    pub event_action: PagerDutyAction,
    pub dedup_key: String,
    pub summary: String,
    pub source: String,
    pub severity: String,
    pub component: String,
    pub group: String,
    pub custom_details: Vec<(String, String)>,
}

/// Deployment strategy chosen during remediation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentGate {
    pub blue_green_enabled: bool,
    pub canary_percent: u8,
    pub promote: bool,
    pub reason: String,
}

/// Top-level automation plan for a signal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncidentAutomationPlan {
    pub signal: IncidentSignal,
    pub pagerduty_event: Option<PagerDutyEvent>,
    pub runbook: Vec<RunbookStep>,
    pub monitoring_queries: Vec<String>,
    pub deployment_gate: DeploymentGate,
}

/// Build a complete, deterministic automation plan.
pub fn build_incident_plan(signal: IncidentSignal, routing_key: &str) -> IncidentAutomationPlan {
    let pagerduty_event = if signal.severity.is_page_required() {
        Some(build_pagerduty_event(
            &signal,
            routing_key,
            PagerDutyAction::Trigger,
        ))
    } else {
        None
    };

    let deployment_gate = choose_deployment_gate(signal.severity, 10_000, 0);

    IncidentAutomationPlan {
        monitoring_queries: monitoring_queries(&signal.service),
        runbook: runbook_for(&signal),
        signal,
        pagerduty_event,
        deployment_gate,
    }
}

/// Build a PagerDuty Events API v2-compatible event model.
pub fn build_pagerduty_event(
    signal: &IncidentSignal,
    routing_key: &str,
    event_action: PagerDutyAction,
) -> PagerDutyEvent {
    PagerDutyEvent {
        routing_key: routing_key.to_string(),
        event_action,
        dedup_key: dedup_key(signal),
        summary: signal.summary.clone(),
        source: "verinode-core".to_string(),
        severity: signal.severity.as_str().to_string(),
        component: signal.service.clone(),
        group: "protocol".to_string(),
        custom_details: alloc::vec![
            ("metric".to_string(), signal.metric.clone()),
            (
                "observed_value".to_string(),
                signal.observed_value.to_string()
            ),
            ("threshold".to_string(), signal.threshold.to_string()),
            (
                "p99_budget_ms".to_string(),
                CRITICAL_PATH_P99_BUDGET_MS.to_string()
            ),
            (
                "availability_target_bps".to_string(),
                AVAILABILITY_TARGET_BPS.to_string()
            ),
        ],
    }
}

/// Decide whether a blue-green/canary deployment can be promoted.
pub fn choose_deployment_gate(
    severity: IncidentSeverity,
    canary_success_rate_bps: u32,
    canary_error_budget_burn_bps: u32,
) -> DeploymentGate {
    let promote = canary_success_rate_bps >= MIN_CANARY_SUCCESS_RATE_BPS
        && canary_error_budget_burn_bps == 0
        && !matches!(severity, IncidentSeverity::Sev1);

    DeploymentGate {
        blue_green_enabled: true,
        canary_percent: if matches!(severity, IncidentSeverity::Sev1) {
            1
        } else {
            10
        },
        promote,
        reason: if promote {
            "canary healthy; promote green environment".to_string()
        } else {
            "hold promotion; continue canary analysis or rollback".to_string()
        },
    }
}

fn dedup_key(signal: &IncidentSignal) -> String {
    let mut key = String::new();
    key.push_str("verinode:");
    key.push_str(&signal.service);
    key.push(':');
    key.push_str(&signal.metric);
    key.push(':');
    key.push_str(signal.severity.as_str());
    key
}

fn monitoring_queries(service: &str) -> Vec<String> {
    alloc::vec![
        format_alloc("latency_p99_ms{service=\"", service, "\"}"),
        format_alloc("availability_bps{service=\"", service, "\"}"),
        format_alloc("pagerduty_events_total{service=\"", service, "\"}"),
    ]
}

fn runbook_for(signal: &IncidentSignal) -> Vec<RunbookStep> {
    alloc::vec![
        RunbookStep {
            name: "acknowledge-page".to_string(),
            command: format_alloc(
                "pd incident acknowledge --dedup-key ",
                &dedup_key(signal),
                ""
            ),
            rollback_command: "pd incident resolve --note 'false-positive or mitigated'"
                .to_string(),
            critical: signal.severity.is_page_required(),
        },
        RunbookStep {
            name: "enable-blue-green-canary".to_string(),
            command: format_alloc("deploy green --service ", &signal.service, " --canary 10"),
            rollback_command: format_alloc(
                "deploy rollback --service ",
                &signal.service,
                " --to blue"
            ),
            critical: true,
        },
        RunbookStep {
            name: "capture-security-evidence".to_string(),
            command: format_alloc("security evidence collect --service ", &signal.service, ""),
            rollback_command: "security evidence archive --status superseded".to_string(),
            critical: true,
        },
    ]
}

fn format_alloc(prefix: &str, value: &str, suffix: &str) -> String {
    let mut out = String::new();
    out.push_str(prefix);
    out.push_str(value);
    out.push_str(suffix);
    out
}
