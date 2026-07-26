use sorosusu_contracts::incident_response::{
    build_incident_plan, build_pagerduty_event, choose_deployment_gate, IncidentSeverity,
    IncidentSignal, PagerDutyAction, AVAILABILITY_TARGET_BPS, CRITICAL_PATH_P99_BUDGET_MS,
};

fn signal(severity: IncidentSeverity) -> IncidentSignal {
    IncidentSignal {
        service: "settlement".into(),
        summary: "settlement p99 latency exceeded".into(),
        severity,
        metric: "latency_p99_ms".into(),
        observed_value: 149,
        threshold: CRITICAL_PATH_P99_BUDGET_MS,
    }
}

#[test]
fn sev1_plan_triggers_pagerduty_and_runbook() {
    let plan = build_incident_plan(signal(IncidentSeverity::Sev1), "routing-key");

    let event = plan.pagerduty_event.expect("sev1 should trigger page");
    assert_eq!(event.event_action, PagerDutyAction::Trigger);
    assert_eq!(event.dedup_key, "verinode:settlement:latency_p99_ms:sev1");
    assert_eq!(event.severity, "sev1");
    assert!(event.custom_details.contains(&(
        "p99_budget_ms".into(),
        CRITICAL_PATH_P99_BUDGET_MS.to_string()
    )));
    assert!(event.custom_details.contains(&(
        "availability_target_bps".into(),
        AVAILABILITY_TARGET_BPS.to_string()
    )));
    assert!(plan
        .runbook
        .iter()
        .any(|step| step.name == "enable-blue-green-canary"));
    assert!(
        !plan.deployment_gate.promote,
        "sev1 canary must not auto-promote"
    );
}

#[test]
fn sev3_plan_records_queries_without_paging() {
    let plan = build_incident_plan(signal(IncidentSeverity::Sev3), "routing-key");

    assert!(plan.pagerduty_event.is_none());
    assert_eq!(plan.monitoring_queries.len(), 3);
    assert!(plan.monitoring_queries[0].contains("settlement"));
}

#[test]
fn deployment_gate_requires_healthy_canary() {
    let healthy = choose_deployment_gate(IncidentSeverity::Sev2, 9_999, 0);
    assert!(healthy.blue_green_enabled);
    assert_eq!(healthy.canary_percent, 10);
    assert!(healthy.promote);

    let burning_budget = choose_deployment_gate(IncidentSeverity::Sev2, 10_000, 1);
    assert!(!burning_budget.promote);

    let sev1 = choose_deployment_gate(IncidentSeverity::Sev1, 10_000, 0);
    assert_eq!(sev1.canary_percent, 1);
    assert!(!sev1.promote);
}

#[test]
fn pagerduty_acknowledge_event_uses_same_dedup_key() {
    let incident = signal(IncidentSeverity::Sev2);
    let trigger = build_pagerduty_event(&incident, "routing-key", PagerDutyAction::Trigger);
    let ack = build_pagerduty_event(&incident, "routing-key", PagerDutyAction::Acknowledge);

    assert_eq!(trigger.dedup_key, ack.dedup_key);
    assert_eq!(ack.event_action.as_str(), "acknowledge");
}
