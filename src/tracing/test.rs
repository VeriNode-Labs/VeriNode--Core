#![cfg(test)]

extern crate alloc;

use super::*;
use crate::SoroSusu;
use soroban_sdk::testutils::{Address as AddressTestUtilsTrait, Ledger};
use soroban_sdk::Address;

fn setup_tracer(env: &Env) -> (Tracer, Address) {
    let contract_id = env.register_contract(None, SoroSusu);
    let tracer = Tracer::new(TraceId(42));
    (tracer, contract_id)
}

#[test]
fn test_tracer_new() {
    let trace_id = TraceId(42);
    let tracer = Tracer::new(trace_id.clone());
    assert_eq!(tracer.trace_id(), &trace_id);
}

#[test]
fn test_next_span_id_increments() {
    let mut tracer = Tracer::new(TraceId(1));
    let first = tracer.next_span_id();
    let second = tracer.next_span_id();
    assert_eq!(first, SpanId(1));
    assert_eq!(second, SpanId(2));
}

#[test]
fn test_start_span_creates_span() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1000);
    let (mut tracer, contract_id) = setup_tracer(&env);

    env.as_contract(&contract_id, || {
        let span = tracer.start_span(&env, "test_operation", SpanId(0), &[("key1", "val1")]);

        assert_eq!(span.span_id, SpanId(1));
        assert_eq!(span.trace_id, TraceId(42));
        assert_eq!(span.parent_span_id, SpanId(0));
        assert_eq!(span.operation_name, String::from_str(&env, "test_operation"));
        assert_eq!(span.start_timestamp, 1000);
    });
}

#[test]
fn test_end_span_completes() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1000);
    let (mut tracer, contract_id) = setup_tracer(&env);

    env.as_contract(&contract_id, || {
        let span = tracer.start_span(&env, "test_op", SpanId(0), &[]);
        env.ledger().set_timestamp(1005);
        tracer.end_span(&env, span, "ok");
    });
}

#[test]
fn test_generate_trace_id_unique() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(50000);
    let contract_id = env.register_contract(None, SoroSusu);

    env.as_contract(&contract_id, || {
        let tid1 = generate_trace_id(&env);
        let tid2 = generate_trace_id(&env);
        assert_ne!(tid1, tid2);
    });
}

#[test]
fn test_trace_enabled_default_false() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SoroSusu);

    env.as_contract(&contract_id, || {
        assert!(!trace_enabled(&env));
    });
}

#[test]
fn test_enable_disable_tracing() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SoroSusu);

    env.as_contract(&contract_id, || {
        assert!(!trace_enabled(&env));

        enable_tracing(&env);
        assert!(trace_enabled(&env));

        disable_tracing(&env);
        assert!(!trace_enabled(&env));
    });
}

#[test]
fn test_span_parent_child_relationship() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(2000);
    let (mut tracer, contract_id) = setup_tracer(&env);

    env.as_contract(&contract_id, || {
        let parent = tracer.start_span(&env, "parent_op", SpanId(0), &[]);
        let child = tracer.start_span(&env, "child_op", parent.span_id, &[]);

        assert_eq!(child.parent_span_id, parent.span_id);

        tracer.end_span(&env, child, "ok");
        tracer.end_span(&env, parent, "ok");
    });
}

#[test]
fn test_end_span_with_duration() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(2000);
    let (mut tracer, contract_id) = setup_tracer(&env);

    env.as_contract(&contract_id, || {
        let span = tracer.start_span(&env, "measured_op", SpanId(0), &[]);
        tracer.end_span_with_duration(&env, span, "ok", 150);
    });
}
