use soroban_sdk::{contracttype, symbol_short, Env, String, Symbol};

const TRACE_PREFIX: Symbol = symbol_short!("trace");

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SpanId(pub u64);

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TraceId(pub u64);

pub struct Tracer {
    trace_id: TraceId,
    span_counter: u64,
}

impl Tracer {
    pub fn new(trace_id: TraceId) -> Self {
        Tracer {
            trace_id,
            span_counter: 0,
        }
    }

    pub fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    pub fn next_span_id(&mut self) -> SpanId {
        self.span_counter += 1;
        SpanId(self.span_counter)
    }

    pub fn start_span(
        &mut self,
        env: &Env,
        operation_name: &str,
        parent_span_id: SpanId,
        attributes: &[(&str, &str)],
    ) -> Span {
        let span_id = self.next_span_id();
        let now = env.ledger().timestamp();

        let attrs = attributes
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(",");

        env.events().publish(
            (TRACE_PREFIX, symbol_short!("sp_start")),
            (
                self.trace_id.0,
                span_id.0,
                parent_span_id.0,
                String::from_str(env, operation_name),
                now,
                String::from_str(env, &attrs),
            ),
        );

        Span {
            trace_id: self.trace_id.clone(),
            span_id,
            parent_span_id,
            operation_name: String::from_str(env, operation_name),
            start_timestamp: now,
        }
    }

    pub fn end_span(&mut self, env: &Env, span: Span, status: &str) {
        let now = env.ledger().timestamp();
        let duration_ms = now.saturating_sub(span.start_timestamp) * 1000;

        env.events().publish(
            (TRACE_PREFIX, symbol_short!("sp_end")),
            (
                span.trace_id.0,
                span.span_id.0,
                now,
                duration_ms,
                String::from_str(env, status),
            ),
        );
    }

    pub fn end_span_with_duration(
        &mut self,
        env: &Env,
        span: Span,
        status: &str,
        actual_duration_ms: u64,
    ) {
        let now = env.ledger().timestamp();

        env.events().publish(
            (TRACE_PREFIX, symbol_short!("sp_end")),
            (
                span.trace_id.0,
                span.span_id.0,
                now,
                actual_duration_ms,
                String::from_str(env, status),
            ),
        );
    }
}

pub struct Span {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub parent_span_id: SpanId,
    pub operation_name: String,
    pub start_timestamp: u64,
}

pub fn trace_enabled(env: &Env) -> bool {
    env.storage().instance().has(&DataKey::TracingEnabled)
}

pub fn enable_tracing(env: &Env) {
    env.storage().instance().set(&DataKey::TracingEnabled, &true);
}

pub fn disable_tracing(env: &Env) {
    env.storage().instance().remove(&DataKey::TracingEnabled);
}

pub fn generate_trace_id(env: &Env) -> TraceId {
    let nonce: u64 = env.storage().instance().get(&DataKey::TraceNonce).unwrap_or(0);
    let new_nonce = nonce.wrapping_add(1);
    env.storage()
        .instance()
        .set(&DataKey::TraceNonce, &new_nonce);
    let now = env.ledger().timestamp();
    TraceId(now.wrapping_mul(1000).wrapping_add(new_nonce))
}

#[contracttype]
#[derive(Clone)]
pub(crate) enum DataKey {
    TracingEnabled,
    TraceNonce,
}

#[cfg(test)]
mod test;
