use soroban_sdk::{contracttype, symbol_short, Env, String, Symbol};

const TRACE_PREFIX: Symbol = symbol_short!("trace");
const LOG_PREFIX: Symbol = symbol_short!("log");

/// OpenTelemetry semantic-convention attribute names used by VeriNode logs.
pub mod semconv {
    pub const SERVICE_NAME: &str = "service.name";
    pub const SERVICE_VERSION: &str = "service.version";
    pub const DEPLOYMENT_ENVIRONMENT_NAME: &str = "deployment.environment.name";
    pub const EVENT_NAME: &str = "event.name";
    pub const ERROR_TYPE: &str = "error.type";
    pub const EXCEPTION_MESSAGE: &str = "exception.message";
    pub const CODE_FUNCTION: &str = "code.function";
    pub const CODE_NAMESPACE: &str = "code.namespace";
    pub const SERVER_ADDRESS: &str = "server.address";
    pub const URL_PATH: &str = "url.path";
    pub const USER_AGENT_ORIGINAL: &str = "user_agent.original";
    pub const VERINODE_CRITICAL_PATH: &str = "verinode.critical_path";
    pub const VERINODE_COMPONENT: &str = "verinode.component";
}

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SpanId(pub u64);

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TraceId(pub u64);

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LogSeverity {
    Trace,
    Debug,
    Info,
    Warn,
    Err,
    Fatal,
}

impl LogSeverity {
    pub fn text(&self) -> &'static str {
        match self {
            LogSeverity::Trace => "TRACE",
            LogSeverity::Debug => "DEBUG",
            LogSeverity::Info => "INFO",
            LogSeverity::Warn => "WARN",
            LogSeverity::Err => "ERROR",
            LogSeverity::Fatal => "FATAL",
        }
    }

    pub fn number(&self) -> u32 {
        match self {
            LogSeverity::Trace => 1,
            LogSeverity::Debug => 5,
            LogSeverity::Info => 9,
            LogSeverity::Warn => 13,
            LogSeverity::Err => 17,
            LogSeverity::Fatal => 21,
        }
    }
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogRecord {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub timestamp: u64,
    pub observed_timestamp: u64,
    pub severity_text: String,
    pub severity_number: u32,
    pub body: String,
    pub attributes: String,
}

pub struct StructuredLogger;

impl StructuredLogger {
    /// Emit an OpenTelemetry-compatible structured log as a Soroban event.
    ///
    /// Attributes are serialized as `key=value` pairs so constrained contract
    /// callers can attach semantic-convention fields without dynamic maps.
    pub fn emit(
        env: &Env,
        trace_id: TraceId,
        span_id: SpanId,
        severity: LogSeverity,
        body: &str,
        attributes: &[(&str, &str)],
    ) -> LogRecord {
        let now = env.ledger().timestamp();
        let attrs = encode_attributes(attributes);
        let record = LogRecord {
            trace_id,
            span_id,
            timestamp: now,
            observed_timestamp: now,
            severity_text: String::from_str(env, severity.text()),
            severity_number: severity.number(),
            body: String::from_str(env, body),
            attributes: String::from_str(env, &attrs),
        };

        env.events().publish(
            (LOG_PREFIX, symbol_short!("record")),
            (
                record.trace_id.0,
                record.span_id.0,
                record.timestamp,
                record.observed_timestamp,
                record.severity_text.clone(),
                record.severity_number,
                record.body.clone(),
                record.attributes.clone(),
            ),
        );

        record
    }

    pub fn info(
        env: &Env,
        trace_id: TraceId,
        span_id: SpanId,
        body: &str,
        attributes: &[(&str, &str)],
    ) -> LogRecord {
        Self::emit(env, trace_id, span_id, LogSeverity::Info, body, attributes)
    }

    pub fn error(
        env: &Env,
        trace_id: TraceId,
        span_id: SpanId,
        body: &str,
        attributes: &[(&str, &str)],
    ) -> LogRecord {
        Self::emit(env, trace_id, span_id, LogSeverity::Err, body, attributes)
    }
}

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
        let attrs = encode_attributes(attributes);

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
            trace_id: self.trace_id,
            span_id,
            parent_span_id,
            operation_name: String::from_str(env, operation_name),
            start_timestamp: now,
        }
    }

    pub fn end_span(&mut self, env: &Env, span: Span, status: &str) {
        let now = env.ledger().timestamp();
        let duration_ms = now.saturating_sub(span.start_timestamp) * 1000;
        self.end_span_at(env, span, status, now, duration_ms);
    }

    pub fn end_span_with_duration(
        &mut self,
        env: &Env,
        span: Span,
        status: &str,
        actual_duration_ms: u64,
    ) {
        let now = env.ledger().timestamp();
        self.end_span_at(env, span, status, now, actual_duration_ms);
    }

    fn end_span_at(&mut self, env: &Env, span: Span, status: &str, now: u64, duration_ms: u64) {
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
}

pub struct Span {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub parent_span_id: SpanId,
    pub operation_name: String,
    pub start_timestamp: u64,
}

pub fn encode_attributes(attributes: &[(&str, &str)]) -> alloc::string::String {
    attributes
        .iter()
        .map(|(k, v)| alloc::format!("{}={}", k, v))
        .collect::<alloc::vec::Vec<_>>()
        .join(",")
}

pub fn critical_path_attributes<'a>(component: &'a str) -> [(&'a str, &'a str); 2] {
    [
        (semconv::VERINODE_CRITICAL_PATH, "true"),
        (semconv::VERINODE_COMPONENT, component),
    ]
}

pub fn trace_enabled(env: &Env) -> bool {
    env.storage().instance().has(&DataKey::TracingEnabled)
}
pub fn enable_tracing(env: &Env) {
    env.storage()
        .instance()
        .set(&DataKey::TracingEnabled, &true);
}
pub fn disable_tracing(env: &Env) {
    env.storage().instance().remove(&DataKey::TracingEnabled);
}

pub fn generate_trace_id(env: &Env) -> TraceId {
    let nonce: u64 = env
        .storage()
        .instance()
        .get(&DataKey::TraceNonce)
        .unwrap_or(0);
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
