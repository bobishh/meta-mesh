#![cfg(target_family = "wasm")]

use std::sync::{
    Once,
    atomic::{AtomicBool, Ordering},
};

use wasm_bindgen::JsValue;

static TRANSPORT_TRACING: Once = Once::new();
static VERBOSE_TRANSPORT_LOGGING: AtomicBool = AtomicBool::new(false);

/// Takes ownership of browser transport tracing before Iroh starts its runtime.
///
/// Iroh's built-in browser subscriber emits every stream and connection debug event.
/// Keep the default console useful by showing only warnings and errors; developers can
/// explicitly enable verbose transport logs while reproducing a networking issue.
pub fn install_browser_transport_tracing() {
    TRANSPORT_TRACING.call_once(|| {
        use tracing_subscriber::prelude::*;

        let subscriber = tracing_subscriber::registry().with(BrowserTransportConsoleLayer);
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}

pub fn set_verbose_transport_logging(enabled: bool) {
    VERBOSE_TRANSPORT_LOGGING.store(enabled, Ordering::Relaxed);
}

pub fn verbose_transport_logging_enabled() -> bool {
    VERBOSE_TRANSPORT_LOGGING.load(Ordering::Relaxed)
}

struct BrowserTransportConsoleLayer;

impl<S> tracing_subscriber::Layer<S> for BrowserTransportConsoleLayer
where
    S: tracing::Subscriber,
{
    fn enabled(
        &self,
        metadata: &tracing::Metadata<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        let transport_event = metadata.target().starts_with("iroh_webrtc_transport")
            || metadata
                .target()
                .starts_with("iroh_webrtc_rust_browser_ping_pong");
        if !transport_event {
            return false;
        }

        matches!(
            *metadata.level(),
            tracing::Level::ERROR | tracing::Level::WARN
        ) || (verbose_transport_logging_enabled()
            && matches!(
                *metadata.level(),
                tracing::Level::INFO | tracing::Level::DEBUG
            ))
    }

    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let metadata = event.metadata();
        let mut fields = ConsoleTraceVisitor::default();
        event.record(&mut fields);

        let message = fields.message.unwrap_or_else(|| metadata.name().to_owned());
        let field_suffix = if fields.fields.is_empty() {
            String::new()
        } else {
            format!(" {}", fields.fields.join(" "))
        };
        let line = JsValue::from_str(&format!(
            "[{}] t={:.3} target={} {}{}",
            metadata.level(),
            js_sys::Date::now(),
            metadata.target(),
            message,
            field_suffix,
        ));
        match *metadata.level() {
            tracing::Level::ERROR => web_sys::console::error_1(&line),
            tracing::Level::WARN => web_sys::console::warn_1(&line),
            tracing::Level::INFO => web_sys::console::info_1(&line),
            tracing::Level::DEBUG | tracing::Level::TRACE => web_sys::console::debug_1(&line),
        }
    }
}

#[derive(Default)]
struct ConsoleTraceVisitor {
    message: Option<String>,
    fields: Vec<String>,
}

impl ConsoleTraceVisitor {
    fn record(&mut self, name: &str, value: String) {
        if name == "message" {
            self.message = Some(value);
        } else {
            self.fields.push(format!("{name}={value}"));
        }
    }
}

impl tracing::field::Visit for ConsoleTraceVisitor {
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.record(field.name(), value.to_string());
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.record(field.name(), value.to_string());
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.record(field.name(), value.to_string());
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.record(field.name(), value.to_owned());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.record(field.name(), format!("{value:?}"));
    }
}
