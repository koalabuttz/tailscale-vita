//! `info!`/`warn!`/`error!`/`debug!`/`trace!` macros designed to be
//! drop-in compatible with the most common `tracing` invocation
//! patterns.
//!
//! Supported forms:
//! - `info!("plain message")`
//! - `info!("formatted: {}", x)`
//! - `info!(key = %expr, "msg")` — `%expr` formats via Display
//! - `info!(key = ?expr, "msg")` — `?expr` formats via Debug
//! - `info!(key = expr, "msg")` — formats via Display
//! - `info!(?expr, "msg")` / `info!(%expr, "msg")` — positional
//!   shorthand; field is named by the stringified expression
//! - `info!(ident, "msg")` — bare-ident sugar (`ident = ident`)
//! - Any combination of fields + trailing fmt-string + args.
//!
//! Output format: `"key1=val1 key2=val2 msg"`. Loses tracing's
//! structured-logging JSON output but log.txt stays human-readable.
//!
//! Field-syntax handling uses the standard tt-munching pattern:
//! the outer macro accepts a token tree and forwards to a `__fmt`
//! helper that peels off one field at a time until it hits the
//! trailing format string.

#[doc(hidden)]
#[macro_export]
macro_rules! __vita_log_fmt {
    // Base case: just a fmt string + args, no fields.
    ($prefix:expr; $fmt:literal $(, $arg:expr)* $(,)?) => {
        format_args!(concat!("{}", $fmt), $prefix $(, $arg)*)
    };

    // Field with % (Display).
    ($prefix:expr; $key:ident = % $value:expr, $($rest:tt)*) => {
        $crate::__vita_log_fmt!(
            format!("{}{}={} ", $prefix, stringify!($key), $value);
            $($rest)*
        )
    };

    // Field with ? (Debug).
    ($prefix:expr; $key:ident = ? $value:expr, $($rest:tt)*) => {
        $crate::__vita_log_fmt!(
            format!("{}{}={:?} ", $prefix, stringify!($key), $value);
            $($rest)*
        )
    };

    // Positional Debug shorthand: `?expr` with no key. Names the field
    // by the stringified expression, matching tracing's `?expr` /
    // `?self.field` form.
    ($prefix:expr; ? $value:expr, $($rest:tt)*) => {
        $crate::__vita_log_fmt!(
            format!("{}{}={:?} ", $prefix, stringify!($value), $value);
            $($rest)*
        )
    };

    // Positional Display shorthand: `%expr` with no key.
    ($prefix:expr; % $value:expr, $($rest:tt)*) => {
        $crate::__vita_log_fmt!(
            format!("{}{}={} ", $prefix, stringify!($value), $value);
            $($rest)*
        )
    };

    // Field plain (Display).
    ($prefix:expr; $key:ident = $value:expr, $($rest:tt)*) => {
        $crate::__vita_log_fmt!(
            format!("{}{}={} ", $prefix, stringify!($key), $value);
            $($rest)*
        )
    };

    // Bare identifier (sugar: `info!(seq, "msg")` == `info!(seq = seq, "msg")`).
    ($prefix:expr; $key:ident, $($rest:tt)*) => {
        $crate::__vita_log_fmt!(
            format!("{}{}={} ", $prefix, stringify!($key), $key);
            $($rest)*
        )
    };

    // No trailing fmt string — just fields, end the line with empty msg.
    ($prefix:expr;) => {
        format_args!("{}", $prefix)
    };
}

/// `info!(...)` — emit an INFO-level log line.
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        $crate::__emit(
            $crate::Level::Info,
            file!(),
            line!(),
            $crate::__vita_log_fmt!(""; $($arg)*),
        )
    };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::__emit(
            $crate::Level::Warn,
            file!(),
            line!(),
            $crate::__vita_log_fmt!(""; $($arg)*),
        )
    };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::__emit(
            $crate::Level::Error,
            file!(),
            line!(),
            $crate::__vita_log_fmt!(""; $($arg)*),
        )
    };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        $crate::__emit(
            $crate::Level::Debug,
            file!(),
            line!(),
            $crate::__vita_log_fmt!(""; $($arg)*),
        )
    };
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        $crate::__emit(
            $crate::Level::Trace,
            file!(),
            line!(),
            $crate::__vita_log_fmt!(""; $($arg)*),
        )
    };
}
