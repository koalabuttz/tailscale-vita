use std::sync::Once;

static INIT: Once = Once::new();

pub(crate) fn install_panic_hook() {
    INIT.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let msg = format_panic_info(info);
            tracing::error!(kind = "panic", "{}", msg);
            crate::flush();
            prev(info);
        }));
    });
}

fn format_panic_info(info: &std::panic::PanicHookInfo<'_>) -> String {
    let location = info
        .location()
        .map(|l| format!("{}:{}", l.file(), l.line()))
        .unwrap_or_else(|| "?".into());
    let payload = info.payload();
    let msg = if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "?".into()
    };
    format!("{} at {}", msg, location)
}
