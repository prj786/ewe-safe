//! A row must not stay lit after the pointer has left the window.
//!
//! On Wayland a pointer that leaves a surface comes with no position, so GDK
//! fills the leave event with the LAST position it knew: a point inside the
//! window. WebKit reads that point to tell the page where the pointer went
//! ("it's very important the actual coordinates the WebProcess receives",
//! WebKitWebViewBase.cpp), hit-tests it, finds the same row and keeps its
//! `:hover`. Next to a tiled neighbour that is a sidebar item still lit while
//! the pointer is in the other window.
//!
//! The fix is the fact WebKit asks for: before its handler runs, the leave
//! event's point is moved outside the view.

use gtk::gdk;
use gtk::glib::translate::ToGlibPtr;
use gtk::prelude::WidgetExt;

/// Anywhere outside the view. Far enough that no rounding brings it back in.
const OUTSIDE: f64 = -10_000.0;

/// Connect to the web view of `window`. Call it once, when the window is built.
pub fn forget_hover_on_leave(window: &tauri::WebviewWindow) {
    let _ = window.with_webview(|platform| {
        platform.inner().connect_leave_notify_event(|_, event| {
            // only a real leave: a grab (a menu opening) or a move into a
            // child window keeps the pointer over the page
            if event.mode() == gdk::CrossingMode::Normal
                && event.detail() != gdk::NotifyType::Inferior
            {
                let raw: *const gdk::ffi::GdkEventCrossing = event.to_glib_none().0;
                // SAFETY: `raw` is the GdkEvent this signal is being emitted
                // with; it is alive for the whole emission, and GTK hands the
                // same struct to the handlers after this one, which is the
                // point. Only two plain doubles are written.
                unsafe {
                    let raw = raw.cast_mut();
                    (*raw).x = OUTSIDE;
                    (*raw).y = OUTSIDE;
                }
            }
            gtk::glib::Propagation::Proceed
        });
    });
}
