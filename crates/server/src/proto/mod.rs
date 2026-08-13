// Everything in `pb` is machine-generated — tonic's prost output plus the
// serde impls emitted alongside it. We don't control its style, and each new
// clippy release finds fresh things to dislike in it (1.97 added
// `useless_borrows_in_formatting`, which fires 46 times on the serde file).
// Blanket-allow rather than chase it: the module contains no hand-written code
// for a lint to protect.
#[allow(clippy::all)]
pub mod pb {
    tonic::include_proto!("walletrpc");
    include!(concat!(env!("OUT_DIR"), "/walletrpc.serde.rs"));
}
