pub mod pb {
    tonic::include_proto!("walletrpc");
    include!(concat!(env!("OUT_DIR"), "/walletrpc.serde.rs"));
}
