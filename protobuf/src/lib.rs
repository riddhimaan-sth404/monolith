#![allow(unsafe_code)]
#![allow(missing_docs)]
#![allow(unused_qualifications)]
#![allow(clippy::large_enum_variant)]

pub mod proto {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/protos/edr.proto.v1.rs"));
    }
}

pub use proto::v1 as types;
