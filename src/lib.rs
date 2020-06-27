#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct xt_entry_target {
    pub target_size: __u16,
    pub name: [std::os::raw::c_char; XT_EXTENSION_MAXNAMELEN as _],
    pub revision: __u8,
    pub align: [u64; 0],
}
#[test]
fn test_layout_xt_entry_target() {
    assert_eq!(
        std::mem::size_of::<xt_entry_target>(),
        32usize,
        concat!("Size of: ", stringify!(xt_entry_target))
    );
    assert_eq!(
        std::mem::align_of::<xt_entry_target>(),
        8usize,
        concat!("Alignment of ", stringify!(xt_entry_target))
    );
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct xt_entry_match {
    pub match_size: __u16,
    pub name: [std::os::raw::c_char; XT_EXTENSION_MAXNAMELEN as _],
    pub revision: __u8,
    pub align: [u64; 0],
}
#[test]
fn test_layout_xt_entry_match() {
    assert_eq!(
        std::mem::size_of::<xt_entry_match>(),
        32usize,
        concat!("Size of: ", stringify!(xt_entry_target))
    );
    assert_eq!(
        std::mem::align_of::<xt_entry_match>(),
        8usize,
        concat!("Alignment of ", stringify!(xt_entry_match))
    );
}
