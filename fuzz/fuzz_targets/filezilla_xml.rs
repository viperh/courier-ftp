//! FileZilla `sitemanager.xml` import (T32): the XML reader with its limits,
//! the field parsers and the remote directory decoder. Same body as
//! `courier-ftp-core` `sites::import_tests::fuzz_filezilla_xml_*`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_core::sites::fuzz_filezilla_xml(data);
});
