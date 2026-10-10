//! T22 AC1: the T03 backend conformance suite against the in-process SFTP server
//! (`testing::SftpTestServer`, russh + the SFTP test server over a temp directory).

#![allow(clippy::expect_used)]

use std::sync::Arc;

use courier_ftp_core::{
    backend::{
        Backend,
        conformance::{ConformanceEnv, MakeSymlink},
    },
    model::RemotePath,
};
use courier_ftp_proto_sftp::testing::{SftpTestKnobs, SftpTestServer};

/// A fresh server per case; `/scratch` is the scratch directory.
fn conformance_env() -> ConformanceEnv {
    let server = Arc::new(SftpTestServer::spawn(SftpTestKnobs::default()));
    let make_server = Arc::clone(&server);
    #[cfg(unix)]
    let make_symlink: Option<MakeSymlink> =
        Some(Box::new(move |link: &RemotePath, target: &str| {
            std::os::unix::fs::symlink(target, server.local(link.as_str()))
                .map_err(courier_ftp_core::Error::Io)
        }));
    #[cfg(not(unix))]
    let make_symlink: Option<MakeSymlink> = {
        drop(server);
        None
    };
    ConformanceEnv {
        scratch: RemotePath::parse("/scratch").expect("path"),
        make: Box::new(move || Ok(Box::new(make_server.backend_default()) as Box<dyn Backend>)),
        // Sparse files: ext4/xfs/APFS; NTFS would allocate 5 GiB.
        large_files: cfg!(any(target_os = "linux", target_os = "macos")),
        skip: Vec::new(),
        make_symlink,
    }
}

courier_ftp_core::backend_conformance_tests!(conformance_env);
