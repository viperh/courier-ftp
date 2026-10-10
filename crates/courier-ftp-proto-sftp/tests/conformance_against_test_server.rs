//! T22 AC1: the T03 backend conformance suite against the in-process SFTP server
//! (`testing::SftpTestServer`, russh + the SFTP test server over a temp directory).

use courier_ftp_proto_sftp::testing::conformance_env;

courier_ftp_core::backend_conformance_tests!(conformance_env);
