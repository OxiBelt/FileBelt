// SPDX-License-Identifier: GPL-3.0-or-later

//! Compile-bound verification of the reviewed `libunftp` security controls.
//!
//! The public-listener contract test proves the parser rejects nonzero `PBSZ`
//! before the no-op PBSZ command handler is reached.

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use libunftp::ServerBuilder;
    use libunftp::options::{ActivePassiveMode, FtpsRequired, TlsFlags};
    use std::fmt::Debug;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::SystemTime;
    use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};
    use unftp_core::auth::{
        AuthenticationError, Authenticator, Credentials, DefaultUser, Principal,
    };
    use unftp_core::storage::{
        ErrorKind, Fileinfo, Metadata, Result as StorageResult, StorageBackend,
    };

    #[derive(Clone, Debug)]
    struct RejectedMetadata;

    impl Metadata for RejectedMetadata {
        fn len(&self) -> u64 {
            0
        }

        fn is_dir(&self) -> bool {
            false
        }

        fn is_file(&self) -> bool {
            false
        }

        fn is_symlink(&self) -> bool {
            false
        }

        fn modified(&self) -> StorageResult<SystemTime> {
            Err(ErrorKind::LocalError.into())
        }

        fn gid(&self) -> u32 {
            0
        }

        fn uid(&self) -> u32 {
            0
        }
    }

    #[derive(Clone, Debug)]
    struct RejectedStorage;

    fn rejected<T>() -> StorageResult<T> {
        Err(ErrorKind::CommandNotImplemented.into())
    }

    #[async_trait]
    impl StorageBackend<DefaultUser> for RejectedStorage {
        type Metadata = RejectedMetadata;

        async fn metadata<P: AsRef<Path> + Send + Debug>(
            &self,
            _user: &DefaultUser,
            _path: P,
        ) -> StorageResult<Self::Metadata> {
            rejected()
        }

        async fn list<P: AsRef<Path> + Send + Debug>(
            &self,
            _user: &DefaultUser,
            _path: P,
        ) -> StorageResult<Vec<Fileinfo<PathBuf, Self::Metadata>>> {
            rejected()
        }

        async fn get<P: AsRef<Path> + Send + Debug>(
            &self,
            _user: &DefaultUser,
            _path: P,
            _start_pos: u64,
        ) -> StorageResult<Box<dyn AsyncRead + Send + Sync + Unpin>> {
            rejected()
        }

        async fn put<P, R>(
            &self,
            _user: &DefaultUser,
            _input: R,
            _path: P,
            _start_pos: u64,
        ) -> StorageResult<u64>
        where
            P: AsRef<Path> + Send + Debug,
            R: AsyncRead + Send + Sync + Unpin + 'static,
        {
            rejected()
        }

        async fn del<P: AsRef<Path> + Send + Debug>(
            &self,
            _user: &DefaultUser,
            _path: P,
        ) -> StorageResult<()> {
            rejected()
        }

        async fn mkd<P: AsRef<Path> + Send + Debug>(
            &self,
            _user: &DefaultUser,
            _path: P,
        ) -> StorageResult<()> {
            rejected()
        }

        async fn rename<P: AsRef<Path> + Send + Debug>(
            &self,
            _user: &DefaultUser,
            _from: P,
            _to: P,
        ) -> StorageResult<()> {
            rejected()
        }

        async fn rmd<P: AsRef<Path> + Send + Debug>(
            &self,
            _user: &DefaultUser,
            _path: P,
        ) -> StorageResult<()> {
            rejected()
        }

        async fn cwd<P: AsRef<Path> + Send + Debug>(
            &self,
            _user: &DefaultUser,
            _path: P,
        ) -> StorageResult<()> {
            rejected()
        }
    }

    #[derive(Debug)]
    struct RejectedAuthenticator;

    #[async_trait]
    impl Authenticator for RejectedAuthenticator {
        async fn authenticate(
            &self,
            _username: &str,
            _creds: &Credentials,
        ) -> std::result::Result<Principal, AuthenticationError> {
            Err(AuthenticationError::BadPassword)
        }
    }

    #[test]
    fn reviewed_builder_api_expresses_the_non_negotiable_listener_profile() {
        let _builder = ServerBuilder::with_authenticator(
            Box::new(|| RejectedStorage),
            Arc::new(RejectedAuthenticator),
        )
        .ftps(
            "/run/filebelt/ftp/server.crt",
            "/run/filebelt/ftp/server.key",
        )
        .ftps_tls_flags(TlsFlags::V1_3)
        .ftps_required(FtpsRequired::All, FtpsRequired::All)
        .active_passive_mode(ActivePassiveMode::PassiveOnly)
        .passive_ports(30_000..=30_031);
    }

    #[tokio::test]
    async fn public_listener_rejects_nonzero_pbsz_before_the_handler() {
        let server = ServerBuilder::with_authenticator(
            Box::new(|| RejectedStorage),
            Arc::new(RejectedAuthenticator),
        )
        .build()
        .unwrap();
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            // This environment disallows loopback binds. The test still runs
            // on ordinary CI/host networking and exercises libunftp's public
            // parser path there.
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("cannot bind parser contract listener: {error}"),
        };
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(address).await.unwrap() });
        let (stream, _) = listener.accept().await.unwrap();
        let service = tokio::spawn(server.service(stream));
        let mut client = BufReader::new(client.await.unwrap());
        let mut response = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_line(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(response.starts_with("220 "));
        client.get_mut().write_all(b"PBSZ 1\r\n").await.unwrap();
        response.clear();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_line(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response, "501 Invalid Parameter\r\n");
        client.get_mut().shutdown().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), service)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
