// SPDX-License-Identifier: Apache-2.0

//! Binds the authenticated mTLS gateway identity to the protocol claimed in
//! each VFS request. TLS admission alone is insufficient on the shared VFS
//! listener because every enabled gateway chains to the same client CA.

use std::collections::BTreeMap;

use filebelt_control_protocol::MountConfig;
use filebelt_runtime::VerifiedMtlsPeer;
use filebelt_vfs_protocol::MountProtocol;

pub const IDENTITY_MISMATCH: &str = "vfs.gateway_identity_mismatch";
pub const NFS_REQUIRES_MTLS: &str = "vfs.nfs_requires_mtls";

#[derive(Clone, Debug)]
pub struct GatewayIdentityMap {
    by_uri_san: BTreeMap<String, MountProtocol>,
}

impl GatewayIdentityMap {
    pub fn from_mounts(mounts: &MountConfig) -> Self {
        let mut by_uri_san = BTreeMap::new();
        if mounts.smb.enabled {
            insert_protocol_identities(
                &mut by_uri_san,
                MountProtocol::Smb,
                &mounts.smb.gateway_uri_san,
                mounts.smb.previous_gateway_uri_san.as_deref(),
            );
        }
        if mounts.ftp_ftps.enabled {
            insert_protocol_identities(
                &mut by_uri_san,
                MountProtocol::Ftps,
                &mounts.ftp_ftps.gateway_uri_san,
                mounts.ftp_ftps.previous_gateway_uri_san.as_deref(),
            );
        }
        if mounts.nfs.enabled {
            insert_protocol_identities(
                &mut by_uri_san,
                MountProtocol::Nfs,
                &mounts.nfs.gateway_uri_san,
                mounts.nfs.previous_gateway_uri_san.as_deref(),
            );
        }
        Self { by_uri_san }
    }

    pub fn authorize(
        &self,
        peer: Option<&VerifiedMtlsPeer>,
        protocol: MountProtocol,
    ) -> Result<(), &'static str> {
        let Some(peer) = peer else {
            return if protocol == MountProtocol::Nfs {
                Err(NFS_REQUIRES_MTLS)
            } else {
                Ok(())
            };
        };
        self.authorize_uri_san(peer.uri_san(), protocol)
    }

    fn authorize_uri_san(
        &self,
        uri_san: &str,
        protocol: MountProtocol,
    ) -> Result<(), &'static str> {
        (self.by_uri_san.get(uri_san) == Some(&protocol))
            .then_some(())
            .ok_or(IDENTITY_MISMATCH)
    }

    #[cfg(test)]
    fn protocol_for_uri_san(&self, uri_san: &str) -> Option<MountProtocol> {
        self.by_uri_san.get(uri_san).copied()
    }
}

fn insert_protocol_identities(
    identities: &mut BTreeMap<String, MountProtocol>,
    protocol: MountProtocol,
    current: &str,
    previous: Option<&str>,
) {
    identities.insert(current.to_owned(), protocol);
    if let Some(previous) = previous {
        identities.insert(previous.to_owned(), protocol);
    }
}

#[cfg(test)]
mod tests {
    use filebelt_control_protocol::{
        FTP_FTPS_GATEWAY_URI_SAN, MountConfig, NFS_GATEWAY_URI_SAN, SMB_GATEWAY_URI_SAN,
    };
    use filebelt_vfs_protocol::MountProtocol;

    use super::{GatewayIdentityMap, IDENTITY_MISMATCH, NFS_REQUIRES_MTLS};

    #[test]
    fn maps_only_enabled_current_and_previous_protocol_identities() {
        let mut mounts = MountConfig::default();
        mounts.smb.enabled = true;
        mounts.smb.previous_gateway_uri_san =
            Some("spiffe://filebelt/smb-gateway/vfs-previous".into());
        mounts.nfs.enabled = true;
        let identities = GatewayIdentityMap::from_mounts(&mounts);

        assert_eq!(
            identities.protocol_for_uri_san(SMB_GATEWAY_URI_SAN),
            Some(MountProtocol::Smb)
        );
        assert_eq!(
            identities.protocol_for_uri_san("spiffe://filebelt/smb-gateway/vfs-previous"),
            Some(MountProtocol::Smb)
        );
        assert_eq!(
            identities.protocol_for_uri_san(NFS_GATEWAY_URI_SAN),
            Some(MountProtocol::Nfs)
        );
        assert_eq!(
            identities.protocol_for_uri_san(FTP_FTPS_GATEWAY_URI_SAN),
            None
        );
        assert_eq!(
            identities.protocol_for_uri_san("spiffe://filebelt/unknown/vfs"),
            None
        );
        assert_eq!(
            identities.authorize_uri_san(SMB_GATEWAY_URI_SAN, MountProtocol::Nfs),
            Err(IDENTITY_MISMATCH)
        );
        assert_eq!(
            identities.authorize_uri_san(NFS_GATEWAY_URI_SAN, MountProtocol::Nfs),
            Ok(())
        );
    }

    #[test]
    fn development_transport_never_admits_nfs() {
        let identities = GatewayIdentityMap::from_mounts(&MountConfig::default());
        assert_eq!(
            identities.authorize(None, MountProtocol::Nfs),
            Err(NFS_REQUIRES_MTLS)
        );
        assert_eq!(identities.authorize(None, MountProtocol::Smb), Ok(()));
        assert_eq!(identities.authorize(None, MountProtocol::Ftps), Ok(()));
    }
}
