//! Key exchange group implementations using OpenSSL.

use dimpl::crypto::Buf;
use dimpl::crypto::{ActiveKeyExchange, NamedGroup, SupportedKxGroup};

use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::PKey;

/// Map a `NamedGroup` to the corresponding OpenSSL `Nid`.
fn nid_for_group(group: NamedGroup) -> Result<Nid, String> {
    match group {
        NamedGroup::Secp256r1 => Ok(Nid::X9_62_PRIME256V1),
        NamedGroup::Secp384r1 => Ok(Nid::SECP384R1),
        _ => Err(format!("Unsupported group: {group:?}")),
    }
}

/// ECDHE key exchange implementation using OpenSSL.
struct EcdhKeyExchange {
    private_key: EcKey<openssl::pkey::Private>,
    public_key_bytes: Buf,
    group: NamedGroup,
}

impl std::fmt::Debug for EcdhKeyExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.group {
            NamedGroup::Secp256r1 => f
                .debug_struct("EcdhKeyExchange::P256")
                .field("public_key_len", &self.public_key_bytes.len())
                .finish_non_exhaustive(),
            NamedGroup::Secp384r1 => f
                .debug_struct("EcdhKeyExchange::P384")
                .field("public_key_len", &self.public_key_bytes.len())
                .finish_non_exhaustive(),
            _ => f
                .debug_struct("EcdhKeyExchange::Unknown")
                .finish_non_exhaustive(),
        }
    }
}

impl EcdhKeyExchange {
    fn new(group: NamedGroup, mut buf: Buf) -> Result<Self, String> {
        let nid = nid_for_group(group)?;

        let ec_group = EcGroup::from_curve_name(nid).map_err(|e| format!("{e}"))?;
        let ec_key = EcKey::generate(&ec_group).map_err(|e| format!("{e}"))?;

        // Export public key as SEC1 uncompressed point format
        let mut ctx = BigNumContext::new().map_err(|e| format!("{e}"))?;
        let public_key_bytes = ec_key
            .public_key()
            .to_bytes(&ec_group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .map_err(|e| format!("{e}"))?;

        buf.clear();
        buf.extend_from_slice(&public_key_bytes);

        Ok(Self {
            private_key: ec_key,
            public_key_bytes: buf,
            group,
        })
    }
}

impl ActiveKeyExchange for EcdhKeyExchange {
    fn pub_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn complete(self: Box<Self>, peer_pub: &[u8], out: &mut Buf) -> Result<(), String> {
        let nid = nid_for_group(self.group)?;

        let ec_group = EcGroup::from_curve_name(nid).map_err(|e| format!("{e}"))?;
        let mut ctx = BigNumContext::new().map_err(|e| format!("{e}"))?;

        // Import peer's public key
        let peer_point =
            EcPoint::from_bytes(&ec_group, peer_pub, &mut ctx).map_err(|e| format!("{e}"))?;

        // Perform ECDH key agreement
        let pkey = PKey::from_ec_key(self.private_key).map_err(|e| format!("{e}"))?;
        let peer_ec_key =
            EcKey::from_public_key(&ec_group, &peer_point).map_err(|e| format!("{e}"))?;
        let peer_pkey = PKey::from_ec_key(peer_ec_key).map_err(|e| format!("{e}"))?;

        let mut deriver = openssl::derive::Deriver::new(&pkey).map_err(|e| format!("{e}"))?;
        deriver.set_peer(&peer_pkey).map_err(|e| format!("{e}"))?;

        let shared_secret = deriver.derive_to_vec().map_err(|e| format!("{e}"))?;

        out.clear();
        out.extend_from_slice(&shared_secret);
        Ok(())
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}

/// P-256 (secp256r1) key exchange group.
#[derive(Debug)]
struct P256;

impl SupportedKxGroup for P256 {
    fn name(&self) -> NamedGroup {
        NamedGroup::Secp256r1
    }

    fn start_exchange(&self, buf: Buf) -> Result<Box<dyn ActiveKeyExchange>, String> {
        Ok(Box::new(EcdhKeyExchange::new(NamedGroup::Secp256r1, buf)?))
    }
}

/// P-384 (secp384r1) key exchange group.
#[derive(Debug)]
struct P384;

impl SupportedKxGroup for P384 {
    fn name(&self) -> NamedGroup {
        NamedGroup::Secp384r1
    }

    fn start_exchange(&self, buf: Buf) -> Result<Box<dyn ActiveKeyExchange>, String> {
        Ok(Box::new(EcdhKeyExchange::new(NamedGroup::Secp384r1, buf)?))
    }
}

static SECP256R1: P256 = P256;
static SECP384R1: P384 = P384;

pub(super) static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&SECP256R1, &SECP384R1];
