use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{AuthError, Result};

#[path = "macos_keyring_platform.rs"]
mod platform;
use platform::SecurityCommandAdapter;
#[path = "macos_keyring_recovery.rs"]
mod macos_keyring_recovery;
use macos_keyring_recovery::recover_malformed_with;

const PROMPT_SAFE_VALUE_BYTES: usize = 96;
const PROMPT_MAX_VALUE_BYTES: usize = 127;
const CHUNK_SOURCE_BYTES: usize = 72;
const MAX_LOGICAL_CREDENTIAL_BYTES: usize = 16 * 1024;
const MAX_CHUNK_COUNT: usize = MAX_LOGICAL_CREDENTIAL_BYTES.div_ceil(CHUNK_SOURCE_BYTES);
const MAX_INVENTORY_GENERATIONS: usize = 2;
const LEGACY_V1_MANIFEST_PREFIX: &str = "cfctl:keyring:v1:";
const LEGACY_V1_CHUNK_KEY_PREFIX: &str = "__cfctl_internal__/keyring-chunk/v1";
const CHUNK_MANIFEST_PREFIX: &str = "cfctl:keyring:manifest:v2:";
const INVENTORY_PREFIX: &str = "cfctl:keyring:inventory:v2:";
const ROOT_MARKER: &str = "cfctl:keyring:managed:v2";
const CHUNK_KEY_PREFIX: &str = "__cfctl_internal__/keyring-chunk/v2";
const GENERATION_MANIFEST_KEY_PREFIX: &str = "__cfctl_internal__/keyring-generation/v2";
const INVENTORY_KEY_PREFIX: &str = "__cfctl_internal__/keyring-inventory/v2";
const CHUNK_MANIFEST_VERSION: u8 = 2;
const INVENTORY_VERSION: u8 = 2;
const CHUNK_MANIFEST_BYTES: usize = 65;
const INVENTORY_BYTES: usize = 38;
const CHUNK_MANIFEST_PAYLOAD_BYTES: usize = 87;
const INVENTORY_PAYLOAD_BYTES: usize = 51;
const MAX_ENCODED_MANIFEST_BYTES: usize =
    CHUNK_MANIFEST_PREFIX.len() + CHUNK_MANIFEST_PAYLOAD_BYTES;
const MAX_ENCODED_INVENTORY_BYTES: usize = INVENTORY_PREFIX.len() + INVENTORY_PAYLOAD_BYTES;
const MAX_ENCODED_CHUNK_BYTES: usize = PROMPT_SAFE_VALUE_BYTES;

pub(super) fn put(service: &str, key: &str, value: &str) -> Result<()> {
    put_with(&SecurityCommandAdapter, service, key, value)
}

pub(super) fn get(service: &str, key: &str) -> Result<Option<String>> {
    get_with(&SecurityCommandAdapter, service, key)
}

pub(super) fn delete(service: &str, key: &str) -> Result<()> {
    delete_with(&SecurityCommandAdapter, service, key)
}

pub(super) fn get_recoverable_unmanaged(service: &str, key: &str) -> Result<Option<String>> {
    get_recoverable_unmanaged_with(&SecurityCommandAdapter, service, key)
}

pub(super) fn recover_malformed(
    service: &str,
    key: &str,
    expected_value: &str,
    quarantine_key: &str,
    replacement_value: &str,
) -> Result<()> {
    recover_malformed_with(
        &SecurityCommandAdapter,
        service,
        key,
        expected_value,
        quarantine_key,
        replacement_value,
    )
}

trait MacosKeychainAdapter {
    fn put_raw(&self, service: &str, key: &str, value: &str) -> Result<()>;
    fn get_raw(&self, service: &str, key: &str) -> Result<Option<String>>;
    fn delete_raw(&self, service: &str, key: &str) -> Result<()>;

    fn acquire_mutation_lock<'a>(
        &'a self,
        _service: &str,
        _key: &str,
    ) -> Result<Box<dyn MutationGuard + 'a>> {
        Ok(Box::new(()))
    }

    fn checkpoint(&self, _boundary: LifecycleBoundary) -> Result<()> {
        Ok(())
    }
}

trait MutationGuard {}

impl<T> MutationGuard for T {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecycleBoundary {
    InventoryTransition,
    GenerationManifestWrite,
    ChunkWrite(usize),
    ReplacementPublication,
    RootTransition,
    ChunkDelete(usize),
    GenerationManifestDelete,
    RootDelete,
    InventoryDelete,
}

fn put_with(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    let _guard = adapter.acquire_mutation_lock(service, key)?;
    put_unlocked(adapter, service, key, value)
}

fn put_unlocked(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    if value.contains(['\n', '\r']) {
        return Err(AuthError::SecretStore(
            "macOS Keychain credentials cannot contain line breaks".to_owned(),
        ));
    }
    if value.len() > MAX_LOGICAL_CREDENTIAL_BYTES {
        return Err(AuthError::SecretStore(
            "platform keyring credential exceeds the maximum logical byte bound".to_owned(),
        ));
    }

    match reconcile(adapter, service, key)? {
        Some(inventory) => put_managed(adapter, service, key, value, inventory),
        None => put_initial(adapter, service, key, value),
    }
}

fn get_with(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
) -> Result<Option<String>> {
    let Some(inventory) = read_inventory(adapter, service, key)? else {
        return get_unmanaged(adapter, service, key);
    };
    match inventory.state {
        InventoryState::PreparingLegacy => get_unmanaged(adapter, service, key),
        InventoryState::Deleting | InventoryState::DeletingLegacyV1 => {
            Err(AuthError::SecretStoreDeletionIncomplete)
        }
        InventoryState::PublishedNeedsRootScrub
        | InventoryState::PublishedLegacyV1NeedsRootScrub => {
            read_generation(adapter, service, key, &inventory.primary).map(Some)
        }
        InventoryState::Active
        | InventoryState::ActiveWithPending
        | InventoryState::ActiveWithRetiring => {
            require_root_marker(adapter, service, key)?;
            read_generation(adapter, service, key, &inventory.primary).map(Some)
        }
    }
}

fn get_recoverable_unmanaged_with(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
) -> Result<Option<String>> {
    if read_inventory(adapter, service, key)?.is_some()
        || !matches!(
            classify_legacy_v1(adapter, service, key)?,
            LegacyV1State::Unmanaged
        )
    {
        return Err(AuthError::SecretStore(
            "malformed registry recovery requires no v2 inventory or legacy chunk manifest"
                .to_owned(),
        ));
    }
    get_unmanaged(adapter, service, key)
}

fn delete_with(adapter: &dyn MacosKeychainAdapter, service: &str, key: &str) -> Result<()> {
    let _guard = adapter.acquire_mutation_lock(service, key)?;
    delete_unlocked(adapter, service, key)
}

fn delete_unlocked(adapter: &dyn MacosKeychainAdapter, service: &str, key: &str) -> Result<()> {
    let Some(inventory) = reconcile(adapter, service, key)? else {
        match classify_legacy_v1(adapter, service, key)? {
            LegacyV1State::Confirmed(legacy) => {
                read_legacy_v1_generation(adapter, service, key, &legacy)?;
                let generation = GenerationRef::new(legacy.write_id, legacy.chunk_count)?;
                let deleting =
                    GenerationInventory::new(InventoryState::DeletingLegacyV1, generation, None)?;
                write_inventory(
                    adapter,
                    service,
                    key,
                    &deleting,
                    LifecycleBoundary::InventoryTransition,
                )?;
                return finish_delete_legacy_v1(adapter, service, key, &deleting.primary);
            }
            LegacyV1State::Ambiguous => return Err(ambiguous_legacy_v1()),
            LegacyV1State::Unmanaged => {}
        }
        delete_raw_exact(adapter, service, key)?;
        adapter.checkpoint(LifecycleBoundary::RootDelete)?;
        return Ok(());
    };
    let deleting = GenerationInventory::new(InventoryState::Deleting, inventory.primary, None)?;
    write_inventory(
        adapter,
        service,
        key,
        &deleting,
        LifecycleBoundary::InventoryTransition,
    )?;
    finish_delete(adapter, service, key, &deleting.primary)
}

fn put_initial(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    let legacy_v1 = match classify_legacy_v1(adapter, service, key)? {
        LegacyV1State::Confirmed(legacy) => {
            read_legacy_v1_generation(adapter, service, key, &legacy)?;
            Some(legacy)
        }
        LegacyV1State::Ambiguous => return Err(ambiguous_legacy_v1()),
        LegacyV1State::Unmanaged => None,
    };
    let generation = GenerationRef::for_value(*Uuid::new_v4().as_bytes(), value)?;
    let preparing = GenerationInventory::new(InventoryState::PreparingLegacy, generation, None)?;
    write_inventory(
        adapter,
        service,
        key,
        &preparing,
        LifecycleBoundary::InventoryTransition,
    )?;
    stage_generation(adapter, service, key, &generation, value)?;
    let (published_state, retiring_legacy) = if let Some(legacy) = legacy_v1.as_ref() {
        (
            InventoryState::PublishedLegacyV1NeedsRootScrub,
            Some(GenerationRef::new(legacy.write_id, legacy.chunk_count)?),
        )
    } else {
        (InventoryState::PublishedNeedsRootScrub, None)
    };
    let published = GenerationInventory::new(published_state, generation, retiring_legacy)?;
    write_inventory(
        adapter,
        service,
        key,
        &published,
        LifecycleBoundary::ReplacementPublication,
    )?;
    if let Some(retiring) = published.secondary.as_ref() {
        cleanup_legacy_v1_generation(adapter, service, key, retiring)?;
    }
    put_raw_exact(adapter, service, key, ROOT_MARKER)?;
    adapter.checkpoint(LifecycleBoundary::RootTransition)?;
    let active = GenerationInventory::new(InventoryState::Active, generation, None)?;
    write_inventory(
        adapter,
        service,
        key,
        &active,
        LifecycleBoundary::InventoryTransition,
    )
}

fn put_managed(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
    value: &str,
    inventory: GenerationInventory,
) -> Result<()> {
    if inventory.state != InventoryState::Active {
        return Err(invalid_inventory());
    }
    require_root_marker(adapter, service, key)?;
    let generation = GenerationRef::for_value(*Uuid::new_v4().as_bytes(), value)?;
    let pending = GenerationInventory::new(
        InventoryState::ActiveWithPending,
        inventory.primary,
        Some(generation),
    )?;
    write_inventory(
        adapter,
        service,
        key,
        &pending,
        LifecycleBoundary::InventoryTransition,
    )?;
    stage_generation(adapter, service, key, &generation, value)?;
    let retiring = GenerationInventory::new(
        InventoryState::ActiveWithRetiring,
        generation,
        Some(inventory.primary),
    )?;
    write_inventory(
        adapter,
        service,
        key,
        &retiring,
        LifecycleBoundary::ReplacementPublication,
    )?;
    cleanup_generation(adapter, service, key, &inventory.primary)?;
    let active = GenerationInventory::new(InventoryState::Active, generation, None)?;
    write_inventory(
        adapter,
        service,
        key,
        &active,
        LifecycleBoundary::InventoryTransition,
    )
}

fn reconcile(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
) -> Result<Option<GenerationInventory>> {
    let Some(inventory) = read_inventory(adapter, service, key)? else {
        return Ok(None);
    };
    match inventory.state {
        InventoryState::PreparingLegacy => {
            cleanup_generation(adapter, service, key, &inventory.primary)?;
            delete_inventory(adapter, service, key)?;
            Ok(None)
        }
        InventoryState::PublishedNeedsRootScrub => {
            read_generation(adapter, service, key, &inventory.primary)?;
            put_raw_exact(adapter, service, key, ROOT_MARKER)?;
            adapter.checkpoint(LifecycleBoundary::RootTransition)?;
            let active = GenerationInventory::new(InventoryState::Active, inventory.primary, None)?;
            write_inventory(
                adapter,
                service,
                key,
                &active,
                LifecycleBoundary::InventoryTransition,
            )?;
            Ok(Some(active))
        }
        InventoryState::PublishedLegacyV1NeedsRootScrub => {
            read_generation(adapter, service, key, &inventory.primary)?;
            let retiring = inventory.secondary.ok_or_else(invalid_inventory)?;
            cleanup_legacy_v1_generation(adapter, service, key, &retiring)?;
            put_raw_exact(adapter, service, key, ROOT_MARKER)?;
            adapter.checkpoint(LifecycleBoundary::RootTransition)?;
            let active = GenerationInventory::new(InventoryState::Active, inventory.primary, None)?;
            write_inventory(
                adapter,
                service,
                key,
                &active,
                LifecycleBoundary::InventoryTransition,
            )?;
            Ok(Some(active))
        }
        InventoryState::ActiveWithPending | InventoryState::ActiveWithRetiring => {
            let pending = inventory.secondary.ok_or_else(invalid_inventory)?;
            cleanup_generation(adapter, service, key, &pending)?;
            let active = GenerationInventory::new(InventoryState::Active, inventory.primary, None)?;
            write_inventory(
                adapter,
                service,
                key,
                &active,
                LifecycleBoundary::InventoryTransition,
            )?;
            Ok(Some(active))
        }
        InventoryState::Deleting => {
            finish_delete(adapter, service, key, &inventory.primary)?;
            Ok(None)
        }
        InventoryState::DeletingLegacyV1 => {
            finish_delete_legacy_v1(adapter, service, key, &inventory.primary)?;
            Ok(None)
        }
        InventoryState::Active => Ok(Some(inventory)),
    }
}

fn finish_delete_legacy_v1(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
    generation: &GenerationRef,
) -> Result<()> {
    cleanup_legacy_v1_generation(adapter, service, key, generation)?;
    delete_raw_exact(adapter, service, key)?;
    adapter.checkpoint(LifecycleBoundary::RootDelete)?;
    delete_inventory(adapter, service, key)
}

fn finish_delete(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
    generation: &GenerationRef,
) -> Result<()> {
    cleanup_generation(adapter, service, key, generation)?;
    delete_raw_exact(adapter, service, key)?;
    adapter.checkpoint(LifecycleBoundary::RootDelete)?;
    delete_inventory(adapter, service, key)
}

fn stage_generation(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
    generation: &GenerationRef,
    value: &str,
) -> Result<()> {
    if value.len() > MAX_LOGICAL_CREDENTIAL_BYTES
        || generation.chunk_count != value.len().div_ceil(CHUNK_SOURCE_BYTES)
    {
        return Err(invalid_manifest());
    }
    let manifest = ChunkManifest {
        write_id: generation.write_id,
        chunk_count: generation.chunk_count,
        value_len: value.len(),
        value_digest: Sha256::digest(value.as_bytes()).into(),
    };
    put_raw_exact(
        adapter,
        service,
        &generation_manifest_key(key, &generation.write_id),
        &manifest.encode()?,
    )?;
    adapter.checkpoint(LifecycleBoundary::GenerationManifestWrite)?;
    for (index, chunk) in value.as_bytes().chunks(CHUNK_SOURCE_BYTES).enumerate() {
        let encoded = URL_SAFE_NO_PAD.encode(chunk);
        if encoded.len() > MAX_ENCODED_CHUNK_BYTES {
            return Err(invalid_manifest());
        }
        put_raw_exact(
            adapter,
            service,
            &chunk_key(key, &generation.write_id, index),
            &encoded,
        )?;
        adapter.checkpoint(LifecycleBoundary::ChunkWrite(index))?;
    }
    let readback = read_generation(adapter, service, key, generation)?;
    if readback != value {
        return Err(AuthError::SecretStore(
            "platform keyring credential generation failed exact readback".to_owned(),
        ));
    }
    Ok(())
}

fn read_generation(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
    generation: &GenerationRef,
) -> Result<String> {
    let encoded_manifest = get_raw_bounded(
        adapter,
        service,
        &generation_manifest_key(key, &generation.write_id),
    )?
    .ok_or_else(|| {
        AuthError::SecretStore("platform keyring generation manifest is missing".to_owned())
    })?;
    let manifest = parse_chunk_manifest(&encoded_manifest)?.ok_or_else(invalid_manifest)?;
    if manifest.write_id != generation.write_id || manifest.chunk_count != generation.chunk_count {
        return Err(invalid_manifest());
    }
    read_manifest_chunks(adapter, service, key, &manifest, false)
}

fn read_legacy_v1_generation(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
    manifest: &ChunkManifest,
) -> Result<String> {
    read_manifest_chunks(adapter, service, key, manifest, true)
}

fn read_manifest_chunks(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
    manifest: &ChunkManifest,
    legacy_v1: bool,
) -> Result<String> {
    let mut decoded = Vec::with_capacity(manifest.value_len);
    for index in 0..manifest.chunk_count {
        let chunk_key = if legacy_v1 {
            legacy_v1_chunk_key(key, &manifest.write_id, index)
        } else {
            chunk_key(key, &manifest.write_id, index)
        };
        let encoded = get_raw_bounded(adapter, service, &chunk_key)?.ok_or_else(|| {
            AuthError::SecretStore(
                "platform keyring chunked credential readback is incomplete".to_owned(),
            )
        })?;
        if encoded.is_empty() || encoded.len() > MAX_ENCODED_CHUNK_BYTES {
            return Err(AuthError::SecretStore(
                "platform keyring chunked credential exceeds its encoded chunk bound".to_owned(),
            ));
        }
        let chunk = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
            AuthError::SecretStore(
                "platform keyring chunked credential contains invalid encoding".to_owned(),
            )
        })?;
        let consumed = index
            .checked_mul(CHUNK_SOURCE_BYTES)
            .ok_or_else(invalid_manifest)?;
        let remaining = manifest
            .value_len
            .checked_sub(consumed)
            .ok_or_else(invalid_manifest)?;
        let expected = remaining.min(CHUNK_SOURCE_BYTES);
        let next_len = decoded
            .len()
            .checked_add(chunk.len())
            .ok_or_else(invalid_manifest)?;
        if chunk.len() != expected
            || next_len > manifest.value_len
            || next_len > MAX_LOGICAL_CREDENTIAL_BYTES
        {
            return Err(AuthError::SecretStore(
                "platform keyring chunked credential violates its decoded byte bound".to_owned(),
            ));
        }
        decoded.extend_from_slice(&chunk);
    }
    let readback_digest: [u8; 32] = Sha256::digest(&decoded).into();
    if decoded.len() != manifest.value_len || readback_digest != manifest.value_digest {
        return Err(AuthError::SecretStore(
            "platform keyring chunked credential failed exact digest readback".to_owned(),
        ));
    }
    String::from_utf8(decoded).map_err(|_| {
        AuthError::SecretStore("platform keyring chunked credential is not valid UTF-8".to_owned())
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChunkManifest {
    write_id: [u8; 16],
    chunk_count: usize,
    value_len: usize,
    value_digest: [u8; 32],
}

impl ChunkManifest {
    fn encode(&self) -> Result<String> {
        validate_manifest_fields(self.chunk_count, self.value_len)?;
        if self.write_id == [0; 16] {
            return Err(invalid_manifest());
        }
        let chunk_count = u64::try_from(self.chunk_count).map_err(|_| invalid_manifest())?;
        let value_len = u64::try_from(self.value_len).map_err(|_| invalid_manifest())?;
        let mut encoded = Vec::with_capacity(CHUNK_MANIFEST_BYTES);
        encoded.push(CHUNK_MANIFEST_VERSION);
        encoded.extend_from_slice(&self.write_id);
        encoded.extend_from_slice(&chunk_count.to_be_bytes());
        encoded.extend_from_slice(&value_len.to_be_bytes());
        encoded.extend_from_slice(&self.value_digest);
        let encoded = format!("{CHUNK_MANIFEST_PREFIX}{}", URL_SAFE_NO_PAD.encode(encoded));
        if encoded.len() != MAX_ENCODED_MANIFEST_BYTES || encoded.len() > PROMPT_MAX_VALUE_BYTES {
            return Err(invalid_manifest());
        }
        Ok(encoded)
    }
}

fn parse_chunk_manifest(value: &str) -> Result<Option<ChunkManifest>> {
    parse_manifest(value, CHUNK_MANIFEST_PREFIX, CHUNK_MANIFEST_VERSION)
}

fn parse_manifest(value: &str, prefix: &str, version: u8) -> Result<Option<ChunkManifest>> {
    let Some(manifest) = decode_manifest(value, prefix, version)? else {
        return Ok(None);
    };
    validate_manifest_fields(manifest.chunk_count, manifest.value_len)?;
    if manifest.write_id == [0; 16] {
        return Err(invalid_manifest());
    }
    Ok(Some(manifest))
}

fn decode_manifest(value: &str, prefix: &str, version: u8) -> Result<Option<ChunkManifest>> {
    let Some(encoded) = value.strip_prefix(prefix) else {
        return Ok(None);
    };
    if value.len() != prefix.len() + CHUNK_MANIFEST_PAYLOAD_BYTES
        || encoded.len() != CHUNK_MANIFEST_PAYLOAD_BYTES
    {
        return Err(invalid_manifest());
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| invalid_manifest())?;
    if decoded.len() != CHUNK_MANIFEST_BYTES || decoded[0] != version {
        return Err(invalid_manifest());
    }
    let mut write_id = [0_u8; 16];
    write_id.copy_from_slice(&decoded[1..17]);
    let mut chunk_count_bytes = [0_u8; 8];
    chunk_count_bytes.copy_from_slice(&decoded[17..25]);
    let mut value_len_bytes = [0_u8; 8];
    value_len_bytes.copy_from_slice(&decoded[25..33]);
    let Some(chunk_count) = usize::try_from(u64::from_be_bytes(chunk_count_bytes)).ok() else {
        return Err(invalid_manifest());
    };
    let Some(value_len) = usize::try_from(u64::from_be_bytes(value_len_bytes)).ok() else {
        return Err(invalid_manifest());
    };
    let mut value_digest = [0_u8; 32];
    value_digest.copy_from_slice(&decoded[33..65]);
    Ok(Some(ChunkManifest {
        write_id,
        chunk_count,
        value_len,
        value_digest,
    }))
}

fn validate_manifest_fields(chunk_count: usize, value_len: usize) -> Result<()> {
    let expected = if value_len == 0 {
        0
    } else {
        value_len
            .checked_add(CHUNK_SOURCE_BYTES - 1)
            .ok_or_else(invalid_manifest)?
            / CHUNK_SOURCE_BYTES
    };
    if value_len > MAX_LOGICAL_CREDENTIAL_BYTES
        || chunk_count > MAX_CHUNK_COUNT
        || chunk_count != expected
    {
        return Err(invalid_manifest());
    }
    Ok(())
}

fn invalid_manifest() -> AuthError {
    AuthError::SecretStore("platform keyring chunk manifest is invalid".to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum InventoryState {
    PreparingLegacy = 1,
    Active = 2,
    ActiveWithPending = 3,
    ActiveWithRetiring = 4,
    PublishedNeedsRootScrub = 5,
    Deleting = 6,
    PublishedLegacyV1NeedsRootScrub = 7,
    DeletingLegacyV1 = 8,
}

impl InventoryState {
    fn from_byte(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::PreparingLegacy),
            2 => Ok(Self::Active),
            3 => Ok(Self::ActiveWithPending),
            4 => Ok(Self::ActiveWithRetiring),
            5 => Ok(Self::PublishedNeedsRootScrub),
            6 => Ok(Self::Deleting),
            7 => Ok(Self::PublishedLegacyV1NeedsRootScrub),
            8 => Ok(Self::DeletingLegacyV1),
            _ => Err(invalid_inventory()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GenerationRef {
    write_id: [u8; 16],
    chunk_count: usize,
}

impl GenerationRef {
    fn new(write_id: [u8; 16], chunk_count: usize) -> Result<Self> {
        if write_id == [0; 16] || chunk_count > MAX_CHUNK_COUNT {
            return Err(invalid_inventory());
        }
        Ok(Self {
            write_id,
            chunk_count,
        })
    }

    fn for_value(write_id: [u8; 16], value: &str) -> Result<Self> {
        Self::new(write_id, value.len().div_ceil(CHUNK_SOURCE_BYTES))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GenerationInventory {
    state: InventoryState,
    primary: GenerationRef,
    secondary: Option<GenerationRef>,
}

impl GenerationInventory {
    fn new(
        state: InventoryState,
        primary: GenerationRef,
        secondary: Option<GenerationRef>,
    ) -> Result<Self> {
        let expects_secondary = matches!(
            state,
            InventoryState::ActiveWithPending
                | InventoryState::ActiveWithRetiring
                | InventoryState::PublishedLegacyV1NeedsRootScrub
        );
        let generation_count = 1_usize
            .checked_add(usize::from(secondary.is_some()))
            .ok_or_else(invalid_inventory)?;
        GenerationRef::new(primary.write_id, primary.chunk_count)?;
        if let Some(secondary) = secondary {
            GenerationRef::new(secondary.write_id, secondary.chunk_count)?;
        }
        if secondary == Some(primary)
            || secondary.is_some() != expects_secondary
            || generation_count > MAX_INVENTORY_GENERATIONS
        {
            return Err(invalid_inventory());
        }
        Ok(Self {
            state,
            primary,
            secondary,
        })
    }

    fn encode(&self) -> Result<String> {
        Self::new(self.state, self.primary, self.secondary)?;
        let mut bytes = Vec::with_capacity(INVENTORY_BYTES);
        bytes.push(INVENTORY_VERSION);
        bytes.push(self.state as u8);
        bytes.extend_from_slice(&self.primary.write_id);
        bytes.extend_from_slice(
            &u16::try_from(self.primary.chunk_count)
                .map_err(|_| invalid_inventory())?
                .to_be_bytes(),
        );
        let secondary = self.secondary.unwrap_or(GenerationRef {
            write_id: [0; 16],
            chunk_count: 0,
        });
        bytes.extend_from_slice(&secondary.write_id);
        bytes.extend_from_slice(
            &u16::try_from(secondary.chunk_count)
                .map_err(|_| invalid_inventory())?
                .to_be_bytes(),
        );
        let encoded = format!("{INVENTORY_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
        if encoded.len() != MAX_ENCODED_INVENTORY_BYTES || encoded.len() > PROMPT_MAX_VALUE_BYTES {
            return Err(invalid_inventory());
        }
        Ok(encoded)
    }
}

fn parse_inventory(value: &str) -> Result<GenerationInventory> {
    if value.len() != MAX_ENCODED_INVENTORY_BYTES {
        return Err(invalid_inventory());
    }
    let encoded = value
        .strip_prefix(INVENTORY_PREFIX)
        .ok_or_else(invalid_inventory)?;
    if encoded.len() != INVENTORY_PAYLOAD_BYTES {
        return Err(invalid_inventory());
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| invalid_inventory())?;
    if decoded.len() != INVENTORY_BYTES || decoded[0] != INVENTORY_VERSION {
        return Err(invalid_inventory());
    }
    let state = InventoryState::from_byte(decoded[1])?;
    let mut primary_id = [0_u8; 16];
    primary_id.copy_from_slice(&decoded[2..18]);
    let primary_count = usize::from(u16::from_be_bytes([decoded[18], decoded[19]]));
    let primary = GenerationRef::new(primary_id, primary_count)?;
    let mut secondary_id = [0_u8; 16];
    secondary_id.copy_from_slice(&decoded[20..36]);
    let secondary_count = usize::from(u16::from_be_bytes([decoded[36], decoded[37]]));
    let secondary = if secondary_id == [0; 16] && secondary_count == 0 {
        None
    } else {
        Some(GenerationRef::new(secondary_id, secondary_count)?)
    };
    GenerationInventory::new(state, primary, secondary)
}

fn invalid_inventory() -> AuthError {
    AuthError::SecretStore("platform keyring generation inventory is invalid".to_owned())
}

fn key_digest(key: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(key.as_bytes()))
}

fn inventory_key(key: &str) -> String {
    format!("{INVENTORY_KEY_PREFIX}/{}", key_digest(key))
}

fn generation_manifest_key(key: &str, write_id: &[u8; 16]) -> String {
    format!(
        "{GENERATION_MANIFEST_KEY_PREFIX}/{}/{}",
        key_digest(key),
        URL_SAFE_NO_PAD.encode(write_id)
    )
}

fn chunk_key(key: &str, write_id: &[u8; 16], index: usize) -> String {
    let write_id = URL_SAFE_NO_PAD.encode(write_id);
    format!("{CHUNK_KEY_PREFIX}/{}/{write_id}/{index}", key_digest(key))
}

fn legacy_v1_chunk_key(key: &str, write_id: &[u8; 16], index: usize) -> String {
    let write_id = URL_SAFE_NO_PAD.encode(write_id);
    format!(
        "{LEGACY_V1_CHUNK_KEY_PREFIX}/{}/{write_id}/{index}",
        key_digest(key)
    )
}

enum LegacyV1State {
    Unmanaged,
    Confirmed(ChunkManifest),
    Ambiguous,
}

fn classify_legacy_v1(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
) -> Result<LegacyV1State> {
    let Some(root) = get_raw_bounded(adapter, service, key)? else {
        return Ok(LegacyV1State::Unmanaged);
    };
    if !root.starts_with(LEGACY_V1_MANIFEST_PREFIX) {
        return Ok(LegacyV1State::Unmanaged);
    }
    let Ok(Some(manifest)) = decode_manifest(&root, LEGACY_V1_MANIFEST_PREFIX, 1) else {
        return Ok(LegacyV1State::Unmanaged);
    };
    validate_manifest_fields(manifest.chunk_count, manifest.value_len)?;
    if manifest.write_id == [0; 16] {
        return Err(invalid_manifest());
    }
    for index in 0..manifest.chunk_count {
        if get_raw_bounded(
            adapter,
            service,
            &legacy_v1_chunk_key(key, &manifest.write_id, index),
        )?
        .is_some()
        {
            return Ok(LegacyV1State::Confirmed(manifest));
        }
    }
    Ok(LegacyV1State::Ambiguous)
}

fn ambiguous_legacy_v1() -> AuthError {
    AuthError::SecretStore(
        "platform keyring legacy v1 ownership is ambiguous; preserve the item and resolve its provenance explicitly"
            .to_owned(),
    )
}

fn get_unmanaged(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
) -> Result<Option<String>> {
    match classify_legacy_v1(adapter, service, key)? {
        LegacyV1State::Confirmed(manifest) => {
            read_legacy_v1_generation(adapter, service, key, &manifest).map(Some)
        }
        LegacyV1State::Ambiguous => Err(ambiguous_legacy_v1()),
        LegacyV1State::Unmanaged => get_raw_bounded(adapter, service, key),
    }
}

fn read_inventory(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
) -> Result<Option<GenerationInventory>> {
    let Some(encoded) = get_raw_bounded(adapter, service, &inventory_key(key))? else {
        return Ok(None);
    };
    parse_inventory(&encoded).map(Some)
}

fn write_inventory(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
    inventory: &GenerationInventory,
    boundary: LifecycleBoundary,
) -> Result<()> {
    put_raw_exact(adapter, service, &inventory_key(key), &inventory.encode()?)?;
    adapter.checkpoint(boundary)
}

fn delete_inventory(adapter: &dyn MacosKeychainAdapter, service: &str, key: &str) -> Result<()> {
    delete_raw_exact(adapter, service, &inventory_key(key))?;
    adapter.checkpoint(LifecycleBoundary::InventoryDelete)
}

fn cleanup_generation(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
    generation: &GenerationRef,
) -> Result<()> {
    let manifest_key = generation_manifest_key(key, &generation.write_id);
    if let Some(encoded_manifest) = get_raw_bounded(adapter, service, &manifest_key)? {
        let manifest = parse_chunk_manifest(&encoded_manifest)?.ok_or_else(invalid_manifest)?;
        if manifest.write_id != generation.write_id
            || manifest.chunk_count != generation.chunk_count
        {
            return Err(invalid_manifest());
        }
    }
    for index in 0..generation.chunk_count {
        delete_raw_exact(
            adapter,
            service,
            &chunk_key(key, &generation.write_id, index),
        )?;
        adapter.checkpoint(LifecycleBoundary::ChunkDelete(index))?;
    }
    delete_raw_exact(adapter, service, &manifest_key)?;
    adapter.checkpoint(LifecycleBoundary::GenerationManifestDelete)?;
    Ok(())
}

fn cleanup_legacy_v1_generation(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
    generation: &GenerationRef,
) -> Result<()> {
    for index in 0..generation.chunk_count {
        delete_raw_exact(
            adapter,
            service,
            &legacy_v1_chunk_key(key, &generation.write_id, index),
        )?;
        adapter.checkpoint(LifecycleBoundary::ChunkDelete(index))?;
    }
    Ok(())
}

fn require_root_marker(adapter: &dyn MacosKeychainAdapter, service: &str, key: &str) -> Result<()> {
    match get_raw_bounded(adapter, service, key)? {
        Some(value) if value == ROOT_MARKER => Ok(()),
        _ => Err(AuthError::SecretStore(
            "platform keyring managed root marker is missing or invalid".to_owned(),
        )),
    }
}

fn get_raw_bounded(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
) -> Result<Option<String>> {
    let value = adapter.get_raw(service, key)?;
    if value
        .as_ref()
        .is_some_and(|value| value.len() > MAX_LOGICAL_CREDENTIAL_BYTES)
    {
        return Err(AuthError::SecretStore(
            "platform keyring item exceeds the maximum encoded byte bound".to_owned(),
        ));
    }
    Ok(value)
}

fn put_raw_exact(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    let write_result = adapter.put_raw(service, key, value);
    match get_raw_bounded(adapter, service, key) {
        Ok(Some(readback)) if readback == value => Ok(()),
        Ok(Some(_) | None) => match write_result {
            Ok(()) => Err(AuthError::SecretStore(
                "platform keyring credential write was not byte-exact".to_owned(),
            )),
            Err(write_error) => Err(write_error),
        },
        Err(readback_error) => {
            let write_state = match write_result {
                Ok(()) => "reported success".to_owned(),
                Err(write_error) => format!("reported failure ({write_error})"),
            };
            Err(AuthError::SecretStore(format!(
                "platform keyring credential write {write_state}, but exact readback is indeterminate ({readback_error})"
            )))
        }
    }
}

fn delete_raw_exact(adapter: &dyn MacosKeychainAdapter, service: &str, key: &str) -> Result<()> {
    let delete_result = adapter.delete_raw(service, key);
    match get_raw_bounded(adapter, service, key) {
        Ok(None) => Ok(()),
        Ok(Some(_)) => match delete_result {
            Ok(()) => Err(AuthError::SecretStore(
                "platform keyring credential deletion did not remove the item".to_owned(),
            )),
            Err(delete_error) => Err(delete_error),
        },
        Err(readback_error) => {
            let delete_state = match delete_result {
                Ok(()) => "reported success".to_owned(),
                Err(delete_error) => format!("reported failure ({delete_error})"),
            };
            Err(AuthError::SecretStore(format!(
                "platform keyring credential deletion {delete_state}, but exact absence readback is indeterminate ({readback_error})"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::{collections::BTreeMap, sync::Mutex};

    use serde_json::json;

    use super::*;

    const PROMPT_VALUE_LIMIT: usize = 127;

    #[derive(Default)]
    struct PromptLimitedAdapter {
        values: Mutex<BTreeMap<(String, String), String>>,
        write_arguments: Mutex<Vec<Vec<String>>>,
        read_keys: Mutex<Vec<String>>,
    }

    impl MacosKeychainAdapter for PromptLimitedAdapter {
        fn put_raw(&self, service: &str, key: &str, value: &str) -> Result<()> {
            // The native adapter passes no process arguments at all, so this records
            // the non-secret addressing a write carries. The invariant it guards is
            // unchanged and now structural: secret bytes never leave this boundary.
            self.write_arguments
                .lock()
                .expect("write-argument lock")
                .push(vec![service.to_owned(), key.to_owned()]);
            let truncated = &value.as_bytes()[..value.len().min(PROMPT_VALUE_LIMIT)];
            let truncated = String::from_utf8(truncated.to_vec())
                .expect("test registry and envelopes are ASCII");
            self.values
                .lock()
                .expect("prompt-limited value lock")
                .insert((service.to_owned(), key.to_owned()), truncated);
            Ok(())
        }

        fn get_raw(&self, service: &str, key: &str) -> Result<Option<String>> {
            self.read_keys
                .lock()
                .expect("read-key lock")
                .push(key.to_owned());
            Ok(self
                .values
                .lock()
                .expect("prompt-limited value lock")
                .get(&(service.to_owned(), key.to_owned()))
                .cloned())
        }

        fn delete_raw(&self, service: &str, key: &str) -> Result<()> {
            self.values
                .lock()
                .expect("prompt-limited value lock")
                .remove(&(service.to_owned(), key.to_owned()));
            Ok(())
        }
    }

    impl PromptLimitedAdapter {
        fn chunk_manifest(&self, service: &str, key: &str) -> ChunkManifest {
            let inventory = read_inventory(self, service, key)
                .expect("inventory read")
                .expect("managed inventory");
            let encoded = self
                .get_raw(
                    service,
                    &generation_manifest_key(key, &inventory.primary.write_id),
                )
                .expect("manifest read")
                .expect("stored manifest");
            parse_chunk_manifest(&encoded)
                .expect("manifest parse")
                .expect("chunk manifest")
        }

        fn stored_keys(&self) -> Vec<String> {
            self.values
                .lock()
                .expect("prompt-limited value lock")
                .keys()
                .map(|(_, key)| key.clone())
                .collect()
        }

        fn reset_reads(&self) {
            self.read_keys.lock().expect("read-key lock").clear();
        }
    }

    #[derive(Default)]
    struct FaultInjectingAdapter {
        inner: PromptLimitedAdapter,
        fail_put_suffix: Mutex<Option<String>>,
        fail_delete_suffix: Mutex<Option<String>>,
        fail_boundary: Mutex<Option<(LifecycleBoundary, usize)>>,
    }

    impl FaultInjectingAdapter {
        fn fail_next_put_suffix(&self, suffix: &str) {
            *self.fail_put_suffix.lock().expect("put fault lock") = Some(suffix.to_owned());
        }

        fn fail_next_delete_suffix(&self, suffix: &str) {
            *self.fail_delete_suffix.lock().expect("delete fault lock") = Some(suffix.to_owned());
        }

        fn fail_next_boundary(&self, boundary: LifecycleBoundary) {
            self.fail_boundary_after(boundary, 0);
        }

        fn fail_boundary_after(
            &self,
            boundary: LifecycleBoundary,
            matching_boundaries_to_skip: usize,
        ) {
            *self.fail_boundary.lock().expect("boundary fault lock") =
                Some((boundary, matching_boundaries_to_skip));
        }

        fn should_fail(slot: &Mutex<Option<String>>, key: &str, exact: bool) -> bool {
            let mut slot = slot.lock().expect("fault lock");
            let matches = slot.as_deref().is_some_and(|target| {
                if exact {
                    key == target
                } else {
                    key.ends_with(target)
                }
            });
            if matches {
                slot.take();
            }
            matches
        }
    }

    impl MacosKeychainAdapter for FaultInjectingAdapter {
        fn put_raw(&self, service: &str, key: &str, value: &str) -> Result<()> {
            if Self::should_fail(&self.fail_put_suffix, key, false) {
                return Err(AuthError::SecretStore(
                    "injected failure before platform write".to_owned(),
                ));
            }
            self.inner.put_raw(service, key, value)
        }

        fn get_raw(&self, service: &str, key: &str) -> Result<Option<String>> {
            self.inner.get_raw(service, key)
        }

        fn delete_raw(&self, service: &str, key: &str) -> Result<()> {
            if Self::should_fail(&self.fail_delete_suffix, key, false) {
                return Err(AuthError::SecretStore(
                    "injected failure before platform delete".to_owned(),
                ));
            }
            self.inner.delete_raw(service, key)
        }

        fn checkpoint(&self, boundary: LifecycleBoundary) -> Result<()> {
            let mut fault = self.fail_boundary.lock().expect("boundary fault lock");
            if let Some((target, remaining)) = fault.as_mut()
                && *target == boundary
            {
                if *remaining == 0 {
                    fault.take();
                    return Err(AuthError::SecretStore(
                        "injected failure after lifecycle boundary".to_owned(),
                    ));
                }
                *remaining -= 1;
            }
            Ok(())
        }
    }

    struct CrossingErrorAdapter {
        inner: PromptLimitedAdapter,
    }

    impl MacosKeychainAdapter for CrossingErrorAdapter {
        fn put_raw(&self, service: &str, key: &str, value: &str) -> Result<()> {
            self.inner.put_raw(service, key, value)?;
            Err(AuthError::SecretStore(
                "injected platform status failure after write".to_owned(),
            ))
        }

        fn get_raw(&self, service: &str, key: &str) -> Result<Option<String>> {
            self.inner.get_raw(service, key)
        }

        fn delete_raw(&self, service: &str, key: &str) -> Result<()> {
            self.inner.delete_raw(service, key)
        }
    }

    fn registry(active: &str, key_material: &str) -> String {
        json!({
            "schema_version": 1,
            "state_root_identity": "state-root-identity",
            "active_generation_id": active,
            "generations": {
                (active): key_material,
                "22222222-2222-4222-8222-222222222222": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
            }
        })
        .to_string()
    }

    fn encode_manifest_unchecked(
        write_id: [u8; 16],
        chunk_count: usize,
        value_len: usize,
        value_digest: [u8; 32],
    ) -> String {
        let mut encoded = Vec::with_capacity(CHUNK_MANIFEST_BYTES);
        encoded.push(CHUNK_MANIFEST_VERSION);
        encoded.extend_from_slice(&write_id);
        encoded.extend_from_slice(&(chunk_count as u64).to_be_bytes());
        encoded.extend_from_slice(&(value_len as u64).to_be_bytes());
        encoded.extend_from_slice(&value_digest);
        format!("{CHUNK_MANIFEST_PREFIX}{}", URL_SAFE_NO_PAD.encode(encoded))
    }

    fn seed_legacy_v1(
        adapter: &PromptLimitedAdapter,
        service: &str,
        key: &str,
        value: &str,
        write_id: [u8; 16],
    ) -> String {
        for (index, chunk) in value.as_bytes().chunks(CHUNK_SOURCE_BYTES).enumerate() {
            adapter
                .put_raw(
                    service,
                    &legacy_v1_chunk_key(key, &write_id, index),
                    &URL_SAFE_NO_PAD.encode(chunk),
                )
                .expect("legacy chunk seed");
        }
        let current = encode_manifest_unchecked(
            write_id,
            value.len().div_ceil(CHUNK_SOURCE_BYTES),
            value.len(),
            Sha256::digest(value.as_bytes()).into(),
        );
        let encoded = current
            .strip_prefix(CHUNK_MANIFEST_PREFIX)
            .expect("current manifest prefix");
        let mut decoded = URL_SAFE_NO_PAD.decode(encoded).expect("manifest decode");
        decoded[0] = 1;
        let legacy = format!(
            "{LEGACY_V1_MANIFEST_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(decoded)
        );
        adapter
            .put_raw(service, key, &legacy)
            .expect("legacy manifest seed");
        legacy
    }

    #[test]
    fn long_registry_round_trips_byte_exactly_without_secret_arguments() {
        let adapter = PromptLimitedAdapter::default();
        let registry = registry(
            "11111111-1111-4111-8111-111111111111",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        assert!(registry.len() > PROMPT_VALUE_LIMIT);

        put_with(&adapter, "service", "registry", &registry).expect("platform adapter write");
        let readback = get_with(&adapter, "service", "registry")
            .expect("platform adapter read")
            .expect("stored platform value");

        assert!(
            readback == registry,
            "long registry readback was not byte-exact"
        );
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(registry.as_bytes()));
        let arguments = adapter.write_arguments.lock().expect("write-argument lock");
        assert!(
            arguments.iter().flatten().all(|argument| {
                !argument.contains(&registry)
                    && !argument.contains("11111111-1111-4111-8111-111111111111")
                    && !argument.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                    && !argument.contains(&digest)
            }),
            "secret bytes or their digest entered the command arguments"
        );
    }

    #[test]
    fn chunked_update_and_delete_remove_superseded_internal_items() {
        let adapter = PromptLimitedAdapter::default();
        let first = registry(
            "11111111-1111-4111-8111-111111111111",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        let second = registry(
            "33333333-3333-4333-8333-333333333333",
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        );
        put_with(&adapter, "service", "registry", &first).expect("first chunked write");
        let first_manifest = adapter.chunk_manifest("service", "registry");
        let first_chunk_keys = (0..first_manifest.chunk_count)
            .map(|index| chunk_key("registry", &first_manifest.write_id, index))
            .collect::<Vec<_>>();

        put_with(&adapter, "service", "registry", &second).expect("second chunked write");
        assert!(
            get_with(&adapter, "service", "registry")
                .expect("second readback")
                .is_some_and(|readback| readback == second),
            "updated registry was not byte-exact"
        );
        {
            let values = adapter.values.lock().expect("prompt-limited value lock");
            assert!(first_chunk_keys.iter().all(|key| {
                !values
                    .keys()
                    .any(|(service, stored_key)| service == "service" && stored_key == key)
            }));
        }

        delete_with(&adapter, "service", "registry").expect("chunked delete");
        assert!(
            get_with(&adapter, "service", "registry")
                .expect("deleted readback")
                .is_none()
        );
        assert!(
            adapter
                .values
                .lock()
                .expect("prompt-limited value lock")
                .is_empty()
        );
    }

    #[test]
    fn chunk_reassembly_rejects_tampering_without_disclosing_the_registry() {
        let adapter = PromptLimitedAdapter::default();
        let registry = registry(
            "11111111-1111-4111-8111-111111111111",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        put_with(&adapter, "service", "registry", &registry).expect("chunked write");
        let manifest = adapter.chunk_manifest("service", "registry");
        adapter
            .values
            .lock()
            .expect("prompt-limited value lock")
            .insert(
                (
                    "service".to_owned(),
                    chunk_key("registry", &manifest.write_id, 0),
                ),
                URL_SAFE_NO_PAD.encode([b'x'; CHUNK_SOURCE_BYTES]),
            );

        let error = get_with(&adapter, "service", "registry")
            .expect_err("tampered chunk must fail closed")
            .to_string();
        assert!(error.contains("exact digest"));
        assert!(!error.contains(&registry));
        assert!(!error.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }

    #[test]
    fn legacy_raw_and_reserved_prefix_values_remain_unambiguous() {
        let adapter = PromptLimitedAdapter::default();
        adapter
            .put_raw("service", "legacy", "legacy-value")
            .expect("legacy raw seed");
        assert_eq!(
            get_with(&adapter, "service", "legacy").expect("legacy raw read"),
            Some("legacy-value".to_owned())
        );

        let reserved = format!("{CHUNK_MANIFEST_PREFIX}not-a-manifest");
        put_with(&adapter, "service", "reserved", &reserved).expect("reserved prefix write");
        assert!(
            get_with(&adapter, "service", "reserved")
                .expect("reserved prefix read")
                .is_some_and(|readback| readback == reserved)
        );
    }

    #[test]
    fn exact_readback_reconciles_a_write_that_crossed_before_status_failed() {
        let adapter = CrossingErrorAdapter {
            inner: PromptLimitedAdapter::default(),
        };
        let registry = registry(
            "11111111-1111-4111-8111-111111111111",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );

        put_with(&adapter, "service", "registry", &registry)
            .expect("exact readback reconciles crossed writes");
        assert!(
            get_with(&adapter, "service", "registry")
                .expect("reconciled readback")
                .is_some_and(|readback| readback == registry)
        );
    }

    #[test]
    fn failed_chunk_write_does_not_strand_a_new_generation() {
        let adapter = FaultInjectingAdapter::default();
        let first = registry(
            "11111111-1111-4111-8111-111111111111",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        let second = registry(
            "33333333-3333-4333-8333-333333333333",
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        );
        put_with(&adapter, "service", "registry", &first).expect("initial write");
        let keys_before = adapter.inner.stored_keys();

        adapter.fail_next_put_suffix("/1");
        assert!(put_with(&adapter, "service", "registry", &second).is_err());
        assert!(
            get_with(&adapter, "service", "registry")
                .expect("old credential read")
                .is_some_and(|value| value == first)
        );
        assert!(adapter.inner.stored_keys().len() > keys_before.len());
        put_with(&adapter, "service", "registry", &second).expect("retry write");
        delete_with(&adapter, "service", "registry").expect("delete after retry");
        assert!(adapter.inner.stored_keys().is_empty());
    }

    #[test]
    fn failed_replacement_publication_does_not_strand_a_new_generation() {
        let adapter = FaultInjectingAdapter::default();
        let first = registry(
            "11111111-1111-4111-8111-111111111111",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        let second = registry(
            "33333333-3333-4333-8333-333333333333",
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        );
        put_with(&adapter, "service", "registry", &first).expect("initial write");
        let keys_before = adapter.inner.stored_keys();

        adapter.fail_next_boundary(LifecycleBoundary::ReplacementPublication);
        assert!(put_with(&adapter, "service", "registry", &second).is_err());
        assert!(
            get_with(&adapter, "service", "registry")
                .expect("published credential read")
                .is_some_and(|value| value == second)
        );
        assert!(adapter.inner.stored_keys().len() > keys_before.len());
        put_with(&adapter, "service", "registry", &second).expect("retry write");
        delete_with(&adapter, "service", "registry").expect("delete after retry");
        assert!(adapter.inner.stored_keys().is_empty());
    }

    #[test]
    fn failed_chunk_delete_remains_discoverable_for_retry() {
        let adapter = FaultInjectingAdapter::default();
        let value = registry(
            "11111111-1111-4111-8111-111111111111",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        put_with(&adapter, "service", "registry", &value).expect("initial write");

        adapter.fail_next_delete_suffix("/1");
        assert!(delete_with(&adapter, "service", "registry").is_err());
        delete_with(&adapter, "service", "registry").expect("retry deletion");
        assert!(adapter.inner.stored_keys().is_empty());
    }

    #[test]
    fn manifest_bounds_reject_max_plus_one_and_usize_scale_before_chunk_reads() {
        const TEST_MAX_LOGICAL_CREDENTIAL_BYTES: usize = 16 * 1024;
        let adapter = PromptLimitedAdapter::default();
        let oversized = encode_manifest_unchecked(
            [7; 16],
            (TEST_MAX_LOGICAL_CREDENTIAL_BYTES + 1).div_ceil(CHUNK_SOURCE_BYTES),
            TEST_MAX_LOGICAL_CREDENTIAL_BYTES + 1,
            [9; 32],
        );
        let write_id = [7; 16];
        let generation = GenerationRef::new(
            write_id,
            (TEST_MAX_LOGICAL_CREDENTIAL_BYTES + 1).div_ceil(CHUNK_SOURCE_BYTES),
        )
        .expect("bounded generation reference");
        let inventory = GenerationInventory::new(InventoryState::Active, generation, None)
            .expect("bounded inventory");
        {
            let mut values = adapter.values.lock().expect("prompt-limited value lock");
            values.insert(
                ("service".to_owned(), inventory_key("registry")),
                inventory.encode().expect("inventory encoding"),
            );
            values.insert(
                ("service".to_owned(), "registry".to_owned()),
                ROOT_MARKER.to_owned(),
            );
            values.insert(
                (
                    "service".to_owned(),
                    generation_manifest_key("registry", &write_id),
                ),
                oversized,
            );
        }
        adapter.reset_reads();

        assert!(get_with(&adapter, "service", "registry").is_err());
        assert!(
            adapter
                .read_keys
                .lock()
                .expect("read-key lock")
                .iter()
                .all(|key| !key.starts_with(CHUNK_KEY_PREFIX))
        );

        let huge_len = usize::MAX - (usize::MAX % CHUNK_SOURCE_BYTES);
        let huge = encode_manifest_unchecked(
            [8; 16],
            huge_len.div_ceil(CHUNK_SOURCE_BYTES),
            huge_len,
            [10; 32],
        );
        assert!(parse_chunk_manifest(&huge).is_err());
    }

    #[test]
    fn max_plus_one_put_is_rejected_before_any_platform_write() {
        const TEST_MAX_LOGICAL_CREDENTIAL_BYTES: usize = 16 * 1024;
        let adapter = PromptLimitedAdapter::default();
        let oversized = "x".repeat(TEST_MAX_LOGICAL_CREDENTIAL_BYTES + 1);

        assert!(put_with(&adapter, "service", "oversized", &oversized).is_err());
        assert!(
            adapter
                .write_arguments
                .lock()
                .expect("write-argument lock")
                .is_empty()
        );
    }

    #[test]
    fn directly_seeded_prefix_colliding_legacy_value_remains_readable() {
        let adapter = PromptLimitedAdapter::default();
        let legacy = format!("{CHUNK_MANIFEST_PREFIX}preexisting-raw-secret");
        adapter
            .put_raw("service", "legacy-prefix", &legacy)
            .expect("legacy seed");

        assert_eq!(
            get_with(&adapter, "service", "legacy-prefix").expect("legacy read"),
            Some(legacy)
        );
    }

    #[test]
    fn canonical_looking_unconfirmed_legacy_value_is_preserved_as_ambiguous() {
        let adapter = PromptLimitedAdapter::default();
        let current = encode_manifest_unchecked([11; 16], 1, 1, [12; 32]);
        let encoded = current.strip_prefix(CHUNK_MANIFEST_PREFIX).expect("prefix");
        let mut decoded = URL_SAFE_NO_PAD.decode(encoded).expect("decode");
        decoded[0] = 1;
        let legacy = format!(
            "{LEGACY_V1_MANIFEST_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(decoded)
        );
        adapter
            .put_raw("service", "legacy-canonical", &legacy)
            .expect("legacy seed");

        assert!(get_with(&adapter, "service", "legacy-canonical").is_err());
        assert!(put_with(&adapter, "service", "legacy-canonical", "replacement").is_err());
        assert!(delete_with(&adapter, "service", "legacy-canonical").is_err());
        assert_eq!(
            adapter
                .get_raw("service", "legacy-canonical")
                .expect("raw read after rejected operations"),
            Some(legacy)
        );
    }

    #[test]
    fn confirmed_v1_generation_is_read_migrated_deleted_and_tampering_fails_closed() {
        let adapter = PromptLimitedAdapter::default();
        let first = registry(
            "11111111-1111-4111-8111-111111111111",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        seed_legacy_v1(&adapter, "service", "registry", &first, [21; 16]);
        assert_eq!(
            get_with(&adapter, "service", "registry").expect("v1 read"),
            Some(first.clone())
        );

        let second = registry(
            "33333333-3333-4333-8333-333333333333",
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        );
        put_with(&adapter, "service", "registry", &second).expect("v1 migration");
        assert_eq!(
            get_with(&adapter, "service", "registry").expect("v2 read"),
            Some(second)
        );
        assert!(
            adapter
                .stored_keys()
                .iter()
                .all(|key| !key.starts_with(LEGACY_V1_CHUNK_KEY_PREFIX))
        );
        delete_with(&adapter, "service", "registry").expect("v2 delete");
        assert!(adapter.stored_keys().is_empty());

        let corrupt = PromptLimitedAdapter::default();
        seed_legacy_v1(&corrupt, "service", "registry", &first, [22; 16]);
        corrupt.values.lock().expect("value lock").insert(
            (
                "service".to_owned(),
                legacy_v1_chunk_key("registry", &[22; 16], 0),
            ),
            URL_SAFE_NO_PAD.encode([b'x'; CHUNK_SOURCE_BYTES]),
        );
        assert!(get_with(&corrupt, "service", "registry").is_err());
    }

    #[test]
    fn overbound_v1_later_chunk_residue_never_falls_back_to_raw() {
        let adapter = PromptLimitedAdapter::default();
        let value = "x".repeat((MAX_CHUNK_COUNT + 1) * CHUNK_SOURCE_BYTES + 1);
        seed_legacy_v1(&adapter, "service", "registry", &value, [23; 16]);
        let later_chunk = legacy_v1_chunk_key("registry", &[23; 16], MAX_CHUNK_COUNT);
        adapter
            .values
            .lock()
            .expect("value lock")
            .retain(|(_, key), _| key == "registry" || key == &later_chunk);

        assert!(get_with(&adapter, "service", "registry").is_err());
        assert!(put_with(&adapter, "service", "registry", "replacement").is_err());
        assert!(delete_with(&adapter, "service", "registry").is_err());
        assert!(adapter.stored_keys().contains(&later_chunk));
    }

    fn assert_update_boundary_is_retryable(
        boundary: LifecycleBoundary,
        matching_boundaries_to_skip: usize,
        published: bool,
    ) {
        let adapter = FaultInjectingAdapter::default();
        let first = registry(
            "11111111-1111-4111-8111-111111111111",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        let second = registry(
            "33333333-3333-4333-8333-333333333333",
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        );
        put_with(&adapter, "service", "registry", &first).expect("initial write");
        adapter.fail_boundary_after(boundary, matching_boundaries_to_skip);

        assert!(put_with(&adapter, "service", "registry", &second).is_err());
        let visible = get_with(&adapter, "service", "registry")
            .expect("credential remains readable")
            .expect("credential remains present");
        assert!(if published {
            visible == second
        } else {
            visible == first
        });

        put_with(&adapter, "service", "registry", &second).expect("retry update");
        delete_with(&adapter, "service", "registry").expect("delete after retry");
        assert!(adapter.inner.stored_keys().is_empty());
    }

    #[test]
    fn every_staging_and_publication_boundary_is_retryable_without_stranding() {
        let sample = registry(
            "33333333-3333-4333-8333-333333333333",
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        );
        let chunk_count = sample.len().div_ceil(CHUNK_SOURCE_BYTES);

        assert_update_boundary_is_retryable(LifecycleBoundary::InventoryTransition, 0, false);
        assert_update_boundary_is_retryable(LifecycleBoundary::GenerationManifestWrite, 0, false);
        for index in 0..chunk_count {
            assert_update_boundary_is_retryable(LifecycleBoundary::ChunkWrite(index), 0, false);
        }
        assert_update_boundary_is_retryable(LifecycleBoundary::ReplacementPublication, 0, true);
        assert_update_boundary_is_retryable(LifecycleBoundary::InventoryTransition, 1, true);
    }

    #[test]
    fn legacy_root_and_inventory_transitions_are_retryable() {
        let legacy = format!("{CHUNK_MANIFEST_PREFIX}preexisting-raw-secret");
        let replacement = registry(
            "11111111-1111-4111-8111-111111111111",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        for boundary in [
            LifecycleBoundary::InventoryTransition,
            LifecycleBoundary::RootTransition,
        ] {
            let adapter = FaultInjectingAdapter::default();
            adapter
                .inner
                .put_raw("service", "registry", &legacy)
                .expect("legacy seed");
            adapter.fail_next_boundary(boundary);
            assert!(put_with(&adapter, "service", "registry", &replacement).is_err());
            let visible = get_with(&adapter, "service", "registry")
                .expect("transition read")
                .expect("transition value");
            assert!(visible == legacy || visible == replacement);
            put_with(&adapter, "service", "registry", &replacement).expect("transition retry");
            delete_with(&adapter, "service", "registry").expect("transition cleanup");
            assert!(adapter.inner.stored_keys().is_empty());
        }
    }

    fn assert_delete_boundary_is_retryable(
        boundary: LifecycleBoundary,
        matching_boundaries_to_skip: usize,
    ) {
        let adapter = FaultInjectingAdapter::default();
        let value = registry(
            "11111111-1111-4111-8111-111111111111",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        put_with(&adapter, "service", "registry", &value).expect("initial write");
        adapter.fail_boundary_after(boundary, matching_boundaries_to_skip);
        assert!(delete_with(&adapter, "service", "registry").is_err());
        delete_with(&adapter, "service", "registry").expect("retry deletion");
        assert!(adapter.inner.stored_keys().is_empty());
    }

    #[test]
    fn every_delete_boundary_retains_inventory_until_retryable_cleanup() {
        let sample = registry(
            "11111111-1111-4111-8111-111111111111",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        let chunk_count = sample.len().div_ceil(CHUNK_SOURCE_BYTES);

        assert_delete_boundary_is_retryable(LifecycleBoundary::InventoryTransition, 0);
        for index in 0..chunk_count {
            assert_delete_boundary_is_retryable(LifecycleBoundary::ChunkDelete(index), 0);
        }
        assert_delete_boundary_is_retryable(LifecycleBoundary::GenerationManifestDelete, 0);
        assert_delete_boundary_is_retryable(LifecycleBoundary::RootDelete, 0);
        assert_delete_boundary_is_retryable(LifecycleBoundary::InventoryDelete, 0);
    }

    #[test]
    fn exact_manifest_inventory_and_logical_bounds_are_enforced() {
        const { assert!(MAX_ENCODED_MANIFEST_BYTES <= PROMPT_MAX_VALUE_BYTES) };
        const { assert!(MAX_ENCODED_INVENTORY_BYTES <= PROMPT_MAX_VALUE_BYTES) };
        assert_eq!(
            MAX_CHUNK_COUNT,
            MAX_LOGICAL_CREDENTIAL_BYTES.div_ceil(CHUNK_SOURCE_BYTES)
        );

        let maximum = "x".repeat(MAX_LOGICAL_CREDENTIAL_BYTES);
        let adapter = PromptLimitedAdapter::default();
        put_with(&adapter, "service", "maximum", &maximum).expect("maximum write");
        assert!(
            get_with(&adapter, "service", "maximum")
                .expect("maximum read")
                .is_some_and(|readback| readback == maximum)
        );
        delete_with(&adapter, "service", "maximum").expect("maximum delete");
        assert!(adapter.stored_keys().is_empty());

        let empty = PromptLimitedAdapter::default();
        put_with(&empty, "service", "empty", "").expect("empty write");
        assert_eq!(
            get_with(&empty, "service", "empty").expect("empty read"),
            Some(String::new())
        );
    }

    #[test]
    fn overlong_metadata_and_chunks_fail_before_unbounded_adapter_work() {
        let adapter = PromptLimitedAdapter::default();
        let write_id = [13; 16];
        let generation = GenerationRef::new(write_id, 1).expect("generation reference");
        let inventory =
            GenerationInventory::new(InventoryState::Active, generation, None).expect("inventory");
        {
            let mut values = adapter.values.lock().expect("value lock");
            values.insert(
                ("service".to_owned(), inventory_key("registry")),
                inventory.encode().expect("inventory encoding"),
            );
            values.insert(
                ("service".to_owned(), "registry".to_owned()),
                ROOT_MARKER.to_owned(),
            );
            values.insert(
                (
                    "service".to_owned(),
                    generation_manifest_key("registry", &write_id),
                ),
                format!(
                    "{CHUNK_MANIFEST_PREFIX}{}",
                    "A".repeat(CHUNK_MANIFEST_PAYLOAD_BYTES + 1)
                ),
            );
        }
        adapter.reset_reads();
        assert!(get_with(&adapter, "service", "registry").is_err());
        assert!(
            adapter
                .read_keys
                .lock()
                .expect("read-key lock")
                .iter()
                .all(|key| !key.starts_with(CHUNK_KEY_PREFIX))
        );

        let corrupt_inventory = PromptLimitedAdapter::default();
        corrupt_inventory.values.lock().expect("value lock").insert(
            ("service".to_owned(), inventory_key("legacy")),
            format!(
                "{INVENTORY_PREFIX}{}",
                "A".repeat(INVENTORY_PAYLOAD_BYTES + 1)
            ),
        );
        corrupt_inventory.reset_reads();
        assert!(get_with(&corrupt_inventory, "service", "legacy").is_err());
        assert_eq!(
            corrupt_inventory
                .read_keys
                .lock()
                .expect("read-key lock")
                .as_slice(),
            [inventory_key("legacy")]
        );
    }

    #[test]
    fn confirmed_corruption_fails_closed_without_legacy_fallback() {
        let adapter = PromptLimitedAdapter::default();
        let secret = registry(
            "11111111-1111-4111-8111-111111111111",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        put_with(&adapter, "service", "registry", &secret).expect("managed write");
        let inventory = read_inventory(&adapter, "service", "registry")
            .expect("inventory read")
            .expect("inventory");
        adapter.values.lock().expect("value lock").insert(
            (
                "service".to_owned(),
                generation_manifest_key("registry", &inventory.primary.write_id),
            ),
            format!("{CHUNK_MANIFEST_PREFIX}corrupt-confirmed"),
        );

        let error = get_with(&adapter, "service", "registry")
            .expect_err("confirmed corruption must fail closed")
            .to_string();
        assert!(!error.contains(&secret));
        assert!(!error.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }
}

#[cfg(test)]
#[path = "macos_keyring_rework_tests.rs"]
mod rework_tests;
