#![allow(clippy::expect_used)]

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Barrier, Condvar, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use super::*;

#[derive(Default)]
struct MapAdapter {
    values: Mutex<BTreeMap<(String, String), String>>,
}

impl MacosKeychainAdapter for MapAdapter {
    fn put_raw(&self, service: &str, key: &str, value: &str) -> Result<()> {
        self.values
            .lock()
            .expect("value lock")
            .insert((service.to_owned(), key.to_owned()), value.to_owned());
        Ok(())
    }

    fn get_raw(&self, service: &str, key: &str) -> Result<Option<String>> {
        Ok(self
            .values
            .lock()
            .expect("value lock")
            .get(&(service.to_owned(), key.to_owned()))
            .cloned())
    }

    fn delete_raw(&self, service: &str, key: &str) -> Result<()> {
        self.values
            .lock()
            .expect("value lock")
            .remove(&(service.to_owned(), key.to_owned()));
        Ok(())
    }
}

fn canonical_v1_root() -> String {
    let mut bytes = Vec::with_capacity(CHUNK_MANIFEST_BYTES);
    bytes.push(1);
    bytes.extend_from_slice(&[41; 16]);
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    bytes.extend_from_slice(&[42; 32]);
    format!(
        "{LEGACY_V1_MANIFEST_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(bytes)
    )
}

#[test]
fn canonical_v1_root_without_chunks_is_ambiguous_not_raw() {
    let adapter = MapAdapter::default();
    let root = canonical_v1_root();
    adapter
        .put_raw("service", "credential", &root)
        .expect("seed canonical v1 root");

    let error = get_with(&adapter, "service", "credential")
        .expect_err("canonical v1 root without provenance must fail closed")
        .to_string();
    assert!(error.contains("ambiguous"));
    assert!(put_with(&adapter, "service", "credential", "replacement").is_err());
    assert!(delete_with(&adapter, "service", "credential").is_err());
    assert_eq!(
        adapter
            .get_raw("service", "credential")
            .expect("raw read after rejected operations"),
        Some(root)
    );
}

#[test]
fn security_stdout_accepts_exact_maximum_with_lf_frame() {
    let mut output = vec![b'x'; MAX_LOGICAL_CREDENTIAL_BYTES];
    output.push(b'\n');

    let decoded = platform::decode_security_stdout(output)
        .expect("one LF frame must not consume the logical byte allowance");
    assert_eq!(decoded.len(), MAX_LOGICAL_CREDENTIAL_BYTES);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RaceMode {
    PutPut,
    PutDelete,
}

#[derive(Default)]
struct ScheduleState {
    first_writer_pending: bool,
    second_writer_transitions: usize,
    second_writer_finished: bool,
    delete_finished: bool,
}

struct InterleavingAdapter {
    inner: MapAdapter,
    mode: Mutex<Option<RaceMode>>,
    active_snapshot_reads: AtomicUsize,
    snapshots_ready: Barrier,
    schedule: Mutex<ScheduleState>,
    schedule_changed: Condvar,
    mutation_lock: Mutex<()>,
    lock_depth: AtomicUsize,
    enabled: AtomicBool,
}

struct TestMutationGuard<'a> {
    _guard: MutexGuard<'a, ()>,
    depth: &'a AtomicUsize,
}

impl Drop for TestMutationGuard<'_> {
    fn drop(&mut self) {
        self.depth.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Default for InterleavingAdapter {
    fn default() -> Self {
        Self {
            inner: MapAdapter::default(),
            mode: Mutex::new(None),
            active_snapshot_reads: AtomicUsize::new(0),
            snapshots_ready: Barrier::new(2),
            schedule: Mutex::new(ScheduleState::default()),
            schedule_changed: Condvar::new(),
            mutation_lock: Mutex::new(()),
            lock_depth: AtomicUsize::new(0),
            enabled: AtomicBool::new(false),
        }
    }
}

impl InterleavingAdapter {
    fn begin(&self, mode: RaceMode) {
        *self.mode.lock().expect("mode lock") = Some(mode);
        self.enabled.store(true, Ordering::SeqCst);
    }

    fn finish(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }

    fn is_unserialized_race(&self) -> bool {
        self.enabled.load(Ordering::SeqCst) && self.lock_depth.load(Ordering::SeqCst) == 0
    }

    fn stored_keys(&self) -> Vec<String> {
        self.inner
            .values
            .lock()
            .expect("value lock")
            .keys()
            .map(|(_, key)| key.clone())
            .collect()
    }
}

impl MacosKeychainAdapter for InterleavingAdapter {
    fn put_raw(&self, service: &str, key: &str, value: &str) -> Result<()> {
        if self.is_unserialized_race() && key.starts_with(INVENTORY_KEY_PREFIX) {
            let state = parse_inventory(value).map(|inventory| inventory.state).ok();
            let thread = std::thread::current();
            let name = thread.name().unwrap_or_default();
            let mode = *self.mode.lock().expect("mode lock");
            let must_wait = (mode == Some(RaceMode::PutPut)
                && name == "writer-b"
                && state == Some(InventoryState::ActiveWithPending))
                || (mode == Some(RaceMode::PutDelete)
                    && name == "writer-delete"
                    && state == Some(InventoryState::Deleting));
            if must_wait {
                let mut schedule = self.schedule.lock().expect("schedule lock");
                while !schedule.first_writer_pending {
                    schedule = self.schedule_changed.wait(schedule).expect("schedule wait");
                }
            }
        }
        self.inner.put_raw(service, key, value)
    }

    fn get_raw(&self, service: &str, key: &str) -> Result<Option<String>> {
        let value = self.inner.get_raw(service, key)?;
        if self.is_unserialized_race()
            && key.starts_with(INVENTORY_KEY_PREFIX)
            && value.as_deref().is_some_and(|encoded| {
                parse_inventory(encoded)
                    .is_ok_and(|inventory| inventory.state == InventoryState::Active)
            })
            && self.active_snapshot_reads.fetch_add(1, Ordering::SeqCst) < 2
        {
            self.snapshots_ready.wait();
        }
        Ok(value)
    }

    fn delete_raw(&self, service: &str, key: &str) -> Result<()> {
        self.inner.delete_raw(service, key)
    }

    fn acquire_mutation_lock<'a>(
        &'a self,
        _service: &str,
        _key: &str,
    ) -> Result<Box<dyn MutationGuard + 'a>> {
        let guard = self.mutation_lock.lock().expect("mutation lock");
        self.lock_depth.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(TestMutationGuard {
            _guard: guard,
            depth: &self.lock_depth,
        }))
    }

    fn checkpoint(&self, boundary: LifecycleBoundary) -> Result<()> {
        if !self.is_unserialized_race() {
            return Ok(());
        }
        let thread = std::thread::current();
        let name = thread.name().unwrap_or_default();
        let mode = *self.mode.lock().expect("mode lock");
        let mut schedule = self.schedule.lock().expect("schedule lock");
        if matches!(name, "writer-a" | "writer-put")
            && boundary == LifecycleBoundary::InventoryTransition
            && !schedule.first_writer_pending
        {
            schedule.first_writer_pending = true;
            self.schedule_changed.notify_all();
            while !(schedule.second_writer_finished || schedule.delete_finished) {
                schedule = self.schedule_changed.wait(schedule).expect("schedule wait");
            }
        } else if mode == Some(RaceMode::PutPut)
            && name == "writer-b"
            && boundary == LifecycleBoundary::InventoryTransition
        {
            schedule.second_writer_transitions += 1;
            if schedule.second_writer_transitions == 2 {
                schedule.second_writer_finished = true;
                self.schedule_changed.notify_all();
            }
        } else if mode == Some(RaceMode::PutDelete)
            && name == "writer-delete"
            && boundary == LifecycleBoundary::InventoryDelete
        {
            schedule.delete_finished = true;
            self.schedule_changed.notify_all();
        }
        Ok(())
    }
}

fn value(label: char) -> String {
    label.to_string().repeat(CHUNK_SOURCE_BYTES * 2)
}

#[test]
fn concurrent_puts_leave_no_unowned_generation() {
    let adapter = Arc::new(InterleavingAdapter::default());
    put_with(adapter.as_ref(), "service", "credential", &value('a')).expect("initial put");
    adapter.begin(RaceMode::PutPut);

    let writer_a = Arc::clone(&adapter);
    let writer_a = std::thread::Builder::new()
        .name("writer-a".to_owned())
        .spawn(move || put_with(writer_a.as_ref(), "service", "credential", &value('b')))
        .expect("spawn writer a");
    let writer_b = Arc::clone(&adapter);
    let writer_b = std::thread::Builder::new()
        .name("writer-b".to_owned())
        .spawn(move || put_with(writer_b.as_ref(), "service", "credential", &value('c')))
        .expect("spawn writer b");
    writer_a.join().expect("join writer a").expect("writer a");
    writer_b.join().expect("join writer b").expect("writer b");

    adapter.finish();
    delete_with(adapter.as_ref(), "service", "credential").expect("delete winner");
    assert!(adapter.stored_keys().is_empty());
}

#[test]
fn concurrent_put_delete_never_acknowledges_broken_state() {
    let adapter = Arc::new(InterleavingAdapter::default());
    put_with(adapter.as_ref(), "service", "credential", &value('a')).expect("initial put");
    adapter.begin(RaceMode::PutDelete);

    let writer = Arc::clone(&adapter);
    let writer = std::thread::Builder::new()
        .name("writer-put".to_owned())
        .spawn(move || put_with(writer.as_ref(), "service", "credential", &value('b')))
        .expect("spawn writer");
    let deleter = Arc::clone(&adapter);
    let deleter = std::thread::Builder::new()
        .name("writer-delete".to_owned())
        .spawn(move || delete_with(deleter.as_ref(), "service", "credential"))
        .expect("spawn deleter");
    writer.join().expect("join writer").expect("writer");
    deleter.join().expect("join deleter").expect("deleter");

    adapter.finish();
    let visible = get_with(adapter.as_ref(), "service", "credential");
    assert!(matches!(visible, Ok(None | Some(_))));
    delete_with(adapter.as_ref(), "service", "credential").expect("final cleanup");
    assert!(adapter.stored_keys().is_empty());
}
