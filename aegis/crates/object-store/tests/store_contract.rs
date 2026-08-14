//! Executable contract for design doc §8 Storage and §10 [CLOSED]:
//! - ground truth is content-addressed immutable blocks (one deduped region per
//!   unique content);
//! - blocks are capability-addressed: the content hash and even the kernel object
//!   id grant nothing — reading requires a region cap granted into *your* CSpace;
//! - mutable data is a copy-on-write layer; snapshots are version-stable;
//! - a write can never await, block on, or depend on the relationship index:
//!   commit signatures mention no index, storage works with no index at all, and
//!   a lagging or missing index cannot disturb reads or writes; the index is a
//!   pure consumer of the write-ahead log and fully rebuildable from it.

use capability_core::{CapHandle, Kernel, KernelError, ObjectKind, Rights, TaskHandle};
use object_store::{FlatView, RelationshipIndex, Store};

struct World {
    k: Kernel,
    root: TaskHandle,
    creator: CapHandle,
    svc: TaskHandle,
    svc_cap: CapHandle,
    store: Store,
}

/// Boot the scene: root grants the store service its own Creator cap; the store
/// acts only under its service identity from then on.
fn world() -> World {
    let mut k = Kernel::new();
    let (root, _, creator) = k.boot("session").unwrap();
    let (svc, svc_cap) = k.create_task(root, creator, "object-store").unwrap();
    k.grant(root, creator, svc_cap, Rights::ALL, None).unwrap();
    let creator_slot = (0..256u32)
        .map(|s| (s, k.cap_info(svc, CapHandle(s))))
        .find(|(_, i)| matches!(i, Ok(c) if c.kind == ObjectKind::Creator))
        .unwrap()
        .0;
    let store = Store::new(svc, CapHandle(creator_slot));
    World {
        k,
        root,
        creator,
        svc,
        svc_cap,
        store,
    }
}

/// A naming cap the *service* holds, naming `t` — root mints it into the service's
/// own CSpace (grants resolve all handles against the grantor's table), carrying
/// RECEIVE as I6 requires of naming caps.
fn svc_name_for(w: &mut World, t: TaskHandle, task_cap_in_root: CapHandle) -> CapHandle {
    w.k.grant(w.root, task_cap_in_root, w.svc_cap, Rights::RECEIVE, None)
        .unwrap();
    let slot = (0..256u32)
        .map(|s| (s, w.k.cap_info(w.svc, CapHandle(s))))
        .find(|(_, i)| matches!(i, Ok(c) if c.obj == t.id()))
        .unwrap()
        .0;
    CapHandle(slot)
}

/// Identical bytes are the same block: content-addressed, stored once.
#[test]
fn identical_bytes_are_one_block() {
    let mut w = world();
    let a = w.store.commit(&mut w.k, b"same bytes").unwrap();
    let b = w.store.commit(&mut w.k, b"same bytes").unwrap();
    assert_eq!(a, b, "content addressing: same content, same block");
    assert_eq!(
        w.store.block_count(),
        1,
        "dedup: one region for both commits"
    );
}

/// A block id is a *name*, not an address: a consumer who knows both the hash
/// and the kernel object id cannot read until a capability is granted into its
/// own CSpace; the granted cap is a narrowed READ copy it cannot widen (I2).
#[test]
fn blocks_are_capability_addressed() {
    let mut w = world();
    let id = w.store.commit(&mut w.k, b"classified payload").unwrap();
    let obj = w.store.block_obj(&id).unwrap();

    let (reader, reader_cap) = w.k.create_task(w.root, w.creator, "reader").unwrap();
    // The reader "knows" the object id — and its CSpace holds no region cap.
    let _ = obj;
    assert_eq!(
        w.k.caps_of(reader).len(),
        1,
        "reader holds only its self cap"
    );
    // Fabricated handles into the reader's (mostly empty) table fail cleanly.
    assert!(w.k.mem_read(reader, CapHandle(255), 0, 1).is_err());
    assert_eq!(
        w.k.mem_read(reader, CapHandle(0), 0, 1).unwrap_err(),
        KernelError::WrongObjectType
    );

    // The store grants READ — placed in the reader's own CSpace.
    let name = svc_name_for(&mut w, reader, reader_cap);
    let slot = w.store.grant_read(&mut w.k, reader, name, &id).unwrap();
    assert_eq!(
        w.k.mem_read(reader, CapHandle(slot), 0, 18).unwrap(),
        b"classified payload".to_vec()
    );
    // The granted cap is a narrowed copy: WRITE on it is refused.
    assert_eq!(
        w.k.mem_write(reader, CapHandle(slot), 0, b"x".to_vec())
            .unwrap_err(),
        KernelError::InsufficientRights(Rights::WRITE)
    );
}

/// Mutable data is a copy-on-write layer: a write never mutates an existing
/// block or node region. Snapshot stability is therefore mechanical — whatever
/// node id you hold, you read that version forever.
#[test]
fn cow_write_versions_are_immutable_snapshots() {
    let mut w = world();
    let v0 = w.store.new_object(&mut w.k).unwrap();
    let v1 = w.store.write_version(&mut w.k, v0, b"draft one").unwrap();
    assert_eq!(w.store.snapshot(&mut w.k, v0).unwrap(), b"".to_vec());
    assert_eq!(
        w.store.snapshot(&mut w.k, v1).unwrap(),
        b"draft one".to_vec()
    );

    let v2 = w
        .store
        .write_version(&mut w.k, v1, b"draft two, bigger")
        .unwrap();
    assert_eq!(
        w.store.snapshot(&mut w.k, v1).unwrap(),
        b"draft one".to_vec()
    );
    assert_eq!(
        w.store.snapshot(&mut w.k, v2).unwrap(),
        b"draft two, bigger".to_vec()
    );
    assert_eq!(
        w.store.block_count(),
        2,
        "two content blocks, zero mutations"
    );
}

/// The index consumes only the write-ahead log and rebuilds purely from it:
/// it is a cache over the store, never part of it.
#[test]
fn index_is_a_consumer_of_the_wal_and_rebuilds_from_it() {
    let mut w = world();
    let v0 = w.store.new_object(&mut w.k).unwrap();
    let v1 = w.store.write_version(&mut w.k, v0, b"v1").unwrap();
    let v2 = w.store.write_version(&mut w.k, v1, b"v2").unwrap();
    let v3 = w.store.write_version(&mut w.k, v2, b"v3").unwrap();

    let mut idx = RelationshipIndex::new();
    idx.ingest(w.store.wal());
    assert_eq!(idx.consumed_seq(), w.store.wal().len() as u64);
    assert_eq!(idx.node_count(), 4, "v0..v3 all present");
    assert_eq!(idx.children_of(v0), vec![v1]);
    assert!(idx.is_derived_from(v0, v3));
    assert!(!idx.is_derived_from(v3, v0), "derivation is not symmetric");

    // Drop the index; rebuild from the log; identical answers.
    let mut fresh = RelationshipIndex::new();
    fresh.rebuild(w.store.wal());
    assert_eq!(fresh.node_count(), idx.node_count());
    assert_eq!(fresh.children_of(v0), idx.children_of(v0));
    assert_eq!(fresh.consumed_seq(), idx.consumed_seq());
}

/// The §10 [CLOSED] contract, stated as types and as behavior:
/// (a) commit's signature mentions no index — pinned by assigning each function
///     to a pointer type with no way to carry one;
/// (b) storage works with no index ever registered;
/// (c) an index that has been down the whole time catches up later, and its
///     absence changed nothing.
#[test]
fn the_index_can_never_participate_in_a_write() {
    // (a) If `commit` or `write_version` took or returned anything index-shaped,
    // these assignments could not compile.
    let _commit: fn(&mut Store, &mut Kernel, &[u8]) -> Option<object_store::BlockId> =
        Store::commit;
    let _write: fn(&mut Store, &mut Kernel, u64, &[u8]) -> Option<u64> = Store::write_version;

    // (b) A full workload with no index registered anywhere.
    let mut w = world();
    let mut view = FlatView::new(&mut w.k, &mut w.store).unwrap();
    view.create_file(&mut w.k, &mut w.store, "memo.txt");
    view.write_file(
        &mut w.k,
        &mut w.store,
        "memo.txt",
        b"appears even though no index exists",
    );
    assert_eq!(
        view.read_file(&mut w.k, &mut w.store, "memo.txt").unwrap(),
        b"appears even though no index exists".to_vec()
    );

    // (c) The index "comes online" after all of it, consuming only the log.
    let mut idx = RelationshipIndex::new();
    idx.ingest(w.store.wal());
    assert_eq!(
        idx.block_count(),
        3,
        "three content blocks: the memo body, the dir after create, the dir after write"
    );
}

/// The POSIX file view is a projection over the store: file bytes are store
/// blocks, the namespace is a COW store object, and every mutation is WAL
/// material. There is no second source of truth to drift.
#[test]
fn posix_view_is_a_projection_with_no_second_source_of_truth() {
    let mut w = world();
    let wal_before = w.store.wal().len();
    let mut view = FlatView::new(&mut w.k, &mut w.store).unwrap();
    view.create_file(&mut w.k, &mut w.store, "a.txt");
    view.write_file(&mut w.k, &mut w.store, "a.txt", b"alpha");
    view.create_file(&mut w.k, &mut w.store, "b.txt");
    view.write_file(&mut w.k, &mut w.store, "b.txt", b"beta");
    assert_eq!(view.list(&mut w.k, &mut w.store).len(), 2);
    assert_eq!(
        view.read_file(&mut w.k, &mut w.store, "a.txt").unwrap(),
        b"alpha".to_vec()
    );
    assert!(view.delete_file(&mut w.k, &mut w.store, "a.txt"));
    assert_eq!(view.list(&mut w.k, &mut w.store), vec!["b.txt".to_string()]);

    // The bytes live only in the store: the WAL grew at every mutation.
    assert!(w.store.wal().len() > wal_before);
}

/// The hierarchical POSIX view (TreeView): nested directories, path
/// resolution (absolute, relative, `.`/`..`), mode/uid as projection metadata,
/// and COW rewriting of the whole root→parent path so snapshots stay
/// version-stable at every level.
#[test]
fn treeview_creates_nested_paths_and_rewrites_the_root_cow() {
    let mut w = world();
    let mut view = object_store::TreeView::new(&mut w.k, &mut w.store).unwrap();
    let root_v0 = view.root();

    assert!(view.mkdir(&mut w.k, &mut w.store, "/home", object_store::MODE_DIR));
    assert!(view.mkdir(
        &mut w.k,
        &mut w.store,
        "/home/alice",
        object_store::MODE_DIR
    ));
    // Parents /home/alice/docs missing: refused, nothing half-created.
    assert!(!view.create_file(
        &mut w.k,
        &mut w.store,
        "/home/alice/docs/report.txt",
        object_store::MODE_FILE
    ));
    assert!(view.mkdir(
        &mut w.k,
        &mut w.store,
        "/home/alice/docs",
        object_store::MODE_DIR
    ));
    assert!(view.create_file(
        &mut w.k,
        &mut w.store,
        "/home/alice/docs/report.txt",
        object_store::MODE_FILE
    ));
    assert!(view.write_file(
        &mut w.k,
        &mut w.store,
        "/home/alice/docs/report.txt",
        b"Phase C: nested POSIX view"
    ));

    assert_eq!(
        view.read_file(&mut w.k, &mut w.store, "/home/alice/docs/report.txt")
            .unwrap(),
        b"Phase C: nested POSIX view".to_vec()
    );
    let (kind, mode, _, size) = view
        .stat(&mut w.k, &mut w.store, "/home/alice/docs/report.txt")
        .unwrap();
    assert_eq!(kind, object_store::EntryKind::File);
    assert_eq!(mode, object_store::MODE_FILE);
    assert_eq!(size, 26);

    // The root is rewritten by a deep mutation; the old root still reads the
    // old tree (COW all the way up).
    let root_v1 = view.root();
    assert_ne!(root_v0, root_v1);
    assert!(view.write_file(&mut w.k, &mut w.store, "/home/alice/docs/report.txt", b"v2"));
    let old_root_entries = view.snapshot_dir(&mut w.k, &mut w.store, root_v1).unwrap();
    assert!(
        old_root_entries.iter().any(|e| e.name == "home"),
        "old root still lists the tree it pointed at"
    );
}

#[test]
fn treeview_path_resolution_handles_abs_dot_dotdot_and_cwd() {
    let mut w = world();
    let mut view = object_store::TreeView::new(&mut w.k, &mut w.store).unwrap();
    assert!(view.mkdir(&mut w.k, &mut w.store, "/home", object_store::MODE_DIR));
    assert!(view.mkdir(
        &mut w.k,
        &mut w.store,
        "/home/alice",
        object_store::MODE_DIR
    ));
    assert!(view.create_file(
        &mut w.k,
        &mut w.store,
        "/home/alice/notes.txt",
        object_store::MODE_FILE
    ));
    assert!(view.write_file(&mut w.k, &mut w.store, "/home/alice/notes.txt", b"alpha"));

    assert_eq!(
        view.read_file(&mut w.k, &mut w.store, "/home/alice/notes.txt")
            .unwrap(),
        b"alpha".to_vec()
    );
    assert!(view.cd(&mut w.k, &mut w.store, "/home/alice"));
    assert_eq!(
        view.read_file(&mut w.k, &mut w.store, "notes.txt").unwrap(),
        b"alpha".to_vec()
    );
    assert_eq!(
        view.read_file(&mut w.k, &mut w.store, "./notes.txt")
            .unwrap(),
        b"alpha".to_vec()
    );
    assert_eq!(
        view.read_file(&mut w.k, &mut w.store, "../alice/notes.txt")
            .unwrap(),
        b"alpha".to_vec()
    );
    assert_eq!(
        view.list(&mut w.k, &mut w.store, "..").unwrap().len(),
        1,
        ".. -> /home"
    );

    assert!(view.cd(&mut w.k, &mut w.store, "/"));
    assert!(view.cd(&mut w.k, &mut w.store, ".."));
    assert_eq!(view.cwd(&mut w.k, &mut w.store).unwrap(), view.root());
}

#[test]
fn treeview_unlink_and_rmdir_enforce_emptiness_and_existence() {
    let mut w = world();
    let mut view = object_store::TreeView::new(&mut w.k, &mut w.store).unwrap();
    assert!(view.mkdir(&mut w.k, &mut w.store, "/d", object_store::MODE_DIR));
    assert!(view.create_file(&mut w.k, &mut w.store, "/d/x.txt", object_store::MODE_FILE));
    assert!(view.write_file(&mut w.k, &mut w.store, "/d/x.txt", b"x"));

    assert!(!view.rmdir(&mut w.k, &mut w.store, "/d")); // not empty
    assert!(!view.unlink(&mut w.k, &mut w.store, "/d/missing.txt"));
    assert!(view.unlink(&mut w.k, &mut w.store, "/d/x.txt"));
    assert!(view.rmdir(&mut w.k, &mut w.store, "/d"));
    assert!(view.stat(&mut w.k, &mut w.store, "/d").is_none());
    assert!(!view.rmdir(&mut w.k, &mut w.store, "/")); // the root is not removable
    assert!(view.stat(&mut w.k, &mut w.store, "/").is_some());
}
