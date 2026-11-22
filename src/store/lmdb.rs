//! A small, safe wrapper over the LMDB C API, after Ditto Relay's.
//!
//! The history index is a `DUPSORT | DUPFIXED` table: each key is stored
//! once, and its values are packed side by side in pages of their own,
//! several times smaller than a key per entry. heed can't read those pages
//! whole (`MDB_GET_MULTIPLE`), so this talks to LMDB directly.
//!
//! All of the store's `unsafe` that isn't memory maps lives here.

use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::path::Path;
use std::ptr;

use lmdb_master_sys as ffi;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(i32);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // SAFETY: mdb_strerror returns a static, NUL-terminated string for any code.
        let message = unsafe { CStr::from_ptr(ffi::mdb_strerror(self.0)) };
        write!(f, "LMDB: {}", message.to_string_lossy())
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

fn check(code: i32) -> Result<()> {
    if code == ffi::MDB_SUCCESS { Ok(()) } else { Err(Error(code)) }
}

fn found(code: i32) -> Result<bool> {
    match code {
        ffi::MDB_SUCCESS => Ok(true),
        ffi::MDB_NOTFOUND => Ok(false),
        code => Err(Error(code)),
    }
}

fn val(bytes: &[u8]) -> ffi::MDB_val {
    ffi::MDB_val { mv_size: bytes.len(), mv_data: bytes.as_ptr() as *mut _ }
}

fn empty() -> ffi::MDB_val {
    ffi::MDB_val { mv_size: 0, mv_data: ptr::null_mut() }
}

/// # Safety
/// `v` must have come from LMDB within a transaction that outlives `'t`.
unsafe fn bytes<'t>(v: &ffi::MDB_val) -> &'t [u8] {
    if v.mv_size == 0 {
        &[]
    } else {
        // SAFETY: LMDB hands back pointers into the map valid for the transaction.
        unsafe { std::slice::from_raw_parts(v.mv_data as *const u8, v.mv_size) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Db(ffi::MDB_dbi);

pub struct Env {
    ptr: *mut ffi::MDB_env,
}

// SAFETY: an MDB_env may be shared between threads; transactions carry their
// own restrictions, enforced by the types below.
unsafe impl Send for Env {}
unsafe impl Sync for Env {}

impl Drop for Env {
    fn drop(&mut self) {
        // SAFETY: transactions borrow the Env, so none outlive it.
        unsafe { ffi::mdb_env_close(self.ptr) }
    }
}

impl Env {
    /// Opens (or makes) the environment in the directory `path`.
    pub fn open(path: &Path, map_size: usize, max_dbs: u32) -> Result<Env> {
        let mut ptr = ptr::null_mut();
        // SAFETY: creates an environment handle, closed on drop or here on failure.
        check(unsafe { ffi::mdb_env_create(&mut ptr) })?;
        let env = Env { ptr };
        let path = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| Error(libc::EINVAL))?;
        // SAFETY: a fresh environment, configured before it's opened.
        unsafe {
            check(ffi::mdb_env_set_mapsize(env.ptr, map_size))?;
            check(ffi::mdb_env_set_maxdbs(env.ptr, max_dbs))?;
            check(ffi::mdb_env_set_maxreaders(env.ptr, 1022))?;
            // NOTLS: read transactions may move between the threads of the
            // HTTP server's pool. NORDAHEAD: lookups are random, and the
            // kernel's read-ahead would only crowd the page cache.
            let flags = ffi::MDB_NOTLS | ffi::MDB_NORDAHEAD;
            check(ffi::mdb_env_open(env.ptr, path.as_ptr(), flags, 0o644))?;
        }
        Ok(env)
    }

    pub fn create_db(&self, name: &str, dup_fixed: bool) -> Result<Db> {
        let name = CString::new(name).expect("no NUL in a table name");
        let mut flags = ffi::MDB_CREATE;
        if dup_fixed {
            flags |= ffi::MDB_DUPSORT | ffi::MDB_DUPFIXED;
        }
        let mut txn = ptr::null_mut();
        let mut dbi = 0;
        // SAFETY: a write transaction just to open the table, committed here.
        unsafe {
            check(ffi::mdb_txn_begin(self.ptr, ptr::null_mut(), 0, &mut txn))?;
            if let Err(err) = check(ffi::mdb_dbi_open(txn, name.as_ptr(), flags, &mut dbi)) {
                ffi::mdb_txn_abort(txn);
                return Err(err);
            }
            check(ffi::mdb_txn_commit(txn))?;
        }
        Ok(Db(dbi))
    }

    fn begin(&self, flags: u32) -> Result<Txn<'_>> {
        let mut ptr = ptr::null_mut();
        // SAFETY: the env is open; the transaction is ended by Txn's drop or commit.
        check(unsafe { ffi::mdb_txn_begin(self.ptr, ptr::null_mut(), flags, &mut ptr) })?;
        Ok(Txn { ptr, _env: PhantomData })
    }

    pub fn read_txn(&self) -> Result<RoTxn<'_>> {
        Ok(RoTxn(self.begin(ffi::MDB_RDONLY)?))
    }

    pub fn write_txn(&self) -> Result<RwTxn<'_>> {
        Ok(RwTxn(self.begin(0)?))
    }

    /// How many bytes of its map are in use.
    pub fn used_bytes(&self) -> Result<u64> {
        // SAFETY: plain data, filled in by LMDB from an open env.
        let mut info = unsafe { std::mem::zeroed::<ffi::MDB_envinfo>() };
        let mut stat = unsafe { std::mem::zeroed::<ffi::MDB_stat>() };
        check(unsafe { ffi::mdb_env_info(self.ptr, &mut info) })?;
        check(unsafe { ffi::mdb_env_stat(self.ptr, &mut stat) })?;
        Ok((info.me_last_pgno as u64 + 1) * stat.ms_psize as u64)
    }
}

pub struct Txn<'env> {
    ptr: *mut ffi::MDB_txn,
    _env: PhantomData<&'env Env>,
}

impl Txn<'_> {
    pub fn get(&self, db: Db, key: &[u8]) -> Result<Option<&[u8]>> {
        let (mut k, mut v) = (val(key), empty());
        // SAFETY: a live transaction; the value is valid while `self` is borrowed.
        let hit = found(unsafe { ffi::mdb_get(self.ptr, db.0, &mut k, &mut v) })?;
        Ok(hit.then(|| unsafe { bytes(&v) }))
    }

    pub fn cursor(&self, db: Db) -> Result<Cursor<'_>> {
        let mut ptr = ptr::null_mut();
        // SAFETY: a live transaction; the cursor is closed on drop, before the txn ends.
        check(unsafe { ffi::mdb_cursor_open(self.ptr, db.0, &mut ptr) })?;
        Ok(Cursor { ptr, _txn: PhantomData })
    }

    /// Every value of `key` in a `DUPFIXED` table of `size`-byte values,
    /// packed, in order.
    pub fn get_dups(&self, db: Db, key: &[u8], size: usize) -> Result<Vec<u8>> {
        let mut cursor = self.cursor(db)?;
        let mut out = Vec::new();
        let Some((_, first)) = cursor.set(key)? else {
            return Ok(out);
        };
        let page = cursor.get_multiple()?;
        if page.is_empty() {
            // A key with one value keeps it outside any page.
            out.extend_from_slice(first);
            return Ok(out);
        }
        out.extend_from_slice(page);
        while let Some(page) = cursor.next_multiple()? {
            out.extend_from_slice(page);
        }
        debug_assert_eq!(out.len() % size, 0);
        Ok(out)
    }
}

impl Txn<'_> {
    /// Calls `f` with every entry of `db`, each value of a key in turn.
    pub fn for_each(&self, db: Db, mut f: impl FnMut(&[u8], &[u8]) -> anyhow::Result<()>) -> anyhow::Result<()> {
        let mut cursor = self.cursor(db)?;
        let mut entry = cursor.first()?;
        while let Some((key, value)) = entry {
            f(key, value)?;
            entry = cursor.next()?;
        }
        Ok(())
    }
}

impl Drop for Txn<'_> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: not yet committed or aborted.
            unsafe { ffi::mdb_txn_abort(self.ptr) }
        }
    }
}

pub struct RoTxn<'env>(Txn<'env>);

// SAFETY: the environment is opened with MDB_NOTLS, so a read-only
// transaction belongs to no thread and may move to another.
unsafe impl Send for RoTxn<'_> {}

impl<'env> std::ops::Deref for RoTxn<'env> {
    type Target = Txn<'env>;
    fn deref(&self) -> &Txn<'env> {
        &self.0
    }
}

pub struct RwTxn<'env>(Txn<'env>);

impl<'env> std::ops::Deref for RwTxn<'env> {
    type Target = Txn<'env>;
    fn deref(&self) -> &Txn<'env> {
        &self.0
    }
}

impl RwTxn<'_> {
    /// Stores `value` under `key`; in a duplicate-sorted table, alongside
    /// its other values, doing nothing if that pair's already there.
    pub fn put(&mut self, db: Db, key: &[u8], value: &[u8], dup: bool) -> Result<()> {
        let (mut k, mut v) = (val(key), val(value));
        let flags = if dup { ffi::MDB_NODUPDATA } else { 0 };
        // SAFETY: a live write transaction, and `&mut self` keeps no reads alive.
        match unsafe { ffi::mdb_put(self.0.ptr, db.0, &mut k, &mut v, flags) } {
            ffi::MDB_KEYEXIST => Ok(()),
            code => check(code),
        }
    }

    /// Removes `key`, or with `value`, just that one of its values.
    pub fn del(&mut self, db: Db, key: &[u8], value: Option<&[u8]>) -> Result<bool> {
        let mut k = val(key);
        let mut v = value.map(val);
        let v_ptr = v.as_mut().map_or(ptr::null_mut(), |v| v as *mut _);
        // SAFETY: a live write transaction; a null value means every value.
        found(unsafe { ffi::mdb_del(self.0.ptr, db.0, &mut k, v_ptr) })
    }

    pub fn commit(mut self) -> Result<()> {
        let ptr = std::mem::replace(&mut self.0.ptr, ptr::null_mut());
        // SAFETY: commit frees the transaction whatever it returns; the
        // pointer's nulled first so Drop doesn't abort it again.
        check(unsafe { ffi::mdb_txn_commit(ptr) })
    }
}

pub struct Cursor<'t> {
    ptr: *mut ffi::MDB_cursor,
    _txn: PhantomData<&'t Txn<'t>>,
}

pub type Entry<'t> = (&'t [u8], &'t [u8]);

impl<'t> Cursor<'t> {
    fn op(&mut self, key: Option<&[u8]>, op: ffi::MDB_cursor_op) -> Result<Option<Entry<'t>>> {
        let mut k = key.map_or_else(empty, val);
        let mut v = empty();
        // SAFETY: a live cursor; returned slices live as long as the transaction.
        let hit = found(unsafe { ffi::mdb_cursor_get(self.ptr, &mut k, &mut v, op) })?;
        Ok(hit.then(|| unsafe { (bytes(&k), bytes(&v)) }))
    }

    pub fn first(&mut self) -> Result<Option<Entry<'t>>> {
        self.op(None, ffi::MDB_FIRST)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Entry<'t>>> {
        self.op(None, ffi::MDB_NEXT)
    }

    pub fn set(&mut self, key: &[u8]) -> Result<Option<Entry<'t>>> {
        self.op(Some(key), ffi::MDB_SET_KEY)
    }

    /// The page of values the cursor is on, packed; empty when its key has
    /// only one value.
    pub fn get_multiple(&mut self) -> Result<&'t [u8]> {
        Ok(self.op(None, ffi::MDB_GET_MULTIPLE)?.map_or(&[][..], |(_, v)| v))
    }

    pub fn next_multiple(&mut self) -> Result<Option<&'t [u8]>> {
        Ok(self.op(None, ffi::MDB_NEXT_MULTIPLE)?.map(|(_, v)| v))
    }

    pub fn count(&mut self) -> Result<usize> {
        let mut count = 0;
        // SAFETY: a live, positioned cursor on a duplicate-sorted table.
        check(unsafe { ffi::mdb_cursor_count(self.ptr, &mut count) })?;
        Ok(count)
    }
}

impl Drop for Cursor<'_> {
    fn drop(&mut self) {
        // SAFETY: the cursor's transaction is still alive (it's borrowed).
        unsafe { ffi::mdb_cursor_close(self.ptr) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dup_fixed_round_trip() {
        let dir = std::env::temp_dir().join(format!("bitdexter-lmdb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let env = Env::open(&dir, 1 << 30, 4).unwrap();
        let db = env.create_db("t", true).unwrap();
        let mut txn = env.write_txn().unwrap();
        for i in 0u64..5000 {
            txn.put(db, b"many", &i.to_be_bytes()[3..], true).unwrap();
        }
        txn.put(db, b"one", &[0, 0, 0, 0, 7], true).unwrap();
        txn.put(db, b"one", &[0, 0, 0, 0, 7], true).unwrap();
        txn.commit().unwrap();
        let txn = env.read_txn().unwrap();
        let many = txn.get_dups(db, b"many", 5).unwrap();
        assert_eq!(many.len(), 5000 * 5);
        assert_eq!(&many[5 * 4999..], &4999u64.to_be_bytes()[3..]);
        assert_eq!(txn.get_dups(db, b"one", 5).unwrap(), vec![0, 0, 0, 0, 7]);
        assert!(txn.get_dups(db, b"none", 5).unwrap().is_empty());
        drop(txn);
        drop(env);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
