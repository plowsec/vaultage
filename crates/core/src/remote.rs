//! What a vault needs from a sync server. Implemented over HTTP in `http.rs`; faked in tests.

use crate::error::Result;
use crate::model::{ChunkId, EntryId};

#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub seq: u64,
    pub entry: EntryId,
    pub rev: u64,
    /// Empty = the server only has a placeholder (revision was purged).
    pub blob: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum CommitOutcome {
    Committed(u64),
    /// The entry moved on; value is its current rev.
    Conflict(u64),
    MissingRefs(Vec<ChunkId>),
}

pub trait Remote: Send + Sync {
    /// Records with seq > after (ascending, contiguous) and the log head.
    fn pull(&self, after: u64, limit: u32) -> Result<(u64, Vec<Record>)>;
    fn commit(&self, entry: &EntryId, base_rev: u64, rev: u64, blob: &[u8], refs: &[ChunkId]) -> Result<CommitOutcome>;
    fn missing(&self, ids: &[ChunkId]) -> Result<Vec<ChunkId>>;
    fn put_chunk(&self, id: &ChunkId, data: &[u8]) -> Result<()>;
    fn get_chunk(&self, id: &ChunkId) -> Result<Vec<u8>>;
    /// Purge revisions below `below` of each entry on the server, and the chunks only they used.
    fn prune(&self, items: &[(EntryId, u64)]) -> Result<()>;
}
