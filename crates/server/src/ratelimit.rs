//! Fixed-window counters with bounded memory.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Max tracked keys; beyond that, new keys share one overflow counter.
const MAX_KEYS: usize = 65_536;

pub struct Limiter<K> {
    limit: u32,
    window: Duration,
    inner: Mutex<Inner<K>>,
}

struct Inner<K> {
    map: HashMap<K, (Instant, u32)>,
    overflow: (Instant, u32),
}

impl<K: Hash + Eq + Clone> Limiter<K> {
    /// `limit` 0 = unlimited.
    pub fn new(limit: u32, window: Duration) -> Self {
        Limiter {
            limit,
            window: window.max(Duration::from_millis(1)),
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                overflow: (Instant::now(), 0),
            }),
        }
    }

    fn retry_after(&self, start: Instant, now: Instant) -> u64 {
        let left = (start + self.window).saturating_duration_since(now);
        (left.as_secs() + u64::from(left.subsec_nanos() > 0)).max(1)
    }

    /// Count one event. `Err(retry_after_secs)` once the window's budget is used up.
    pub fn hit(&self, key: &K) -> Result<(), u64> {
        self.check(key, true)
    }

    /// Over the limit right now? (does not count)
    pub fn blocked(&self, key: &K) -> bool {
        self.check(key, false).is_err()
    }

    fn check(&self, key: &K, count: bool) -> Result<(), u64> {
        if self.limit == 0 {
            return Ok(());
        }
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let window = self.window;
        if !g.map.contains_key(key) && g.map.len() >= MAX_KEYS {
            g.map.retain(|_, (s, _)| now.duration_since(*s) < window);
        }
        let inner = &mut *g;
        let slot = if inner.map.contains_key(key) || inner.map.len() < MAX_KEYS {
            if !count && !inner.map.contains_key(key) {
                return Ok(());
            }
            inner.map.entry(key.clone()).or_insert((now, 0))
        } else {
            &mut inner.overflow
        };
        if now.duration_since(slot.0) >= window {
            *slot = (now, 0);
        }
        if slot.1 >= self.limit {
            return Err(self.retry_after(slot.0, now));
        }
        if count {
            slot.1 += 1;
        }
        Ok(())
    }
}
