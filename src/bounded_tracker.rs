use parking_lot::RwLock;
use prometheus::IntCounterVec;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

// Clock trait for dependency injection
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

// Real clock implementation
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Clone)]
pub struct TrackedEntry {
    pub value: u64,
    pub last_updated: Instant,
}

pub struct BoundedMetricTracker {
    entries: RwLock<HashMap<String, TrackedEntry>>,
    max_entries: usize,
    ttl: Duration,
    evicted_count: RwLock<u64>,
    clock: Arc<dyn Clock>,
}

impl BoundedMetricTracker {
    pub fn new(max_entries: usize, ttl: Duration, clock: Arc<dyn Clock>) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_entries,
            ttl,
            evicted_count: RwLock::new(0),
            clock,
        }
    }

    pub fn increment(&self, key: &str, metric: &IntCounterVec, labels: &[&str], amount: u64) {
        let now = self.clock.now();
        let mut entries = self.entries.write();

        if let Some(entry) = entries.get_mut(key) {
            entry.value += amount;
            entry.last_updated = now;
            metric.with_label_values(labels).inc_by(amount);
        } else {
            if entries.len() >= self.max_entries {
                self.evict_one(&mut entries);
            }

            entries.insert(
                key.to_string(),
                TrackedEntry {
                    value: amount,
                    last_updated: now,
                },
            );
            metric.with_label_values(labels).inc_by(amount);
        }
    }

    fn evict_one(&self, entries: &mut HashMap<String, TrackedEntry>) {
        if let Some(lru_key) = entries
            .iter()
            .min_by_key(|(_, entry)| (entry.value, entry.last_updated))
            .map(|(k, _)| k.clone())
        {
            entries.remove(&lru_key);
            let mut evicted = self.evicted_count.write();
            *evicted += 1;
        }
    }

    pub fn cleanup_expired(&self) -> usize {
        let now = self.clock.now();
        let mut entries = self.entries.write();
        let before_count = entries.len();

        entries.retain(|_, entry| now.duration_since(entry.last_updated) < self.ttl);

        let removed = before_count - entries.len();
        if removed > 0 {
            let mut evicted = self.evicted_count.write();
            *evicted += removed as u64;
        }
        removed
    }

    pub fn current_cardinality(&self) -> usize {
        self.entries.read().len()
    }

    pub fn total_evicted(&self) -> u64 {
        *self.evicted_count.read()
    }

    #[cfg(test)]
    pub fn get_entry(&self, key: &str) -> Option<TrackedEntry> {
        self.entries.read().get(key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{Opts, Registry};

    // Mock clock for testing
    struct MockClock {
        current_time: RwLock<Instant>,
    }

    impl MockClock {
        fn new() -> Self {
            Self {
                current_time: RwLock::new(Instant::now()),
            }
        }

        fn advance(&self, duration: Duration) {
            let mut time = self.current_time.write();
            *time += duration;
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> Instant {
            *self.current_time.read()
        }
    }

    fn create_test_counter() -> IntCounterVec {
        IntCounterVec::new(Opts::new("test_counter", "Test counter"), &["key"]).unwrap()
    }

    #[test]
    fn test_basic_increment() {
        let tracker =
            BoundedMetricTracker::new(100, Duration::from_secs(60), Arc::new(SystemClock));
        let counter = create_test_counter();

        tracker.increment("key1", &counter, &["key1"], 10);
        tracker.increment("key1", &counter, &["key1"], 5);

        assert_eq!(tracker.current_cardinality(), 1);
        let entry = tracker.get_entry("key1").unwrap();
        assert_eq!(entry.value, 15);
    }

    #[test]
    fn test_multiple_keys() {
        let tracker =
            BoundedMetricTracker::new(100, Duration::from_secs(60), Arc::new(SystemClock));
        let counter = create_test_counter();

        tracker.increment("key1", &counter, &["key1"], 10);
        tracker.increment("key2", &counter, &["key2"], 20);
        tracker.increment("key3", &counter, &["key3"], 30);

        assert_eq!(tracker.current_cardinality(), 3);
        assert_eq!(tracker.get_entry("key1").unwrap().value, 10);
        assert_eq!(tracker.get_entry("key2").unwrap().value, 20);
        assert_eq!(tracker.get_entry("key3").unwrap().value, 30);
    }

    #[test]
    fn test_cardinality_limit_evicts_lowest_value() {
        let tracker = BoundedMetricTracker::new(3, Duration::from_secs(60), Arc::new(SystemClock));
        let counter = create_test_counter();

        tracker.increment("key1", &counter, &["key1"], 100);
        tracker.increment("key2", &counter, &["key2"], 50);
        tracker.increment("key3", &counter, &["key3"], 200);

        assert_eq!(tracker.current_cardinality(), 3);

        tracker.increment("key4", &counter, &["key4"], 75);

        assert_eq!(tracker.current_cardinality(), 3);
        assert!(tracker.get_entry("key1").is_some());
        assert!(tracker.get_entry("key2").is_none());
        assert!(tracker.get_entry("key3").is_some());
        assert!(tracker.get_entry("key4").is_some());
        assert_eq!(tracker.total_evicted(), 1);
    }

    #[test]
    fn test_updating_existing_entry_updates_timestamp() {
        let clock = Arc::new(MockClock::new());
        let tracker = BoundedMetricTracker::new(100, Duration::from_secs(60), clock.clone());
        let counter = create_test_counter();

        tracker.increment("key1", &counter, &["key1"], 10);
        let first_timestamp = tracker.get_entry("key1").unwrap().last_updated;

        // Advance time
        clock.advance(Duration::from_millis(10));

        tracker.increment("key1", &counter, &["key1"], 5);
        let second_timestamp = tracker.get_entry("key1").unwrap().last_updated;

        assert!(second_timestamp > first_timestamp);
        assert_eq!(tracker.get_entry("key1").unwrap().value, 15);
    }

    #[test]
    fn test_time_based_expiration() {
        let clock = Arc::new(MockClock::new());
        let tracker = BoundedMetricTracker::new(100, Duration::from_secs(50), clock.clone());
        let counter = create_test_counter();

        tracker.increment("key1", &counter, &["key1"], 10);
        tracker.increment("key2", &counter, &["key2"], 20);

        assert_eq!(tracker.current_cardinality(), 2);

        // Advance time past TTL
        clock.advance(Duration::from_secs(60));

        let removed = tracker.cleanup_expired();

        assert_eq!(removed, 2);
        assert_eq!(tracker.current_cardinality(), 0);
        assert_eq!(tracker.total_evicted(), 2);
    }

    #[test]
    fn test_partial_expiration() {
        let clock = Arc::new(MockClock::new());
        let tracker = BoundedMetricTracker::new(100, Duration::from_secs(100), clock.clone());
        let counter = create_test_counter();

        tracker.increment("key1", &counter, &["key1"], 10);

        // Advance time
        clock.advance(Duration::from_secs(60));

        tracker.increment("key2", &counter, &["key2"], 20);

        // Advance time enough to expire key1 but not key2
        clock.advance(Duration::from_secs(50));

        let removed = tracker.cleanup_expired();

        assert_eq!(removed, 1);
        assert_eq!(tracker.current_cardinality(), 1);
        assert!(tracker.get_entry("key1").is_none());
        assert!(tracker.get_entry("key2").is_some());
    }

    #[test]
    fn test_cleanup_with_no_expired_entries() {
        let tracker =
            BoundedMetricTracker::new(100, Duration::from_secs(60), Arc::new(SystemClock));
        let counter = create_test_counter();

        tracker.increment("key1", &counter, &["key1"], 10);
        tracker.increment("key2", &counter, &["key2"], 20);

        let removed = tracker.cleanup_expired();

        assert_eq!(removed, 0);
        assert_eq!(tracker.current_cardinality(), 2);
        assert_eq!(tracker.total_evicted(), 0);
    }

    #[test]
    fn test_eviction_counter_accumulates() {
        let tracker = BoundedMetricTracker::new(2, Duration::from_secs(60), Arc::new(SystemClock));
        let counter = create_test_counter();

        tracker.increment("key1", &counter, &["key1"], 100);
        tracker.increment("key2", &counter, &["key2"], 200);
        tracker.increment("key3", &counter, &["key3"], 300);
        tracker.increment("key4", &counter, &["key4"], 400);

        assert_eq!(tracker.total_evicted(), 2);
        assert_eq!(tracker.current_cardinality(), 2);
    }

    #[test]
    fn test_prometheus_counter_increments_correctly() {
        let tracker =
            BoundedMetricTracker::new(100, Duration::from_secs(60), Arc::new(SystemClock));
        let registry = Registry::new();
        let counter =
            IntCounterVec::new(Opts::new("test_metric", "Test metric"), &["key"]).unwrap();
        registry.register(Box::new(counter.clone())).unwrap();

        tracker.increment("key1", &counter, &["key1"], 10);
        tracker.increment("key1", &counter, &["key1"], 5);
        tracker.increment("key2", &counter, &["key2"], 20);

        assert_eq!(counter.with_label_values(&["key1"]).get(), 15);
        assert_eq!(counter.with_label_values(&["key2"]).get(), 20);
    }
}
