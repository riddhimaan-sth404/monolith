use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use monolith_protobuf::proto::v1;

const MAX_RETRY_QUEUE: usize = 5000;
const BASE_BACKOFF_MS: u64 = 100;
const MAX_BACKOFF_MS: u64 = 30_000;

#[derive(Clone)]
pub struct RetryItem {
    pub events: Vec<v1::Event>,
    pub first_attempt: Instant,
    pub retry_count: u32,
}

pub struct RetryQueue {
    inner: Arc<Mutex<VecDeque<RetryItem>>>,
}

impl RetryQueue {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_RETRY_QUEUE))),
        }
    }

    pub async fn push(&self, events: Vec<v1::Event>) {
        let mut queue = self.inner.lock().await;
        if queue.len() >= MAX_RETRY_QUEUE {
            tracing::warn!("retry queue full, dropping {} events", events.len());
            return;
        }
        queue.push_back(RetryItem {
            events,
            first_attempt: Instant::now(),
            retry_count: 0,
        });
    }

    pub async fn pop_ready(&self) -> Option<RetryItem> {
        let mut queue = self.inner.lock().await;
        if let Some(front) = queue.front() {
            let backoff = Self::backoff(front.retry_count);
            if front.first_attempt.elapsed() >= Duration::from_millis(backoff) {
                return queue.pop_front();
            }
        }
        None
    }

    pub async fn retry_later(&self, mut item: RetryItem) {
        item.retry_count += 1;
        item.first_attempt = Instant::now();
        let mut queue = self.inner.lock().await;
        if queue.len() >= MAX_RETRY_QUEUE {
            tracing::warn!(
                "retry queue full during re-enqueue, dropping {} events (retry {})",
                item.events.len(),
                item.retry_count,
            );
            return;
        }
        queue.push_back(item);
    }

    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }

    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    fn backoff(retry_count: u32) -> u64 {
        let ms = BASE_BACKOFF_MS * (1u64 << retry_count.min(8));
        ms.min(MAX_BACKOFF_MS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    fn dummy_event() -> v1::Event {
        v1::Event {
            id: Some(v1::Uuid { value: vec![0u8; 16] }),
            endpoint_id: None,
            event_type: 0,
            timestamp: None,
            collected_at: None,
            sequence_number: 0,
            payload: None,
            metadata: vec![],
        }
    }

    #[test]
    fn test_pop_empty_returns_none() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let queue = RetryQueue::new();
            assert!(queue.pop_ready().await.is_none());
        });
    }

    #[test]
    fn test_backoff_increases_exponentially() {
        assert_eq!(RetryQueue::backoff(0), 100);
        assert_eq!(RetryQueue::backoff(1), 200);
        assert_eq!(RetryQueue::backoff(2), 400);
        assert_eq!(RetryQueue::backoff(3), 800);
        assert_eq!(RetryQueue::backoff(4), 1600);
        assert_eq!(RetryQueue::backoff(5), 3200);
        assert_eq!(RetryQueue::backoff(6), 6400);
        assert_eq!(RetryQueue::backoff(7), 12800);
        assert_eq!(RetryQueue::backoff(8), 25600);
        assert_eq!(RetryQueue::backoff(9), 25600);
        assert_eq!(RetryQueue::backoff(10), 25600);
    }

    #[test]
    fn test_retry_later_increments_count() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let queue = RetryQueue::new();
            queue.push(vec![dummy_event()]).await;
            // Wait for initial backoff (100ms for retry_count=0)
            tokio::time::sleep(Duration::from_millis(110)).await;
            let item = queue.pop_ready().await.unwrap();
            assert_eq!(item.retry_count, 0);
            // Re-enqueue with incremented retry count
            queue.retry_later(RetryItem {
                events: item.events,
                first_attempt: Instant::now(),
                retry_count: 1,
            }).await;
            // Not ready yet — backoff for retry_count=2 (1+1 from retry_later) is 400ms
            assert!(queue.pop_ready().await.is_none());
            // Wait for 400ms backoff
            tokio::time::sleep(Duration::from_millis(410)).await;
            let popped = queue.pop_ready().await;
            assert!(popped.is_some());
            assert_eq!(popped.unwrap().retry_count, 2);
        });
    }

    #[test]
    fn test_push_respects_max_capacity() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let queue = RetryQueue::new();
            for _ in 0..MAX_RETRY_QUEUE {
                queue.push(vec![dummy_event()]).await;
            }
            assert_eq!(queue.len().await, MAX_RETRY_QUEUE);
            queue.push(vec![dummy_event()]).await;
            assert_eq!(queue.len().await, MAX_RETRY_QUEUE);
        });
    }

    #[test]
    fn test_pop_not_ready_due_to_backoff() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let queue = RetryQueue::new();
            queue.push(vec![dummy_event()]).await;
            // Wait for initial backoff (100ms)
            tokio::time::sleep(Duration::from_millis(110)).await;
            let item = queue.pop_ready().await.unwrap();
            // Re-enqueue with higher retry count — backoff becomes 200ms
            queue.retry_later(RetryItem {
                events: item.events,
                first_attempt: Instant::now(),
                retry_count: 1,
            }).await;
            // Not ready yet
            assert!(queue.pop_ready().await.is_none());
        });
    }

    #[test]
    fn test_is_empty_and_len() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let queue = RetryQueue::new();
            assert!(queue.is_empty().await);
            assert_eq!(queue.len().await, 0);
            queue.push(vec![dummy_event()]).await;
            assert!(!queue.is_empty().await);
            assert_eq!(queue.len().await, 1);
        });
    }

    #[test]
    fn test_multiple_events_in_item() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let queue = RetryQueue::new();
            queue.push(vec![dummy_event(), dummy_event(), dummy_event()]).await;
            tokio::time::sleep(Duration::from_millis(110)).await;
            let item = queue.pop_ready().await.unwrap();
            assert_eq!(item.events.len(), 3);
        });
    }

    #[test]
    fn test_push_and_pop_after_backoff() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let queue = RetryQueue::new();
            assert!(queue.is_empty().await);
            queue.push(vec![dummy_event()]).await;
            assert_eq!(queue.len().await, 1);
            // Not ready immediately due to 100ms backoff
            assert!(queue.pop_ready().await.is_none());
            assert_eq!(queue.len().await, 1);
            // Wait for backoff
            tokio::time::sleep(Duration::from_millis(110)).await;
            let item = queue.pop_ready().await;
            assert!(item.is_some());
            assert_eq!(item.unwrap().retry_count, 0);
            assert!(queue.is_empty().await);
        });
    }
}
