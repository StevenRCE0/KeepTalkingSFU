//! The token bucket behind every per-connection rate limit.

use std::time::Instant;

use super::config::Rate;

/// Byte and frame token buckets, refilled continuously.
pub(crate) struct Bucket {
    rate: Rate,
    bytes: f64,
    frames: f64,
    last: Instant,
}

impl Bucket {
    pub(crate) fn new(rate: Rate) -> Self {
        Self {
            rate,
            bytes: rate.burst_bytes,
            frames: rate.burst_frames,
            last: Instant::now(),
        }
    }

    /// Takes one frame of `len` bytes if both buckets allow it. A frame
    /// larger than the byte burst needs a full bucket and leaves it in debt.
    pub(crate) fn try_take(&mut self, len: usize) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        let rate = self.rate;
        self.bytes = refill(self.bytes, rate.bytes_per_second, rate.burst_bytes, elapsed);
        self.frames = refill(
            self.frames,
            rate.frames_per_second,
            rate.burst_frames,
            elapsed,
        );
        let len = len as f64;
        if self.frames < 1.0 || self.bytes < len.min(self.rate.burst_bytes) {
            return false;
        }
        self.frames -= 1.0;
        self.bytes -= len;
        true
    }
}

fn refill(level: f64, per_second: f64, burst: f64, elapsed: f64) -> f64 {
    if burst.is_infinite() {
        return f64::INFINITY;
    }
    (level + elapsed * per_second).min(burst)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn bucket_limits_frames_and_bytes() {
        let mut frames = Bucket::new(Rate::frames(1.0, 3.0));
        assert!((0..3).all(|_| frames.try_take(1_000_000)));
        assert!(!frames.try_take(0));

        let mut bytes = Bucket::new(Rate {
            bytes_per_second: 1.0,
            burst_bytes: 100.0,
            frames_per_second: 1000.0,
            burst_frames: 1000.0,
        });
        assert!(bytes.try_take(60));
        assert!(!bytes.try_take(60));
        assert!(bytes.try_take(40));
        assert!(!bytes.try_take(1));
    }

    #[test]
    fn bucket_admits_an_oversized_frame_from_a_full_bucket() {
        let mut bucket = Bucket::new(Rate {
            bytes_per_second: 1000.0,
            burst_bytes: 100.0,
            frames_per_second: 1000.0,
            burst_frames: 1000.0,
        });
        assert!(bucket.try_take(500));
        // Now in debt: nothing passes until it is repaid.
        assert!(!bucket.try_take(1));
    }

    #[test]
    fn bucket_refills_over_time() {
        let mut bucket = Bucket::new(Rate::frames(1000.0, 1.0));
        assert!(bucket.try_take(0));
        assert!(!bucket.try_take(0));
        std::thread::sleep(Duration::from_millis(5));
        assert!(bucket.try_take(0));
    }
}
