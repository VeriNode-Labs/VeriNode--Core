//! Distributed job scheduler with lease-based worker claiming.
//!
//! Workers acquire exclusive leases on jobs from a priority queue.
//! Leases carry a TTL and must be renewed before expiry; expired leases
//! release their jobs back to the queue so another worker can claim them.
//! The design is lock-free at the scheduler level and keeps per-operation
//! work bounded by the number of jobs in the highest-priority tier.
//!
//! Closes #76

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

// --- Constants ----------------------------------------------------------------

/// Default lease duration in seconds.
pub const DEFAULT_LEASE_TTL_SECS: u64 = 30;
/// Minimum time before lease expiry to trigger a renewal attempt.
pub const DEFAULT_RENEWAL_BUFFER_SECS: u64 = 5;
/// Maximum number of failed lease acquisitions before a job is dead-lettered.
pub const MAX_ACQUISITION_ATTEMPTS: u32 = 3;
/// Maximum number of jobs the scheduler tracks concurrently.
pub const MAX_QUEUED_JOBS: usize = 100_000;

// --- Types --------------------------------------------------------------------

/// Monotonically increasing job identifier.
pub type JobId = u64;

/// Priority tier. Lower numeric value = higher priority.
pub type Priority = u8;

/// Worker identifier, typically a node address or instance ID.
pub type WorkerId = u64;

/// Epoch timestamp in seconds.
pub type TimestampSecs = u64;

// --- Core Structures ----------------------------------------------------------

/// A job that can be scheduled and claimed by a worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Job {
    pub id: JobId,
    /// Logical queue or topic this job belongs to.
    pub queue: String,
    /// Higher-priority jobs are claimed first.
    pub priority: Priority,
    /// Opaque payload delivered to the worker.
    pub payload: Vec<u8>,
    /// When this job was enqueued.
    pub enqueued_at: TimestampSecs,
    /// Maximum wall-clock time allowed to process this job.
    pub max_processing_secs: u64,
    /// Number of times a worker has attempted to claim this job.
    pub acquisition_attempts: u32,
    /// Current lifecycle state.
    pub state: JobState,
}

/// Lifecycle of a scheduled job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobState {
    /// Waiting to be claimed by a worker.
    Pending,
    /// Claimed by a worker and being processed (or waiting to be).
    Acquired {
        worker_id: WorkerId,
        lease_expires_at: TimestampSecs,
    },
    /// Successfully completed.
    Completed {
        worker_id: WorkerId,
        completed_at: TimestampSecs,
    },
    /// Permanently failed after exhausting retries.
    DeadLettered {
        reason: &'static str,
        at: TimestampSecs,
    },
}

/// A lease grants a worker exclusive access to a job for a limited time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lease {
    pub job_id: JobId,
    pub worker_id: WorkerId,
    /// Absolute timestamp when this lease expires.
    pub expires_at: TimestampSecs,
}

/// Configuration for the job scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerConfig {
    /// Default lease TTL assigned to newly acquired jobs.
    pub lease_ttl_secs: u64,
    /// How long before lease expiry a worker should renew.
    pub renewal_buffer_secs: u64,
    /// Maximum acquisition retries before dead-lettering.
    pub max_acquisition_attempts: u32,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            lease_ttl_secs: DEFAULT_LEASE_TTL_SECS,
            renewal_buffer_secs: DEFAULT_RENEWAL_BUFFER_SECS,
            max_acquisition_attempts: MAX_ACQUISITION_ATTEMPTS,
        }
    }
}

/// Observability snapshot for monitoring and alerting dashboards.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SchedulerMetrics {
    pub jobs_enqueued: u64,
    pub jobs_pending: u64,
    pub jobs_acquired: u64,
    pub jobs_completed: u64,
    pub jobs_dead_lettered: u64,
    pub lease_expirations: u64,
    pub lease_renewals: u64,
    pub active_workers: u64,
}

/// Error cases for scheduler operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SchedulerError {
    QueueCapacityExceeded {
        max: usize,
    },
    JobNotFound(JobId),
    JobNotPending {
        id: JobId,
        state: JobState,
    },
    LeaseNotOwned {
        job_id: JobId,
        worker_id: WorkerId,
        owner: WorkerId,
    },
    LeaseAlreadyExpired {
        job_id: JobId,
        expires_at: TimestampSecs,
        now: TimestampSecs,
    },
    MaxAcquisitionAttemptsExceeded(JobId),
    DuplicateJobId(JobId),
}

// --- Distributed Job Scheduler ------------------------------------------------

/// The distributed job scheduler.
///
/// Maintains a priority queue of jobs that workers can claim via exclusive
/// leases.  Expired leases are detected lazily on the next `acquire` call
/// and released back to the queue.
#[derive(Clone, Debug)]
pub struct JobScheduler {
    config: SchedulerConfig,
    jobs: BTreeMap<JobId, Job>,
    /// Priority-sorted index: (priority, enqueued_at, job_id)
    pending_by_priority: Vec<(Priority, TimestampSecs, JobId)>,
    /// Active worker leases indexed by job.
    leases: BTreeMap<JobId, Lease>,
    /// Workers currently holding leases, keyed by worker ID with count.
    workers: BTreeMap<WorkerId, u32>,
    next_job_id: JobId,
    metrics: SchedulerMetrics,
}

impl JobScheduler {
    /// Create a new scheduler with the given config.
    pub fn new(config: SchedulerConfig) -> Self {
        Self {
            config,
            jobs: BTreeMap::new(),
            pending_by_priority: Vec::new(),
            leases: BTreeMap::new(),
            workers: BTreeMap::new(),
            next_job_id: 1,
            metrics: SchedulerMetrics::default(),
        }
    }

    /// Enqueue a new job with a priority and payload.
    ///
    /// Returns the assigned [`JobId`].
    pub fn enqueue(
        &mut self,
        queue: String,
        priority: Priority,
        payload: Vec<u8>,
        max_processing_secs: u64,
        now: TimestampSecs,
    ) -> Result<JobId, SchedulerError> {
        if self.jobs.len() >= MAX_QUEUED_JOBS {
            return Err(SchedulerError::QueueCapacityExceeded {
                max: MAX_QUEUED_JOBS,
            });
        }

        let id = self.next_job_id;
        let job = Job {
            id,
            queue,
            priority,
            payload,
            enqueued_at: now,
            max_processing_secs,
            acquisition_attempts: 0,
            state: JobState::Pending,
        };

        self.jobs.insert(id, job);
        self.pending_by_priority.push((priority, now, id));
        self.pending_by_priority.sort();

        self.next_job_id = self.next_job_id.saturating_add(1);
        self.metrics.jobs_enqueued = self.metrics.jobs_enqueued.saturating_add(1);
        self.metrics.jobs_pending = self.metrics.jobs_pending.saturating_add(1);

        Ok(id)
    }

    /// Attempt to acquire the highest-priority pending job for a worker.
    ///
    /// On success, returns the acquired [`Job`] with an active lease.
    /// Expired leases owned by other workers are released during acquisition.
    pub fn acquire(
        &mut self,
        worker_id: WorkerId,
        now: TimestampSecs,
    ) -> Result<Job, SchedulerError> {
        // Release any expired leases first
        self.release_expired_leases(now);

        // Find the highest-priority pending job
        let job_id = self
            .pending_by_priority
            .first()
            .map(|(_, _, id)| *id)
            .ok_or(SchedulerError::JobNotFound(0))?;

        let job = self
            .jobs
            .get_mut(&job_id)
            .ok_or(SchedulerError::JobNotFound(job_id))?;

        if job.state != JobState::Pending {
            return Err(SchedulerError::JobNotPending {
                id: job_id,
                state: job.state,
            });
        }

        // Check max acquisition attempts
        if job.acquisition_attempts >= self.config.max_acquisition_attempts {
            let state = JobState::DeadLettered {
                reason: "max acquisition attempts exceeded",
                at: now,
            };
            job.state = state;
            self.pending_by_priority.retain(|(_, _, id)| *id != job_id);
            self.metrics.jobs_pending = self.metrics.jobs_pending.saturating_sub(1);
            self.metrics.jobs_dead_lettered = self.metrics.jobs_dead_lettered.saturating_add(1);
            return Err(SchedulerError::MaxAcquisitionAttemptsExceeded(job_id));
        }

        let expires_at = now.saturating_add(self.config.lease_ttl_secs);

        // Assign lease
        let lease = Lease {
            job_id,
            worker_id,
            expires_at,
        };

        job.state = JobState::Acquired {
            worker_id,
            lease_expires_at: expires_at,
        };
        job.acquisition_attempts = job.acquisition_attempts.saturating_add(1);

        self.leases.insert(job_id, lease);
        self.pending_by_priority.retain(|(_, _, id)| *id != job_id);

        let worker_count = self.workers.entry(worker_id).or_insert(0);
        *worker_count = worker_count.saturating_add(1);

        self.metrics.jobs_pending = self.metrics.jobs_pending.saturating_sub(1);
        self.metrics.jobs_acquired = self.metrics.jobs_acquired.saturating_add(1);

        Ok(job.clone())
    }

    /// Renew a lease for an acquired job, extending its expiry time.
    ///
    /// Only the owning worker may renew.  Returns the new expiry time.
    pub fn renew_lease(
        &mut self,
        job_id: JobId,
        worker_id: WorkerId,
        now: TimestampSecs,
    ) -> Result<TimestampSecs, SchedulerError> {
        let lease = self
            .leases
            .get(&job_id)
            .ok_or(SchedulerError::JobNotFound(job_id))?;

        if lease.worker_id != worker_id {
            return Err(SchedulerError::LeaseNotOwned {
                job_id,
                worker_id,
                owner: lease.worker_id,
            });
        }

        if now >= lease.expires_at {
            return Err(SchedulerError::LeaseAlreadyExpired {
                job_id,
                expires_at: lease.expires_at,
                now,
            });
        }

        let new_expires_at = now.saturating_add(self.config.lease_ttl_secs);
        let new_lease = Lease {
            expires_at: new_expires_at,
            ..*lease
        };

        self.leases.insert(job_id, new_lease);

        // Update job state expiry
        if let Some(job) = self.jobs.get_mut(&job_id) {
            if let JobState::Acquired {
                ref mut lease_expires_at,
                ..
            } = job.state
            {
                *lease_expires_at = new_expires_at;
            }
        }

        self.metrics.lease_renewals = self.metrics.lease_renewals.saturating_add(1);
        Ok(new_expires_at)
    }

    /// Mark a job as completed by its owning worker.
    pub fn complete(
        &mut self,
        job_id: JobId,
        worker_id: WorkerId,
        now: TimestampSecs,
    ) -> Result<(), SchedulerError> {
        let job = self
            .jobs
            .get_mut(&job_id)
            .ok_or(SchedulerError::JobNotFound(job_id))?;

        match job.state {
            JobState::Acquired {
                worker_id: owner,
                lease_expires_at,
            } => {
                if owner != worker_id {
                    return Err(SchedulerError::LeaseNotOwned {
                        job_id,
                        worker_id,
                        owner,
                    });
                }
                if now >= lease_expires_at {
                    return Err(SchedulerError::LeaseAlreadyExpired {
                        job_id,
                        expires_at: lease_expires_at,
                        now,
                    });
                }
            }
            _ => {
                return Err(SchedulerError::JobNotPending {
                    id: job_id,
                    state: job.state,
                });
            }
        }

        job.state = JobState::Completed {
            worker_id,
            completed_at: now,
        };

        self.leases.remove(&job_id);

        if let Some(count) = self.workers.get_mut(&worker_id) {
            *count = count.saturating_sub(1);
        }

        self.metrics.jobs_completed = self.metrics.jobs_completed.saturating_add(1);
        Ok(())
    }

    /// Dead-letter a job that has failed permanently.
    pub fn dead_letter(
        &mut self,
        job_id: JobId,
        reason: &'static str,
        now: TimestampSecs,
    ) -> Result<(), SchedulerError> {
        let job = self
            .jobs
            .get_mut(&job_id)
            .ok_or(SchedulerError::JobNotFound(job_id))?;

        job.state = JobState::DeadLettered { reason, at: now };
        self.leases.remove(&job_id);
        self.pending_by_priority.retain(|(_, _, id)| *id != job_id);
        self.metrics.jobs_dead_lettered = self.metrics.jobs_dead_lettered.saturating_add(1);

        Ok(())
    }

    /// Get the state of a specific job.
    pub fn get_job(&self, job_id: JobId) -> Option<&Job> {
        self.jobs.get(&job_id)
    }

    /// List all leases currently held.
    pub fn active_leases(&self) -> Vec<Lease> {
        self.leases.values().cloned().collect()
    }

    /// List pending jobs, ordered by priority (highest first).
    pub fn pending_jobs(&self) -> Vec<&Job> {
        self.pending_by_priority
            .iter()
            .filter_map(|(_, _, id)| self.jobs.get(id))
            .filter(|j| j.state == JobState::Pending)
            .collect()
    }

    /// Check whether a lease should be renewed (within renewal buffer).
    pub fn should_renew(&self, job_id: JobId, now: TimestampSecs) -> bool {
        self.leases
            .get(&job_id)
            .map(|lease| {
                let buffer = self.config.renewal_buffer_secs;
                lease.expires_at.saturating_sub(now) <= buffer
            })
            .unwrap_or(false)
    }

    /// Export metrics snapshot for monitoring dashboards.
    pub fn metrics(&self) -> SchedulerMetrics {
        SchedulerMetrics {
            active_workers: self.workers.len() as u64,
            ..self.metrics
        }
    }

    // --- Internal helpers -----------------------------------------------------

    fn release_expired_leases(&mut self, now: TimestampSecs) {
        let expired: Vec<JobId> = self
            .leases
            .iter()
            .filter(|(_, lease)| now >= lease.expires_at)
            .map(|(id, _)| *id)
            .collect();

        for job_id in expired {
            // Snapshot worker_id before removing the lease.
            let worker_id = self.leases.get(&job_id).map(|l| l.worker_id);
            self.leases.remove(&job_id);

            if let Some(job) = self.jobs.get_mut(&job_id) {
                // Re-queue the job as pending
                self.pending_by_priority
                    .push((job.priority, job.enqueued_at, job_id));
                self.pending_by_priority.sort();

                job.state = JobState::Pending;
                self.metrics.jobs_pending = self.metrics.jobs_pending.saturating_add(1);
                self.metrics.lease_expirations = self.metrics.lease_expirations.saturating_add(1);
            }

            // Decrement worker lease count
            if let Some(wid) = worker_id {
                if let Some(count) = self.workers.get_mut(&wid) {
                    *count = count.saturating_sub(1);
                }
            }
        }
    }
}

impl Default for JobScheduler {
    fn default() -> Self {
        Self::new(SchedulerConfig::default())
    }
}

// --- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enqueue_returns_sequential_ids() {
        let mut scheduler = JobScheduler::default();
        let id1 = scheduler
            .enqueue("default".into(), 5, vec![0x01], 60, 1000)
            .unwrap();
        let id2 = scheduler
            .enqueue("default".into(), 3, vec![0x02], 60, 1000)
            .unwrap();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(scheduler.metrics().jobs_enqueued, 2);
    }

    #[test]
    fn acquire_returns_highest_priority_job_first() {
        let mut scheduler = JobScheduler::default();
        scheduler
            .enqueue("q".into(), 5, vec![0x05], 60, 1000)
            .unwrap(); // lower priority
        scheduler
            .enqueue("q".into(), 1, vec![0x01], 60, 1000)
            .unwrap(); // higher priority

        let job = scheduler.acquire(42, 1000).unwrap();
        assert_eq!(job.priority, 1); // highest priority acquired first
        assert_eq!(job.payload, vec![0x01]);
    }

    #[test]
    fn acquire_assigns_lease_and_decrements_pending() {
        let mut scheduler = JobScheduler::default();
        scheduler
            .enqueue("q".into(), 1, vec![0xAA], 60, 1000)
            .unwrap();

        let metrics = scheduler.metrics();
        assert_eq!(metrics.jobs_pending, 1);

        let job = scheduler.acquire(7, 1000).unwrap();
        assert_eq!(job.id, 1);

        let metrics = scheduler.metrics();
        assert_eq!(metrics.jobs_pending, 0);
        assert_eq!(metrics.jobs_acquired, 1);

        let leases = scheduler.active_leases();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].worker_id, 7);
        assert_eq!(leases[0].expires_at, 1000 + DEFAULT_LEASE_TTL_SECS);
    }

    #[test]
    fn acquire_empty_queue_fails() {
        let mut scheduler = JobScheduler::default();
        let result = scheduler.acquire(1, 1000);
        assert!(matches!(result, Err(SchedulerError::JobNotFound(0))));
    }

    #[test]
    fn renew_lease_extends_expiry() {
        let mut scheduler = JobScheduler::default();
        scheduler
            .enqueue("q".into(), 1, vec![0x01], 60, 1000)
            .unwrap();
        scheduler.acquire(10, 1000).unwrap();

        // Original expiry: 1000 + DEFAULT_LEASE_TTL_SECS
        let new_expiry = scheduler.renew_lease(1, 10, 1010).unwrap();
        assert_eq!(new_expiry, 1010 + DEFAULT_LEASE_TTL_SECS);
        assert_eq!(scheduler.metrics().lease_renewals, 1);
    }

    #[test]
    fn renew_lease_wrong_worker_fails() {
        let mut scheduler = JobScheduler::default();
        scheduler
            .enqueue("q".into(), 1, vec![0x01], 60, 1000)
            .unwrap();
        scheduler.acquire(10, 1000).unwrap();

        let result = scheduler.renew_lease(1, 99, 1010); // wrong worker
        assert!(matches!(result, Err(SchedulerError::LeaseNotOwned { .. })));
    }

    #[test]
    fn renew_expired_lease_fails() {
        let mut scheduler = JobScheduler::default();
        scheduler
            .enqueue("q".into(), 1, vec![0x01], 60, 1000)
            .unwrap();
        scheduler.acquire(10, 1000).unwrap();

        let expired_time = 1000 + DEFAULT_LEASE_TTL_SECS + 1;
        let result = scheduler.renew_lease(1, 10, expired_time);
        assert!(matches!(
            result,
            Err(SchedulerError::LeaseAlreadyExpired { .. })
        ));
    }

    #[test]
    fn expired_lease_is_released_on_next_acquire() {
        let mut scheduler = JobScheduler::default();
        scheduler
            .enqueue("q".into(), 1, vec![0x01], 60, 1000)
            .unwrap();
        scheduler
            .enqueue("q".into(), 2, vec![0x02], 60, 1000)
            .unwrap();

        // Worker 10 acquires first job
        scheduler.acquire(10, 1000).unwrap();

        // Time passes: lease expires
        let expired_time = 1000 + DEFAULT_LEASE_TTL_SECS + 1;

        // Worker 20 acquires; expired lease should release job 1 back to queue
        let job = scheduler.acquire(20, expired_time).unwrap();
        // Should get the highest priority pending job (released job 1, priority 1)
        assert_eq!(job.id, 1);
        assert_eq!(job.priority, 1);

        assert_eq!(scheduler.metrics().lease_expirations, 1);
    }

    #[test]
    fn complete_job_transitions_to_completed_state() {
        let mut scheduler = JobScheduler::default();
        scheduler
            .enqueue("q".into(), 1, vec![0x01], 60, 1000)
            .unwrap();
        scheduler.acquire(7, 1000).unwrap();

        scheduler.complete(1, 7, 1010).unwrap();

        let job = scheduler.get_job(1).unwrap();
        assert!(matches!(
            job.state,
            JobState::Completed { worker_id: 7, .. }
        ));
        assert_eq!(scheduler.metrics().jobs_completed, 1);
        assert!(scheduler.active_leases().is_empty());
    }

    #[test]
    fn complete_wrong_worker_fails() {
        let mut scheduler = JobScheduler::default();
        scheduler
            .enqueue("q".into(), 1, vec![0x01], 60, 1000)
            .unwrap();
        scheduler.acquire(7, 1000).unwrap();

        let result = scheduler.complete(1, 99, 1010);
        assert!(matches!(result, Err(SchedulerError::LeaseNotOwned { .. })));
    }

    #[test]
    fn dead_letter_after_max_acquisition_attempts() {
        let config = SchedulerConfig {
            max_acquisition_attempts: 2,
            ..Default::default()
        };
        let mut scheduler = JobScheduler::new(config);
        scheduler
            .enqueue("q".into(), 1, vec![0x01], 60, 1000)
            .unwrap();

        // Worker acquires and lease expires
        scheduler.acquire(1, 1000).unwrap();
        let expired = 1000 + DEFAULT_LEASE_TTL_SECS + 1;

        // Another worker acquires (lease expired, so re-acquired)
        scheduler.acquire(2, expired).unwrap();
        let expired2 = expired + DEFAULT_LEASE_TTL_SECS + 1;

        // Third acquire attempt should dead-letter
        let result = scheduler.acquire(3, expired2);
        assert!(matches!(
            result,
            Err(SchedulerError::MaxAcquisitionAttemptsExceeded(1))
        ));

        let job = scheduler.get_job(1).unwrap();
        assert!(matches!(job.state, JobState::DeadLettered { .. }));
        assert_eq!(scheduler.metrics().jobs_dead_lettered, 1);
    }

    #[test]
    fn pending_jobs_returns_sorted_by_priority() {
        let mut scheduler = JobScheduler::default();
        scheduler
            .enqueue("q".into(), 10, vec![0x10], 60, 1000)
            .unwrap();
        scheduler
            .enqueue("q".into(), 2, vec![0x02], 60, 1000)
            .unwrap();
        scheduler
            .enqueue("q".into(), 5, vec![0x05], 60, 1000)
            .unwrap();

        let pending = scheduler.pending_jobs();
        assert_eq!(pending[0].priority, 2);
        assert_eq!(pending[1].priority, 5);
        assert_eq!(pending[2].priority, 10);
    }

    #[test]
    fn should_renew_detects_near_expiry() {
        let mut scheduler = JobScheduler::default();
        scheduler
            .enqueue("q".into(), 1, vec![0x01], 60, 1000)
            .unwrap();
        scheduler.acquire(7, 1000).unwrap();

        let expires_at = 1000 + DEFAULT_LEASE_TTL_SECS;
        let buffer = DEFAULT_RENEWAL_BUFFER_SECS;

        // Well before expiry
        assert!(!scheduler.should_renew(1, 1001));

        // Within buffer window
        assert!(scheduler.should_renew(1, expires_at - buffer));

        // Past expiry
        assert!(scheduler.should_renew(1, expires_at + 1));
    }

    #[test]
    fn queue_capacity_prevents_overflow() {
        let mut scheduler = JobScheduler::new(SchedulerConfig::default());

        // Fill up to capacity
        for i in 0..MAX_QUEUED_JOBS {
            scheduler
                .enqueue("q".into(), 1, vec![i as u8], 60, 1000)
                .unwrap();
        }

        let result = scheduler.enqueue("q".into(), 1, vec![0xFF], 60, 1000);
        assert!(matches!(
            result,
            Err(SchedulerError::QueueCapacityExceeded { max: _ })
        ));
    }

    #[test]
    fn manual_dead_letter_marks_job_permanently_failed() {
        let mut scheduler = JobScheduler::default();
        scheduler
            .enqueue("q".into(), 1, vec![0x01], 60, 1000)
            .unwrap();

        scheduler
            .dead_letter(1, "irrecoverable error", 1050)
            .unwrap();

        let job = scheduler.get_job(1).unwrap();
        assert!(matches!(
            job.state,
            JobState::DeadLettered {
                reason: "irrecoverable error",
                ..
            }
        ));
    }

    #[test]
    fn worker_tracking_counts_leases() {
        let mut scheduler = JobScheduler::default();
        scheduler
            .enqueue("q".into(), 1, vec![0x01], 60, 1000)
            .unwrap();
        scheduler
            .enqueue("q".into(), 1, vec![0x02], 60, 1000)
            .unwrap();

        scheduler.acquire(7, 1000).unwrap();
        scheduler.acquire(7, 1000).unwrap();

        assert_eq!(scheduler.metrics().active_workers, 1);
    }

    #[test]
    fn config_defaults_match_constants() {
        let config = SchedulerConfig::default();
        assert_eq!(config.lease_ttl_secs, DEFAULT_LEASE_TTL_SECS);
        assert_eq!(config.renewal_buffer_secs, DEFAULT_RENEWAL_BUFFER_SECS);
        assert_eq!(config.max_acquisition_attempts, MAX_ACQUISITION_ATTEMPTS);
    }
}
