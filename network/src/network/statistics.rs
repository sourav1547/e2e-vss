use core::default::Default;
use core::option::Option;
use core::option::Option::None;
use std::time::Instant;

use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub(super) struct ManagerStats {
    start: Instant,
    sent_bytes: usize,
    sent_count: usize,
    peer_count: usize,
    handle_stats: Vec<HandleStats>
}

impl ManagerStats {
    #[inline]
    pub fn new(peer_count: usize) -> Self {
        Self { peer_count, sent_count: 0, sent_bytes: 0, handle_stats: Vec::new(), start: Instant::now() }
    }

    #[inline]
    pub fn add_handle_stats(&mut self, handle_stats: HandleStats) {
        self.handle_stats.push(handle_stats);
    }

    #[inline]
    pub fn send(&mut self, len_bytes: usize) {
        self.sent_bytes += len_bytes;
        self.sent_count += 1;
    }

    #[inline]
    pub fn broadcast(&mut self, len_bytes: usize) {
        self.sent_bytes += len_bytes * self.peer_count;
        self.sent_count += self.peer_count;
    }

    #[inline]
    pub fn finalize(self) -> FinalizedManagerStats {
        FinalizedManagerStats::new(self)
    }
}

#[derive(Debug)]
pub(super) struct HandleStats {
    label: Option<String>,
    start: Option<Instant>,
    end: Option<Instant>,
    events: Vec<(String, Instant)>,
}

impl Default for HandleStats {
    #[inline]
    fn default() -> Self {
        Self { label: None, start: None, end: None, events: Vec::new() }
    }
}

impl HandleStats {
    pub fn set_label<L: Into<String>>(&mut self, label: L) {
        if self.label.is_none() {
            self.label = Some(label.into());
        }
    }

    #[inline]
    pub fn start(&mut self) {
        if self.start.is_none() {
            self.start = Some(Instant::now());
        }
    }

    #[inline]
    pub fn end(&mut self) {
        if self.start.is_some() {
            self.end = Some(Instant::now());
        }
    }
    
    pub fn event<L: Into<String>>(&mut self, label: L) {
        if self.start.is_some() {
            self.events.push((label.into(), Instant::now()))
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FinalizedManagerStats {
    sent_bytes: usize,
    sent_count: usize,
    handle_stats: Vec<FinalizedHandleStats>
}

impl FinalizedManagerStats {
    fn new(manager_stats: ManagerStats) -> Self {
        Self {
            sent_bytes: manager_stats.sent_bytes,
            sent_count: manager_stats.sent_count,
            handle_stats: manager_stats.handle_stats.into_iter().map(|s| FinalizedHandleStats::new(s, manager_stats.start)).collect(),
        }
    }

    #[inline]
    pub fn sent_bytes(&self) -> usize {
        self.sent_bytes
    }

    #[inline]
    pub fn sent_count(&self) -> usize {
        self.sent_count
    }

    #[inline]
    pub fn handle_stats(&self) -> &Vec<FinalizedHandleStats> {
        &self.handle_stats
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FinalizedHandleStats {
    label: Option<String>,
    start: Option<u128>,
    end: Option<u128>,
    events: Vec<(String, u128)>,
}

impl FinalizedHandleStats {
    fn new(handle_stats: HandleStats, earlier: Instant) -> Self {
        let start = handle_stats.start.and_then(|i| Some(i.duration_since(earlier).as_millis()));
        let end = handle_stats.end.and_then(|i| Some(i.duration_since(earlier).as_millis()));
        let events = handle_stats.events.into_iter().map(|(l, i)| (l, i.duration_since(earlier).as_millis())).collect();

        Self { label: handle_stats.label, start, end, events }
    }

    #[inline]
    pub fn get_label(&self) -> &Option<String> {
        &self.label
    }

    #[inline]
    pub fn get_start(&self) -> Option<u128> {
        self.start
    }

    #[inline]
    pub fn get_end(&self) -> Option<u128> {
        self.end
    }

    #[inline]
    pub fn get_events(&self) -> &Vec<(String, u128)> {
        &self.events
    }

    #[inline]
    pub fn duration(&self) -> Option<u128> {
        self.end.and_then(|e| Some(e - self.start.unwrap()))
    }
}

