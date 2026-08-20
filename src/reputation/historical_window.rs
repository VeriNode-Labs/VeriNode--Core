
pub const WINDOW_SIZE: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircularWindow {
    buffer: Vec<u64>,
    write_ptr: usize,
    entries_written: u64,
}

impl CircularWindow {
    pub fn new() -> Self {
        CircularWindow {
            buffer: vec![0; WINDOW_SIZE],
            write_ptr: 0,
            entries_written: 0,
        }
    }

    pub fn push_score(&mut self, score: u64) {
        self.buffer[self.write_ptr] = score;
        self.write_ptr = (self.write_ptr + 1) % WINDOW_SIZE;
        self.entries_written += 1;
    }

    pub fn effective_entries(&self) -> Vec<u64> {
        let effective_len = std::cmp::min(self.entries_written, WINDOW_SIZE as u64) as usize;
        if effective_len == 0 {
            return vec![];
        }

        if self.entries_written <= WINDOW_SIZE as u64 {
            self.buffer[0..effective_len].to_vec()
        } else {
            let mut entries = Vec::with_capacity(WINDOW_SIZE);
            entries.extend_from_slice(&self.buffer[self.write_ptr..]);
            entries.extend_from_slice(&self.buffer[..self.write_ptr]);
            entries
        }
    }

    pub fn entry_count(&self) -> usize {
        std::cmp::min(self.entries_written, WINDOW_SIZE as u64) as usize
    }
}

impl Default for CircularWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reputation::score_engine::compute_weighted_average;

    #[test]
    fn test_new_window_is_empty() {
        let window = CircularWindow::new();
        assert_eq!(window.entry_count(), 0);
        assert!(window.effective_entries().is_empty());
    }

    #[test]
    fn test_push_few_entries() {
        let mut window = CircularWindow::new();
        for i in 1..=100 {
            window.push_score(i);
        }
        assert_eq!(window.entry_count(), 100);
        let entries = window.effective_entries();
        assert_eq!(entries.len(), 100);
        for (idx, &entry) in entries.iter().enumerate() {
            assert_eq!(entry, (idx + 1) as u64);
        }
    }

    #[test]
    fn test_push_full_window() {
        let mut window = CircularWindow::new();
        for i in 1..=WINDOW_SIZE {
            window.push_score(i as u64);
        }
        assert_eq!(window.entry_count(), WINDOW_SIZE);
        let entries = window.effective_entries();
        assert_eq!(entries.len(), WINDOW_SIZE);
        for (idx, &entry) in entries.iter().enumerate() {
            assert_eq!(entry, (idx + 1) as u64);
        }
    }

    #[test]
    fn test_push_over_window() {
        let mut window = CircularWindow::new();
        for i in 1..=WINDOW_SIZE + 100 {
            window.push_score(i as u64);
        }
        assert_eq!(window.entry_count(), WINDOW_SIZE);
        let entries = window.effective_entries();
        assert_eq!(entries.len(), WINDOW_SIZE);
        for (idx, &entry) in entries.iter().enumerate() {
            assert_eq!(entry, (idx + 101) as u64);
        }
    }

    #[test]
    fn test_compute_weighted_average_empty() {
        let window = CircularWindow::new();
        assert_eq!(compute_weighted_average(&window), 0);
    }

    #[test]
    fn test_compute_weighted_average_few_entries() {
        let mut window = CircularWindow::new();
        for i in 1..=100 {
            window.push_score(i);
        }
        // Sum 1..100 is 5050, average is 5050 / 100 = 50
        assert_eq!(compute_weighted_average(&window), 50);
    }
}
