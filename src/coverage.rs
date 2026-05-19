/// Stable identifier for one coverage feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoverageId(pub(crate) u64);

impl CoverageId {
    /// Construct a coverage ID from a raw feature key.
    pub fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Raw feature key behind this coverage ID.
    pub fn raw(self) -> u64 {
        self.0
    }
}

/// Coverage observed during one execution.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoverageSet {
    ids: Vec<CoverageId>,
}

impl CoverageSet {
    /// Create an empty coverage set.
    pub fn new() -> Self {
        Self { ids: Vec::new() }
    }

    /// Insert one ID. Returns `true` if it was not already present.
    pub fn insert(&mut self, id: CoverageId) -> bool {
        match self.ids.binary_search(&id) {
            Ok(_) => false,
            Err(index) => {
                self.ids.insert(index, id);
                true
            }
        }
    }

    /// Extend this set from an iterator of IDs.
    pub fn extend(&mut self, ids: impl IntoIterator<Item = CoverageId>) {
        let mut incoming: Vec<CoverageId> = ids.into_iter().collect();
        if incoming.is_empty() {
            return;
        }
        incoming.sort_unstable();
        incoming.dedup();

        if self.ids.is_empty() {
            self.ids = incoming;
            return;
        }

        let mut out = Vec::with_capacity(self.ids.len() + incoming.len());
        let (mut i, mut j) = (0, 0);
        let existing = &self.ids;
        while i < existing.len() && j < incoming.len() {
            match existing[i].cmp(&incoming[j]) {
                std::cmp::Ordering::Less => {
                    out.push(existing[i]);
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    out.push(incoming[j]);
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    out.push(existing[i]);
                    i += 1;
                    j += 1;
                }
            }
        }
        out.extend_from_slice(&existing[i..]);
        out.extend_from_slice(&incoming[j..]);
        self.ids = out;
    }

    /// Number of unique IDs in this set.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Returns `true` if this set has no coverage IDs.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Iterate over coverage IDs.
    pub fn iter(&self) -> impl Iterator<Item = CoverageId> + '_ {
        self.ids.iter().copied()
    }

    pub(crate) fn difference(&self, other: &Self) -> Self {
        let mut ids = Vec::new();
        let mut left = 0;
        let mut right = 0;
        while left < self.ids.len() {
            while right < other.ids.len() && other.ids[right] < self.ids[left] {
                right += 1;
            }
            if right == other.ids.len() || self.ids[left] < other.ids[right] {
                ids.push(self.ids[left]);
            }
            left += 1;
        }
        Self { ids }
    }

    pub(crate) fn from_unsorted(mut ids: Vec<CoverageId>) -> Self {
        ids.sort_unstable();
        ids.dedup();
        Self { ids }
    }
}

impl FromIterator<CoverageId> for CoverageSet {
    fn from_iter<T: IntoIterator<Item = CoverageId>>(iter: T) -> Self {
        let mut ids: Vec<_> = iter.into_iter().collect();
        ids.sort_unstable();
        ids.dedup();
        Self { ids }
    }
}

/// Feedback observed during one execution.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecutionFeedback {
    /// Coverage features observed during the execution.
    pub(crate) features: CoverageSet,

    /// Coarse execution intensity derived from hit-count buckets when available.
    pub(crate) hit_count_weight: u64,

    /// Values learned from comparison feedback during this execution.
    pub(crate) dictionary: Vec<Vec<u8>>,
}

impl ExecutionFeedback {
    /// Build feedback from all observed parts.
    pub fn new(features: CoverageSet, hit_count_weight: u64, dictionary: Vec<Vec<u8>>) -> Self {
        Self {
            features,
            hit_count_weight,
            dictionary,
        }
    }

    /// Build feedback from coverage features. The default hit-count weight is one unit per feature.
    pub fn from_features(features: CoverageSet) -> Self {
        let hit_count_weight = features.len() as u64;
        Self::new(features, hit_count_weight, Vec::new())
    }

    /// Override the coarse execution intensity.
    pub fn with_hit_count_weight(mut self, hit_count_weight: u64) -> Self {
        self.hit_count_weight = hit_count_weight;
        self
    }

    /// Attach comparison dictionary values to this feedback.
    pub fn with_dictionary(mut self, dictionary: Vec<Vec<u8>>) -> Self {
        self.dictionary = dictionary;
        self
    }

    /// Coverage features observed during the execution.
    pub fn features(&self) -> &CoverageSet {
        &self.features
    }

    /// Coarse execution intensity derived from hit-count buckets when available.
    pub fn hit_count_weight(&self) -> u64 {
        self.hit_count_weight
    }

    /// Values learned from comparison feedback during this execution.
    pub fn dictionary(&self) -> &[Vec<u8>] {
        &self.dictionary
    }

    /// Split feedback into owned parts.
    pub fn into_parts(self) -> (CoverageSet, u64, Vec<Vec<u8>>) {
        (self.features, self.hit_count_weight, self.dictionary)
    }
}

impl From<CoverageSet> for ExecutionFeedback {
    fn from(features: CoverageSet) -> Self {
        Self::from_features(features)
    }
}

/// Result of attempting to start one coverage capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureStart<Session> {
    /// Capture started and must be finished or discarded with this session.
    Started(Session),

    /// The backend is temporarily busy and the caller may retry later.
    Busy,
}

/// Starts and finishes coverage capture for one RNG case.
pub trait CoverageCapture {
    /// Opaque per-execution session.
    type Session;

    /// Start capturing coverage.
    ///
    /// [`CaptureStart::Busy`] represents retryable contention. `Err` represents a backend failure
    /// that should be surfaced to the caller.
    fn start_capture(&mut self) -> Result<CaptureStart<Self::Session>, String>;

    /// Finish coverage capture and return the observed feedback.
    fn finish_capture(&mut self, session: Self::Session) -> Result<ExecutionFeedback, String>;

    /// Discard a capture without reading/exporting its coverage.
    fn discard_capture(&mut self, _session: Self::Session) -> Result<(), String> {
        Ok(())
    }
}

/// Coverage backend that can correctly attribute multiple concurrent in-process executions.
pub trait ParallelCoverageCapture: CoverageCapture + Clone + Send + Sync + 'static {
    /// Validate that the current process is configured for concurrent attribution.
    fn validate_parallel(&self) -> Result<(), String> {
        Ok(())
    }
}
