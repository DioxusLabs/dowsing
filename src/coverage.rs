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
        self.ids.extend(ids);
        self.ids.sort_unstable();
        self.ids.dedup();
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

/// Starts and finishes coverage capture for one demonic RNG item.
pub trait CoverageCapture {
    /// Opaque per-execution token.
    type Token;

    /// Start capturing coverage.
    fn start_capture(&mut self) -> Result<Self::Token, String>;

    /// Finish coverage capture and return the observed coverage.
    fn finish_capture(&mut self, token: Self::Token) -> Result<CoverageSet, String>;

    /// Discard a capture without reading/exporting its coverage.
    fn discard_capture(&mut self, _token: Self::Token) -> Result<(), String> {
        Ok(())
    }
}
