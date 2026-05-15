use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

const SHARD_SEED_STRIDE: u64 = 0x9E37_79B9_7F4A_7C15;

/// Independent work shard for Rayon-backed fuzzing loops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RayonShard {
    index: usize,
    seed: u64,
    cases: usize,
}

impl RayonShard {
    /// Zero-based shard index.
    pub fn index(self) -> usize {
        self.index
    }

    /// Seed to pass to [`crate::curious`] for this shard.
    pub fn seed(self) -> u64 {
        self.seed
    }

    /// Number of discovery cases assigned to this shard.
    pub fn cases(self) -> usize {
        self.cases
    }
}

/// Build a Rayon iterator of independent deterministic fuzzing shards.
pub fn rayon_shards(
    shards: usize,
    cases_per_shard: usize,
) -> impl IndexedParallelIterator<Item = RayonShard> {
    rayon_shards_from(0, shards, cases_per_shard)
}

/// Build a Rayon iterator of independent deterministic fuzzing shards from a base seed.
pub fn rayon_shards_from(
    base_seed: u64,
    shards: usize,
    cases_per_shard: usize,
) -> impl IndexedParallelIterator<Item = RayonShard> {
    (0..shards.max(1))
        .into_par_iter()
        .map(move |index| RayonShard {
            index,
            seed: base_seed.wrapping_add((index as u64).wrapping_mul(SHARD_SEED_STRIDE)),
            cases: cases_per_shard,
        })
}
