use super::{
    prelude::{INTERESTING_BYTES, MAX_PREFIX_LEN, Mode, State},
    run::min_path_schedule_energy,
};
use crate::coverage::{CoverageCapture, CoverageId};
use rand::{Rng, SeedableRng, rngs::SmallRng};

pub(super) fn havoc_prefix(
    prefix: &[u8],
    rng: &mut SmallRng,
    depth: usize,
    dictionary: &[Vec<u8>],
) -> Vec<u8> {
    let mut candidate = prefix.to_vec();
    for _ in 0..depth.max(1) {
        mutate_minimizing_havoc(&mut candidate, rng, dictionary);
        if candidate.len() > MAX_PREFIX_LEN {
            candidate.truncate(MAX_PREFIX_LEN);
        }
    }
    if candidate == prefix {
        mutate_minimizing_havoc(&mut candidate, rng, dictionary);
    }
    candidate
}

fn mutate_minimizing_havoc(prefix: &mut Vec<u8>, rng: &mut SmallRng, dictionary: &[Vec<u8>]) {
    match rng.random_range(0..40) {
        0..=4 if prefix.len() > 1 => {
            let removed = drain_minimizing_chunk(prefix, rng, true);
            shrink_leading_byte(prefix, removed, rng);
        }
        5..=7 if prefix.len() > 1 => {
            drain_minimizing_chunk(prefix, rng, false);
        }
        8 if prefix.len() > 1 => {
            let keep_from = rng.random_range(1..prefix.len());
            prefix.drain(0..keep_from);
        }
        9..=10 if prefix.len() > 1 => {
            let keep = 1 + minimizing_index(prefix.len() - 1, rng);
            let removed = prefix.len() - keep;
            prefix.truncate(keep);
            shrink_leading_byte(prefix, removed, rng);
        }
        11 if !prefix.is_empty() => {
            let len = minimizing_index(prefix.len(), rng);
            prefix.truncate(len);
        }
        12..=13 if !prefix.is_empty() => {
            let start = minimizing_index(prefix.len(), rng);
            let end = minimizing_end(prefix.len(), start, rng);
            prefix[start..end].fill(0);
        }
        14..=17 if !prefix.is_empty() => {
            let index = minimizing_index(prefix.len(), rng);
            prefix[index] = shrink_byte(prefix[index], rng);
        }
        18 if !prefix.is_empty() => {
            let index = minimizing_index(prefix.len(), rng);
            prefix[index] = small_or_interesting_byte(rng);
        }
        19 if !prefix.is_empty() => {
            let index = minimizing_index(prefix.len(), rng);
            prefix[index] ^= 1 << rng.random_range(0..8);
        }
        20 if !prefix.is_empty() => {
            let index = minimizing_index(prefix.len(), rng);
            prefix[index] = prefix[index].wrapping_add(rng.random_range(1..=35));
        }
        21 if !prefix.is_empty() => {
            let index = minimizing_index(prefix.len(), rng);
            prefix[index] = prefix[index].wrapping_sub(rng.random_range(1..=35));
        }
        22 if !dictionary.is_empty() && !prefix.is_empty() => {
            let bytes = &dictionary[rng.random_range(0..dictionary.len())];
            replace_bytes(prefix, rng, bytes);
        }
        23 if !dictionary.is_empty() => {
            let bytes = &dictionary[rng.random_range(0..dictionary.len())];
            insert_bytes(prefix, rng, bytes);
        }
        24..=27 if prefix.len() >= 2 => {
            shrink_word_to_target(prefix, rng, 2);
        }
        28..=30 if prefix.len() >= 4 => {
            shrink_word_to_target(prefix, rng, 4);
        }
        31 if prefix.len() >= 8 => {
            shrink_word_to_target(prefix, rng, 8);
        }
        32 if prefix.len() >= 2 => {
            mutate_word(prefix, rng, 2);
        }
        33 if prefix.len() >= 4 => {
            mutate_word(prefix, rng, 4);
        }
        34 if !prefix.is_empty() => {
            let index = minimizing_index(prefix.len(), rng);
            prefix[index] = 0;
        }
        35 if prefix.len() > 1 => {
            let index = minimizing_index(prefix.len(), rng);
            prefix.remove(index);
        }
        36 if !prefix.is_empty() => {
            let index = minimizing_index(prefix.len(), rng);
            prefix[index] = rng.random();
        }
        37 if !prefix.is_empty() => {
            let index = minimizing_index(prefix.len(), rng);
            prefix[index] = prefix[index].min(small_or_interesting_byte(rng));
        }
        38 if prefix.len() > 1 => {
            let start = minimizing_index(prefix.len(), rng);
            let end = minimizing_end(prefix.len(), start, rng);
            for byte in &mut prefix[start..end] {
                *byte = small_or_interesting_byte(rng);
            }
        }
        39 => {
            let index = rng.random_range(0..=prefix.len());
            prefix.insert(index, rng.random());
        }
        _ if !prefix.is_empty() => {
            let index = minimizing_index(prefix.len(), rng);
            prefix[index] = shrink_byte(prefix[index], rng);
        }
        _ => prefix.push(rng.random()),
    }
}

fn drain_minimizing_chunk(prefix: &mut Vec<u8>, rng: &mut SmallRng, body_only: bool) -> usize {
    let start = if body_only && prefix.len() > 1 {
        1 + minimizing_index(prefix.len() - 1, rng)
    } else {
        minimizing_index(prefix.len(), rng)
    };
    let end = minimizing_end(prefix.len(), start, rng);
    let removed = end - start;
    prefix.drain(start..end);
    removed
}

fn shrink_leading_byte(prefix: &mut [u8], removed: usize, rng: &mut SmallRng) {
    let Some(first) = prefix.first_mut() else {
        return;
    };
    let max = removed.min(16) as u8;
    if max != 0 {
        *first = first.saturating_sub(rng.random_range(1..=max));
    }
}

fn minimizing_index(len: usize, rng: &mut SmallRng) -> usize {
    if len <= 1 {
        return 0;
    }
    if rng.random_bool(0.25) {
        return 0;
    }
    rng.random_range(0..len)
        .min(rng.random_range(0..len))
        .min(rng.random_range(0..len))
}

fn minimizing_end(len: usize, start: usize, rng: &mut SmallRng) -> usize {
    let remaining = len - start;
    let max_len = remaining.min(1 << rng.random_range(0..=remaining.ilog2()));
    start + rng.random_range(1..=max_len.max(1))
}

fn small_or_interesting_byte(rng: &mut SmallRng) -> u8 {
    if rng.random_bool(0.75) {
        rng.random_range(0..=16)
    } else {
        interesting_byte(rng)
    }
}

fn shrink_byte(byte: u8, rng: &mut SmallRng) -> u8 {
    if byte == 0 {
        0
    } else if rng.random_bool(0.5) {
        rng.random_range(0..=byte)
    } else {
        byte.saturating_sub(rng.random_range(1..=byte.min(16)))
    }
}

pub(super) fn choose_corpus_index<Capture: CoverageCapture>(
    state: &mut State<Capture>,
) -> Option<usize> {
    if state.corpus.is_empty() {
        return None;
    }

    entropic_corpus_index(state)
}

fn entropic_corpus_index<Capture: CoverageCapture>(state: &mut State<Capture>) -> Option<usize> {
    state
        .energy_index
        .sample(&mut state.scheduler)
        .or_else(|| Some(state.scheduler.random_range(0..state.corpus.len())))
}

pub(super) fn mutate_prefix(
    prefix: &mut Vec<u8>,
    rng: &mut SmallRng,
    crossover_prefix: Option<&[u8]>,
    dictionary: &[Vec<u8>],
    salt: u64,
) {
    match rng.random_range(0..14) {
        0 if !prefix.is_empty() => {
            let index = rng.random_range(0..prefix.len());
            prefix[index] ^= 1 << rng.random_range(0..8);
        }
        1 if !prefix.is_empty() => {
            let index = rng.random_range(0..prefix.len());
            prefix[index] = rng.random();
        }
        2 => {
            let index = rng.random_range(0..=prefix.len());
            prefix.insert(index, rng.random());
        }
        3 if prefix.len() > 1 => {
            let index = rng.random_range(0..prefix.len());
            prefix.remove(index);
        }
        4 if !prefix.is_empty() => {
            let start = rng.random_range(0..prefix.len());
            let end = rng.random_range(start + 1..=prefix.len());
            for byte in &mut prefix[start..end] {
                *byte = rng.random();
            }
        }
        5 if prefix.len() > 1 => {
            let start = rng.random_range(0..prefix.len());
            let end = rng.random_range(start + 1..=prefix.len());
            prefix.drain(start..end);
        }
        6 if !prefix.is_empty() => {
            let start = rng.random_range(0..prefix.len());
            let end = rng.random_range(start + 1..=prefix.len());
            let chunk: Vec<_> = prefix[start..end].to_vec();
            let insert = rng.random_range(0..=prefix.len());
            prefix.splice(insert..insert, chunk);
        }
        7 if !prefix.is_empty() => {
            let index = rng.random_range(0..prefix.len());
            prefix[index] = prefix[index].wrapping_add(rng.random_range(1..=35));
        }
        8 if !prefix.is_empty() => {
            let index = rng.random_range(0..prefix.len());
            prefix[index] = prefix[index].wrapping_sub(rng.random_range(1..=35));
        }
        9 if !prefix.is_empty() => {
            mutate_word(prefix, rng, 2);
        }
        10 if !prefix.is_empty() => {
            mutate_word(prefix, rng, 4);
        }
        11 if !dictionary.is_empty() => {
            let bytes = &dictionary[rng.random_range(0..dictionary.len())];
            insert_bytes(prefix, rng, bytes);
        }
        12 if !dictionary.is_empty() && !prefix.is_empty() => {
            let bytes = &dictionary[rng.random_range(0..dictionary.len())];
            let index = rng.random_range(0..prefix.len());
            let end = (index + bytes.len()).min(prefix.len());
            prefix.splice(index..end, bytes.iter().copied());
        }
        13 if crossover_prefix.is_some_and(|other| !other.is_empty()) => {
            let other = crossover_prefix.expect("checked crossover prefix");
            let start = rng.random_range(0..other.len());
            let end = rng.random_range(start + 1..=other.len());
            insert_bytes(prefix, rng, &other[start..end]);
        }
        _ => {
            let mut filler = SmallRng::seed_from_u64(salt);
            let extra = rng.random_range(1..=8);
            prefix.extend((0..extra).map(|_| filler.random::<u8>()));
        }
    };
}

fn mutate_word(prefix: &mut [u8], rng: &mut SmallRng, width: usize) {
    if prefix.len() < width {
        let index = rng.random_range(0..prefix.len());
        prefix[index] = interesting_byte(rng);
        return;
    }
    let index = rng.random_range(0..=prefix.len() - width);
    match width {
        2 => {
            let value = u16::from_le_bytes([prefix[index], prefix[index + 1]]);
            let value = value.wrapping_add(rng.random_range(1..=35));
            prefix[index..index + 2].copy_from_slice(&value.to_le_bytes());
        }
        4 => {
            let value = u32::from_le_bytes([
                prefix[index],
                prefix[index + 1],
                prefix[index + 2],
                prefix[index + 3],
            ]);
            let value = value.wrapping_sub(rng.random_range(1..=35));
            prefix[index..index + 4].copy_from_slice(&value.to_le_bytes());
        }
        _ => {}
    }
}

fn shrink_word_to_target(prefix: &mut [u8], rng: &mut SmallRng, width: usize) {
    if prefix.len() < width {
        let index = minimizing_index(prefix.len(), rng);
        prefix[index] = shrink_byte(prefix[index], rng);
        return;
    }

    let index = minimizing_index(prefix.len() - width + 1, rng);
    let current = read_le_word(&prefix[index..index + width]);
    let targets = smaller_word_targets(current, width);
    let Some(target) = choose_word_target(&targets, rng) else {
        let byte = index + minimizing_index(width, rng);
        prefix[byte] = shrink_byte(prefix[byte], rng);
        return;
    };
    write_le_word(&mut prefix[index..index + width], target);
}

fn choose_word_target(targets: &[u64], rng: &mut SmallRng) -> Option<u64> {
    if targets.is_empty() {
        return None;
    }

    if targets.len() > 1 && rng.random_bool(0.8) {
        let first_non_zero = targets.iter().position(|target| *target != 0).unwrap_or(0);
        let index = first_non_zero + minimizing_index(targets.len() - first_non_zero, rng);
        Some(targets[index])
    } else {
        Some(targets[minimizing_index(targets.len(), rng)])
    }
}

fn read_le_word(bytes: &[u8]) -> u64 {
    let mut word = 0_u64;
    for (index, byte) in bytes.iter().enumerate() {
        word |= (*byte as u64) << (index * 8);
    }
    word
}

fn write_le_word(bytes: &mut [u8], mut word: u64) {
    for byte in bytes {
        *byte = word as u8;
        word >>= 8;
    }
}

fn smaller_word_targets(word: u64, width: usize) -> Vec<u64> {
    if word == 0 {
        return Vec::new();
    }

    let max = match width {
        2 => u16::MAX as u64,
        4 => u32::MAX as u64,
        _ => u64::MAX,
    };

    let mut targets = Vec::new();
    for value in (0..=32)
        .chain([63, 64, 127, 128, 255, 256, 511, 512, 1023, 1024])
        .chain([
            word / 2,
            word.saturating_sub(1),
            word.saturating_sub(2),
            word.saturating_sub(4),
            word.saturating_sub(8),
            word.saturating_sub(16),
            word.saturating_sub(32),
            word.saturating_sub(64),
        ])
    {
        if value < word && value <= max && !targets.contains(&value) {
            targets.push(value);
        }
    }
    targets
}

fn interesting_byte(rng: &mut SmallRng) -> u8 {
    INTERESTING_BYTES[rng.random_range(0..INTERESTING_BYTES.len())]
}

fn insert_bytes(prefix: &mut Vec<u8>, rng: &mut SmallRng, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let index = rng.random_range(0..=prefix.len());
    prefix.splice(index..index, bytes.iter().copied());
}

fn replace_bytes(prefix: &mut Vec<u8>, rng: &mut SmallRng, bytes: &[u8]) {
    if bytes.is_empty() || prefix.is_empty() {
        return;
    }
    let index = rng.random_range(0..prefix.len());
    let end = (index + bytes.len()).min(prefix.len());
    prefix.splice(index..end, bytes.iter().copied());
}

#[cfg(test)]
pub(crate) fn test_dictionary_mutation(prefix: &mut Vec<u8>, dictionary: &[Vec<u8>]) {
    if let Some(bytes) = dictionary.first() {
        let mut rng = SmallRng::seed_from_u64(1);
        insert_bytes(prefix, &mut rng, bytes);
    }
}

pub(super) fn corpus_energy<Capture: CoverageCapture>(
    state: &State<Capture>,
    coverage: &[CoverageId],
) -> f64 {
    let executions = state.stats.executed.max(1) as f64;
    let mut energy = 0.0;
    for id in coverage {
        let frequency = (*state.coverage_frequency.get(id).unwrap_or(&1)).max(1) as f64;
        energy += (executions / frequency).ln().max(0.0);
    }
    energy.max(1.0)
}

pub(super) fn refresh_corpus_energies<Capture: CoverageCapture>(state: &mut State<Capture>) {
    match state.mode {
        Mode::Curious => {
            let executions = state.stats.executed.max(1) as f64;
            for entry in &mut state.corpus {
                let mut energy = 0.0;
                for id in &entry.coverage {
                    let frequency = (*state.coverage_frequency.get(id).unwrap_or(&1)).max(1) as f64;
                    energy += (executions / frequency).ln().max(0.0);
                }
                entry.energy = energy.max(1.0);
            }
        }
        Mode::Cautious => {
            if let Some(best) = state.min_path_best {
                for entry in &mut state.corpus {
                    entry.energy = min_path_schedule_energy(
                        &state.min_path_removed_frequency,
                        state.stats.accepted,
                        best,
                        &entry.removed,
                        entry.score,
                        entry.hit_count_weight,
                        entry.path_len,
                    );
                }
            }
        }
    }
    state
        .energy_index
        .rebuild(state.corpus.iter().map(|entry| entry.energy));
    state.executions_since_refresh = 0;
}
