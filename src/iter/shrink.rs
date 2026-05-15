use super::{
    prelude::{
        CAUTIOUS_ENERGY_REFRESH_INTERVAL, CURIOUS_ENERGY_REFRESH_INTERVAL,
        MAX_CAUTIOUS_BEST_NEIGHBORS, MAX_CORPUS_LEN, MAX_DICTIONARY_VALUES, MAX_PENDING_CANDIDATES,
        MAX_PREFIX_LEN, MinPathScore, Mode, State,
    },
    run::Candidate,
};
use crate::coverage::CoverageCapture;

pub(super) fn merge_dictionary_values<Capture: CoverageCapture>(
    state: &mut State<Capture>,
    values: Vec<Vec<u8>>,
) {
    for value in values {
        if state.dictionary.len() >= MAX_DICTIONARY_VALUES {
            break;
        }
        if value.is_empty() || state.dictionary.iter().any(|existing| existing == &value) {
            continue;
        }
        state.dictionary.push(value);
    }
}

pub(super) fn enqueue_cautious_best_neighbors<Capture: CoverageCapture>(
    state: &mut State<Capture>,
    index: usize,
) {
    let Some(entry) = state.corpus.get(index) else {
        return;
    };
    let seed = entry.seed;
    let prefix = entry.prefix.clone();

    let mut variants = Vec::new();
    enqueue_structural_shrink_neighbors(&prefix, &mut variants);
    enqueue_word_shrink_neighbors(&prefix, &mut variants);
    enqueue_byte_shrink_neighbors(&prefix, &mut variants);

    for mut candidate in variants.into_iter().rev() {
        if candidate.len() > MAX_PREFIX_LEN {
            candidate.truncate(MAX_PREFIX_LEN);
        }
        state.pending_candidates.push_front(Candidate {
            seed,
            prefix: candidate,
            mutated: true,
            zero_tail: true,
        });
    }
    while state.pending_candidates.len() > MAX_PENDING_CANDIDATES {
        state.pending_candidates.pop_back();
    }
}

fn enqueue_structural_shrink_neighbors(prefix: &[u8], variants: &mut Vec<Vec<u8>>) {
    let structural_limit = MAX_CAUTIOUS_BEST_NEIGHBORS / 2;
    if prefix.len() <= 1 {
        return;
    }

    for trim in [64, 32, 16, 8, 4, 3, 2, 1] {
        if trim >= prefix.len() {
            continue;
        }
        let mut candidate = prefix[..prefix.len() - trim].to_vec();
        shrink_first_by(&mut candidate, trim);
        push_neighbor(variants, candidate, structural_limit);
    }

    for width in structural_widths(prefix.len()) {
        let chunk_starts = [
            1,
            prefix.len().saturating_sub(width),
            prefix.len() / 2,
            prefix.len() / 4,
            prefix.len().saturating_mul(3) / 4,
        ];
        for start in chunk_starts {
            if variants.len() >= structural_limit {
                break;
            }
            if start == 0 || start >= prefix.len() {
                continue;
            }
            let end = (start + width).min(prefix.len());
            if end <= start {
                continue;
            }
            let mut candidate = prefix.to_vec();
            candidate.drain(start..end);
            shrink_first_by(&mut candidate, end - start);
            push_neighbor(variants, candidate, structural_limit);
        }
    }

    for index in 1..prefix.len() {
        if variants.len() >= structural_limit {
            break;
        }
        let mut candidate = prefix.to_vec();
        candidate.remove(index);
        shrink_first_by(&mut candidate, 1);
        push_neighbor(variants, candidate, structural_limit);
    }
}

fn enqueue_word_shrink_neighbors(prefix: &[u8], variants: &mut Vec<Vec<u8>>) {
    let word_limit = MAX_CAUTIOUS_BEST_NEIGHBORS * 3 / 4;
    for width in [2, 4, 8] {
        if prefix.len() < width {
            continue;
        }
        let max_start = (prefix.len() - width).min(16);
        for start in 0..=max_start {
            let current = read_le_word(&prefix[start..start + width]);
            for target in smaller_word_targets(current, width) {
                if variants.len() >= word_limit {
                    return;
                }
                let mut candidate = prefix.to_vec();
                write_le_word(&mut candidate[start..start + width], target);
                push_neighbor(variants, candidate, word_limit);
            }
        }
    }
}

fn enqueue_byte_shrink_neighbors(prefix: &[u8], variants: &mut Vec<Vec<u8>>) {
    let priority_len = prefix.len().min(16);
    for index in 0..priority_len {
        let byte = prefix[index];
        for value in smaller_byte_targets(byte) {
            if variants.len() >= MAX_CAUTIOUS_BEST_NEIGHBORS {
                return;
            }
            let mut candidate = prefix.to_vec();
            candidate[index] = value;
            push_neighbor(variants, candidate, MAX_CAUTIOUS_BEST_NEIGHBORS);
        }
    }
}

fn structural_widths(len: usize) -> impl Iterator<Item = usize> {
    [len / 2, 64, 32, 16, 8, 4, 3, 2, 1]
        .into_iter()
        .filter(move |width| *width > 0 && *width < len)
}

fn push_neighbor(variants: &mut Vec<Vec<u8>>, candidate: Vec<u8>, limit: usize) {
    if variants.len() >= limit || variants.iter().any(|existing| existing == &candidate) {
        return;
    }
    variants.push(candidate);
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

fn smaller_byte_targets(byte: u8) -> Vec<u8> {
    if byte == 0 {
        return Vec::new();
    }

    let mut targets = Vec::new();
    for value in [
        0,
        1,
        2,
        3,
        4,
        8,
        16,
        32,
        64,
        128,
        byte / 2,
        byte.saturating_sub(1),
        byte.saturating_sub(2),
        byte.saturating_sub(4),
        byte.saturating_sub(8),
        byte.saturating_sub(16),
    ] {
        if value < byte && !targets.contains(&value) {
            targets.push(value);
        }
    }
    targets
}

fn shrink_first_by(prefix: &mut [u8], amount: usize) {
    let Some(first) = prefix.first_mut() else {
        return;
    };
    *first = first.saturating_sub(amount.min(u8::MAX as usize) as u8);
}

pub(super) fn energy_refresh_interval(mode: Mode) -> u64 {
    match mode {
        Mode::Curious => CURIOUS_ENERGY_REFRESH_INTERVAL,
        Mode::Cautious => CAUTIOUS_ENERGY_REFRESH_INTERVAL,
    }
}

pub(super) fn prune_corpus<Capture: CoverageCapture>(state: &mut State<Capture>) {
    if state.corpus.len() <= MAX_CORPUS_LEN {
        return;
    }

    let remove = if state.mode == Mode::Cautious {
        state
            .corpus
            .iter()
            .enumerate()
            .max_by_key(|(_, entry)| {
                MinPathScore::new(entry.score, entry.hit_count_weight, entry.path_len)
            })
            .map(|(index, _)| index)
    } else {
        state
            .corpus
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| a.energy.total_cmp(&b.energy))
            .map(|(index, _)| index)
    }
    .or_else(|| {
        state
            .corpus
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| a.energy.total_cmp(&b.energy))
            .map(|(index, _)| index)
    });

    if let Some(index) = remove {
        state.corpus.swap_remove(index);
        state.energy_index.swap_remove(index);
        if state.mode == Mode::Cautious {
            refresh_min_path_best(state);
        }
    }
}

fn refresh_min_path_best<Capture: CoverageCapture>(state: &mut State<Capture>) {
    let best = state
        .corpus
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            (
                index,
                MinPathScore::new(entry.score, entry.hit_count_weight, entry.path_len),
            )
        })
        .min_by_key(|(_, score)| *score);
    state.min_path_best = best.map(|(_, score)| score);
    state.min_path_best_index = best.map(|(index, _)| index);
}
