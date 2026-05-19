use super::{
    mutation::{self, MutationWeights, RngByteMutation},
    prelude::{INTERESTING_BYTES, MAX_PREFIX_LEN, StateCore},
};
use rand::{Rng, SeedableRng, rngs::SmallRng};
use std::any::TypeId;

#[derive(Debug)]
struct WeightedMutation {
    type_id: TypeId,
    baseline: f64,
    mutator: Box<dyn RngByteMutation>,
}

pub(super) fn havoc_prefix(
    prefix: &[u8],
    rng: &mut SmallRng,
    depth: usize,
    dictionary: &[Vec<u8>],
    weights: &MutationWeights,
) -> (Vec<u8>, Vec<TypeId>) {
    let mut candidate = prefix.to_vec();
    let mut kinds = Vec::new();
    for _ in 0..depth.max(1) {
        if let Some(kind) = mutate_minimizing_havoc(&mut candidate, rng, dictionary, weights) {
            kinds.push(kind);
        }
        if candidate.len() > MAX_PREFIX_LEN {
            candidate.truncate(MAX_PREFIX_LEN);
        }
    }
    if candidate == prefix
        && let Some(kind) = mutate_minimizing_havoc(&mut candidate, rng, dictionary, weights)
    {
        kinds.push(kind);
    }
    (candidate, kinds)
}

fn mutate_minimizing_havoc(
    prefix: &mut Vec<u8>,
    rng: &mut SmallRng,
    dictionary: &[Vec<u8>],
    weights: &MutationWeights,
) -> Option<TypeId> {
    let mutations = minimizing_havoc_mutations(prefix, rng, dictionary);
    let mutation = choose_weighted_mutation(mutations, weights, rng)?;
    apply_mutation(prefix, dictionary, mutation)
}

fn minimizing_havoc_mutations(
    prefix: &[u8],
    rng: &mut SmallRng,
    dictionary: &[Vec<u8>],
) -> Vec<WeightedMutation> {
    let mut mutations = Vec::new();

    if prefix.len() > 1 {
        let (start, len) = minimizing_chunk(prefix.len(), rng, true);
        push_mutation(
            &mut mutations,
            5.0,
            mutation::delete_range(start, len, leading_byte_subtraction(len, rng)),
        );

        let (start, len) = minimizing_chunk(prefix.len(), rng, false);
        push_mutation(
            &mut mutations,
            3.0,
            mutation::delete_range(start, len, None),
        );

        push_mutation(
            &mut mutations,
            1.0,
            mutation::drain_prefix(rng.random_range(1..prefix.len())),
        );

        let keep = 1 + minimizing_index(prefix.len() - 1, rng);
        let removed = prefix.len() - keep;
        push_mutation(
            &mut mutations,
            2.0,
            mutation::truncate(keep, leading_byte_subtraction(removed, rng)),
        );

        push_mutation(
            &mut mutations,
            1.0,
            mutation::delete_range(minimizing_index(prefix.len(), rng), 1, None),
        );

        let start = minimizing_index(prefix.len(), rng);
        let end = minimizing_end(prefix.len(), start, rng);
        let bytes = (start..end)
            .map(|_| small_or_interesting_byte(rng))
            .collect();
        push_mutation(&mut mutations, 1.0, mutation::fill_range(start, bytes));
    }

    if !prefix.is_empty() {
        push_mutation(
            &mut mutations,
            1.0,
            mutation::truncate(minimizing_index(prefix.len(), rng), None),
        );

        let start = minimizing_index(prefix.len(), rng);
        let end = minimizing_end(prefix.len(), start, rng);
        push_mutation(
            &mut mutations,
            2.0,
            mutation::fill_range(start, vec![0; end - start]),
        );

        let index = minimizing_index(prefix.len(), rng);
        push_mutation(
            &mut mutations,
            4.0,
            mutation::set_byte(index, shrink_byte(prefix[index], rng)),
        );
        push_mutation(
            &mut mutations,
            1.0,
            mutation::set_byte(
                minimizing_index(prefix.len(), rng),
                small_or_interesting_byte(rng),
            ),
        );
        push_mutation(
            &mut mutations,
            1.0,
            mutation::xor_bit(minimizing_index(prefix.len(), rng), rng.random_range(0..8)),
        );
        push_mutation(
            &mut mutations,
            1.0,
            mutation::add_byte(
                minimizing_index(prefix.len(), rng),
                rng.random_range(1..=35),
            ),
        );
        push_mutation(
            &mut mutations,
            1.0,
            mutation::sub_byte(
                minimizing_index(prefix.len(), rng),
                rng.random_range(1..=35),
            ),
        );
        push_mutation(
            &mut mutations,
            1.0,
            mutation::set_byte(minimizing_index(prefix.len(), rng), 0),
        );
        push_mutation(
            &mut mutations,
            1.0,
            mutation::set_byte(minimizing_index(prefix.len(), rng), rng.random()),
        );
        push_mutation(
            &mut mutations,
            1.0,
            mutation::min_byte(
                minimizing_index(prefix.len(), rng),
                small_or_interesting_byte(rng),
            ),
        );
    }

    if !dictionary.is_empty() {
        push_mutation(
            &mut mutations,
            1.0,
            mutation::insert_dictionary(
                rng.random_range(0..=prefix.len()),
                rng.random_range(0..dictionary.len()),
            ),
        );
        if !prefix.is_empty() {
            let dictionary_index = rng.random_range(0..dictionary.len());
            let start = rng.random_range(0..prefix.len());
            let len = dictionary[dictionary_index].len().min(prefix.len() - start);
            push_mutation(
                &mut mutations,
                1.0,
                mutation::replace_dictionary(start, len, dictionary_index),
            );
        }
    }

    if prefix.len() >= 2 {
        push_mutation(
            &mut mutations,
            4.0,
            sample_shrink_word_to_target(prefix, rng, 2),
        );
        push_mutation(&mut mutations, 1.0, sample_mutate_word(prefix, rng, 2));
    }
    if prefix.len() >= 4 {
        push_mutation(
            &mut mutations,
            3.0,
            sample_shrink_word_to_target(prefix, rng, 4),
        );
        push_mutation(&mut mutations, 1.0, sample_mutate_word(prefix, rng, 4));
    }
    if prefix.len() >= 8 {
        push_mutation(
            &mut mutations,
            1.0,
            sample_shrink_word_to_target(prefix, rng, 8),
        );
    }

    push_mutation(
        &mut mutations,
        1.0,
        mutation::insert_bytes(rng.random_range(0..=prefix.len()), vec![rng.random()]),
    );
    mutations
}

fn push_mutation(
    mutations: &mut Vec<WeightedMutation>,
    baseline: f64,
    mutator: Box<dyn RngByteMutation>,
) {
    mutations.push(WeightedMutation {
        type_id: mutator.as_ref().type_id(),
        baseline,
        mutator,
    });
}

fn choose_weighted_mutation(
    mut mutations: Vec<WeightedMutation>,
    weights: &MutationWeights,
    rng: &mut SmallRng,
) -> Option<Box<dyn RngByteMutation>> {
    let total = mutations
        .iter()
        .map(|mutation| weights.selection_weight(mutation.type_id, mutation.baseline))
        .sum::<f64>();
    if !total.is_finite() || total <= 0.0 {
        return mutations.pop().map(|mutation| mutation.mutator);
    }

    let mut target = rng.random::<f64>() * total;
    for (index, mutation) in mutations.iter().enumerate() {
        let weight = weights.selection_weight(mutation.type_id, mutation.baseline);
        if target < weight {
            return Some(mutations.swap_remove(index).mutator);
        }
        target -= weight;
    }
    mutations.pop().map(|mutation| mutation.mutator)
}

fn apply_mutation(
    prefix: &mut Vec<u8>,
    dictionary: &[Vec<u8>],
    mutation: Box<dyn RngByteMutation>,
) -> Option<TypeId> {
    let type_id = mutation.as_ref().type_id();
    mutation.apply_bytes(prefix, dictionary).then_some(type_id)
}

fn minimizing_chunk(len: usize, rng: &mut SmallRng, body_only: bool) -> (usize, usize) {
    let start = if body_only && len > 1 {
        1 + minimizing_index(len - 1, rng)
    } else {
        minimizing_index(len, rng)
    };
    let end = minimizing_end(len, start, rng);
    (start, end - start)
}

fn leading_byte_subtraction(removed: usize, rng: &mut SmallRng) -> Option<u8> {
    let max = removed.min(16) as u8;
    (max != 0).then(|| rng.random_range(1..=max))
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

pub(super) fn choose_corpus_index(state: &mut StateCore) -> Option<usize> {
    if state.corpus.is_empty() {
        return None;
    }

    entropic_corpus_index(state)
}

fn entropic_corpus_index(state: &mut StateCore) -> Option<usize> {
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
    weights: &MutationWeights,
) -> Option<TypeId> {
    let mutations = curious_mutations(prefix, rng, crossover_prefix, dictionary, salt);
    let mutation = choose_weighted_mutation(mutations, weights, rng)?;
    apply_mutation(prefix, dictionary, mutation)
}

fn curious_mutations(
    prefix: &[u8],
    rng: &mut SmallRng,
    crossover_prefix: Option<&[u8]>,
    dictionary: &[Vec<u8>],
    salt: u64,
) -> Vec<WeightedMutation> {
    let mut mutations = Vec::new();

    if !prefix.is_empty() {
        push_mutation(
            &mut mutations,
            1.0,
            mutation::xor_bit(rng.random_range(0..prefix.len()), rng.random_range(0..8)),
        );
        push_mutation(
            &mut mutations,
            1.0,
            mutation::set_byte(rng.random_range(0..prefix.len()), rng.random()),
        );

        let start = rng.random_range(0..prefix.len());
        let end = rng.random_range(start + 1..=prefix.len());
        let bytes = (start..end).map(|_| rng.random()).collect();
        push_mutation(&mut mutations, 1.0, mutation::fill_range(start, bytes));

        let start = rng.random_range(0..prefix.len());
        let end = rng.random_range(start + 1..=prefix.len());
        let chunk = prefix[start..end].to_vec();
        push_mutation(
            &mut mutations,
            1.0,
            mutation::insert_bytes(rng.random_range(0..=prefix.len()), chunk),
        );

        push_mutation(
            &mut mutations,
            1.0,
            mutation::add_byte(rng.random_range(0..prefix.len()), rng.random_range(1..=35)),
        );
        push_mutation(
            &mut mutations,
            1.0,
            mutation::sub_byte(rng.random_range(0..prefix.len()), rng.random_range(1..=35)),
        );
        push_mutation(&mut mutations, 1.0, sample_mutate_word(prefix, rng, 2));
        push_mutation(&mut mutations, 1.0, sample_mutate_word(prefix, rng, 4));
    }

    push_mutation(
        &mut mutations,
        1.0,
        mutation::insert_bytes(rng.random_range(0..=prefix.len()), vec![rng.random()]),
    );

    if prefix.len() > 1 {
        push_mutation(
            &mut mutations,
            1.0,
            mutation::delete_range(rng.random_range(0..prefix.len()), 1, None),
        );
        let start = rng.random_range(0..prefix.len());
        let end = rng.random_range(start + 1..=prefix.len());
        push_mutation(
            &mut mutations,
            1.0,
            mutation::delete_range(start, end - start, None),
        );
    }

    if !dictionary.is_empty() {
        push_mutation(
            &mut mutations,
            1.0,
            mutation::insert_dictionary(
                rng.random_range(0..=prefix.len()),
                rng.random_range(0..dictionary.len()),
            ),
        );
        if !prefix.is_empty() {
            let dictionary_index = rng.random_range(0..dictionary.len());
            let index = rng.random_range(0..prefix.len());
            let len = dictionary[dictionary_index].len().min(prefix.len() - index);
            push_mutation(
                &mut mutations,
                1.0,
                mutation::replace_dictionary(index, len, dictionary_index),
            );
        }
    }

    if let Some(other) = crossover_prefix.filter(|other| !other.is_empty()) {
        let start = rng.random_range(0..other.len());
        let end = rng.random_range(start + 1..=other.len());
        push_mutation(
            &mut mutations,
            1.0,
            mutation::insert_bytes(
                rng.random_range(0..=prefix.len()),
                other[start..end].to_vec(),
            ),
        );
    }

    let mut filler = SmallRng::seed_from_u64(salt);
    let extra = rng.random_range(1..=8);
    push_mutation(
        &mut mutations,
        1.0,
        mutation::insert_bytes(
            prefix.len(),
            (0..extra).map(|_| filler.random::<u8>()).collect(),
        ),
    );

    mutations
}

fn sample_mutate_word(prefix: &[u8], rng: &mut SmallRng, width: usize) -> Box<dyn RngByteMutation> {
    if prefix.len() < width {
        let index = rng.random_range(0..prefix.len());
        return mutation::set_byte(index, interesting_byte(rng));
    }
    let index = rng.random_range(0..=prefix.len() - width);
    match width {
        2 => {
            let value = u16::from_le_bytes([prefix[index], prefix[index + 1]]);
            let value = value.wrapping_add(rng.random_range(1..=35));
            mutation::set_word(index, width, u64::from(value))
        }
        4 => {
            let value = u32::from_le_bytes([
                prefix[index],
                prefix[index + 1],
                prefix[index + 2],
                prefix[index + 3],
            ]);
            let value = value.wrapping_sub(rng.random_range(1..=35));
            mutation::set_word(index, width, u64::from(value))
        }
        _ => mutation::set_byte(index, interesting_byte(rng)),
    }
}

fn sample_shrink_word_to_target(
    prefix: &[u8],
    rng: &mut SmallRng,
    width: usize,
) -> Box<dyn RngByteMutation> {
    if prefix.len() < width {
        let index = minimizing_index(prefix.len(), rng);
        return mutation::set_byte(index, shrink_byte(prefix[index], rng));
    }

    let index = minimizing_index(prefix.len() - width + 1, rng);
    let current = read_le_word(&prefix[index..index + width]);
    let targets = smaller_word_targets(current, width);
    let Some(target) = choose_word_target(&targets, rng) else {
        let byte = index + minimizing_index(width, rng);
        return mutation::set_byte(byte, shrink_byte(prefix[byte], rng));
    };
    mutation::set_word(index, width, target)
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

#[cfg(test)]
pub(crate) fn test_dictionary_mutation(prefix: &mut Vec<u8>, dictionary: &[Vec<u8>]) {
    if let Some(bytes) = dictionary.first() {
        let mut rng = SmallRng::seed_from_u64(1);
        let mutation = mutation::insert_bytes(rng.random_range(0..=prefix.len()), bytes.clone());
        let _ = mutation.apply_bytes(prefix, dictionary);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weighted_mutation_selection_favors_boosted_concrete_mutator() {
        let mut weights = MutationWeights::default();
        let set_byte_id = mutation::set_byte(0, 0).as_ref().type_id();
        let insert_bytes_id = mutation::insert_bytes(0, vec![1]).as_ref().type_id();
        weights.set_for_test(set_byte_id, 16.0);
        weights.set_for_test(insert_bytes_id, 0.10);

        let mut rng = SmallRng::seed_from_u64(1);
        let mut set_byte = 0;
        for _ in 0..64 {
            let insert_bytes = mutation::insert_bytes(0, vec![1]);
            let set_byte_mutation = mutation::set_byte(0, 0);
            let mutation = choose_weighted_mutation(
                vec![
                    WeightedMutation {
                        type_id: insert_bytes.as_ref().type_id(),
                        baseline: 1.0,
                        mutator: insert_bytes,
                    },
                    WeightedMutation {
                        type_id: set_byte_mutation.as_ref().type_id(),
                        baseline: 1.0,
                        mutator: set_byte_mutation,
                    },
                ],
                &weights,
                &mut rng,
            )
            .expect("weighted mutation");
            set_byte += usize::from(mutation.as_ref().type_id() == set_byte_id);
        }

        assert!(set_byte >= 60, "set_byte selected {set_byte} times");
    }
}
