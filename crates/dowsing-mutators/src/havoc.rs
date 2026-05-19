use crate as mutation;
use dowsing_core::{INTERESTING_BYTES, MAX_PREFIX_LEN, MutationWeights, RngTraceMutation};
use dowsing_rng::{ByteAffinity, Trace, TraceEvent, TraceNode};
use rand::{Rng, SeedableRng, rngs::SmallRng};
use std::{any::TypeId, ops::Range};

const SPECIAL_BYTES: &[u8] = b"!*'();:@&=+$,/?%#[]012Az-`~.\xff\0";
const MAX_REPEATED_INSERT: usize = 128;
const MAX_SHUFFLE: usize = 8;
const MAX_COPY_PART: usize = 64;
const MAX_ASCII_INTEGER_LEN: usize = 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HavocProfile {
    Coverage,
    Minimizing,
}

#[derive(Debug)]
struct WeightedMutation {
    type_id: TypeId,
    baseline: f64,
    mutator: Box<dyn RngTraceMutation>,
}

pub fn havoc_trace(
    trace: &Trace,
    rng: &mut SmallRng,
    depth: usize,
    dictionary: &[Vec<u8>],
    weights: &MutationWeights,
) -> (Trace, Vec<TypeId>) {
    let mut candidate = trace.clone();
    let mut kinds = Vec::new();
    for _ in 0..depth.max(1) {
        if let Some(kind) = mutate_minimizing_havoc(&mut candidate, rng, dictionary, weights) {
            kinds.push(kind);
        }
        if candidate.flatten_prefix().len() > MAX_PREFIX_LEN {
            let _ = mutation::truncate(MAX_PREFIX_LEN, None).apply_trace(&mut candidate, &[]);
        }
    }
    if candidate == *trace
        && let Some(kind) = mutate_minimizing_havoc(&mut candidate, rng, dictionary, weights)
    {
        kinds.push(kind);
    }
    (candidate, kinds)
}

fn mutate_minimizing_havoc(
    trace: &mut Trace,
    rng: &mut SmallRng,
    dictionary: &[Vec<u8>],
    weights: &MutationWeights,
) -> Option<TypeId> {
    let prefix = trace.flatten_prefix();
    let mutations = minimizing_havoc_mutations(&prefix, rng, dictionary);
    let mutation = choose_weighted_mutation(mutations, weights, rng)?;
    apply_mutation(trace, dictionary, mutation)
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
        mutation::insert_bytes(
            rng.random_range(0..=prefix.len()),
            vec![random_or_special_byte(rng)],
        ),
    );
    push_mature_byte_mutations(
        &mut mutations,
        prefix,
        rng,
        None,
        dictionary,
        HavocProfile::Minimizing,
    );
    mutations
}

fn push_mutation(
    mutations: &mut Vec<WeightedMutation>,
    baseline: f64,
    mutator: Box<dyn RngTraceMutation>,
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
) -> Option<Box<dyn RngTraceMutation>> {
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
    trace: &mut Trace,
    dictionary: &[Vec<u8>],
    mutation: Box<dyn RngTraceMutation>,
) -> Option<TypeId> {
    let type_id = mutation.as_ref().type_id();
    mutation.apply_trace(trace, dictionary).then_some(type_id)
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

pub fn mutate_trace(
    trace: &mut Trace,
    rng: &mut SmallRng,
    crossover_trace: Option<&Trace>,
    dictionary: &[Vec<u8>],
    salt: u64,
    weights: &MutationWeights,
) -> Option<TypeId> {
    let prefix = trace.flatten_prefix();
    let crossover_prefix = crossover_trace.map(Trace::flatten_prefix);
    let mutations = curious_mutations(&prefix, rng, crossover_prefix.as_deref(), dictionary, salt);
    let mutation = choose_weighted_mutation(mutations, weights, rng)?;
    apply_mutation(trace, dictionary, mutation)
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
            mutation::set_byte(
                rng.random_range(0..prefix.len()),
                random_or_special_byte(rng),
            ),
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
        mutation::insert_bytes(
            rng.random_range(0..=prefix.len()),
            vec![random_or_special_byte(rng)],
        ),
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

    push_mature_byte_mutations(
        &mut mutations,
        prefix,
        rng,
        crossover_prefix,
        dictionary,
        HavocProfile::Coverage,
    );

    mutations
}

fn push_mature_byte_mutations(
    mutations: &mut Vec<WeightedMutation>,
    prefix: &[u8],
    rng: &mut SmallRng,
    crossover_prefix: Option<&[u8]>,
    dictionary: &[Vec<u8>],
    profile: HavocProfile,
) {
    if !prefix.is_empty() {
        if let Some(mutator) = sample_shuffle_bytes(prefix, rng) {
            push_mutation(mutations, profile_weight(profile, 1.0, 0.25), mutator);
        }
        if let Some(mutator) = sample_copy_part(prefix, rng) {
            push_mutation(mutations, profile_weight(profile, 1.25, 0.25), mutator);
        }
        if let Some(mutator) = sample_change_ascii_integer(prefix, rng, profile) {
            push_mutation(mutations, profile_weight(profile, 1.0, 1.25), mutator);
        }
        if let Some(mutator) = sample_change_binary_integer(prefix, rng, profile) {
            push_mutation(mutations, profile_weight(profile, 1.5, 1.5), mutator);
        }
    }

    if let Some(mutator) = sample_insert_repeated_bytes(prefix.len(), rng) {
        push_mutation(mutations, profile_weight(profile, 1.0, 0.20), mutator);
    }

    if !dictionary.is_empty() {
        push_dictionary_mutations(mutations, prefix, rng, dictionary, profile);
    }

    if let Some(other) = crossover_prefix.filter(|other| !other.is_empty()) {
        push_crossover_mutations(mutations, prefix, other, rng, profile);
    }
}

fn profile_weight(profile: HavocProfile, coverage: f64, minimizing: f64) -> f64 {
    match profile {
        HavocProfile::Coverage => coverage,
        HavocProfile::Minimizing => minimizing,
    }
}

fn sample_insert_repeated_bytes(
    prefix_len: usize,
    rng: &mut SmallRng,
) -> Option<Box<dyn RngTraceMutation>> {
    let room = MAX_PREFIX_LEN
        .saturating_sub(prefix_len)
        .min(MAX_REPEATED_INSERT);
    if room < 3 {
        return None;
    }
    Some(mutation::insert_repeated_bytes(
        rng.random_range(0..=prefix_len),
        repeated_byte(rng),
        rng.random_range(3..=room),
    ))
}

fn sample_shuffle_bytes(prefix: &[u8], rng: &mut SmallRng) -> Option<Box<dyn RngTraceMutation>> {
    if prefix.len() < 2 {
        return None;
    }
    let len = rng.random_range(2..=prefix.len().min(MAX_SHUFFLE));
    let start = rng.random_range(0..=prefix.len() - len);
    let mut bytes = prefix[start..start + len].to_vec();
    shuffle_in_place(&mut bytes, rng);
    if bytes == prefix[start..start + len] {
        bytes.swap(0, len - 1);
    }
    Some(mutation::shuffle_bytes(start, bytes))
}

fn sample_copy_part(prefix: &[u8], rng: &mut SmallRng) -> Option<Box<dyn RngTraceMutation>> {
    if prefix.is_empty() {
        return None;
    }
    let len = random_chunk_len(prefix.len().min(MAX_COPY_PART), rng);
    let source = rng.random_range(0..=prefix.len() - len);
    let insert = rng.random_bool(0.5);
    let target = if insert {
        rng.random_range(0..=prefix.len())
    } else {
        rng.random_range(0..=prefix.len() - len)
    };
    Some(mutation::copy_part(source, target, len, insert))
}

fn push_crossover_mutations(
    mutations: &mut Vec<WeightedMutation>,
    prefix: &[u8],
    other: &[u8],
    rng: &mut SmallRng,
    profile: HavocProfile,
) {
    let other_range = random_range(other.len(), MAX_COPY_PART, rng);
    let other_bytes = other[other_range].to_vec();
    push_mutation(
        mutations,
        profile_weight(profile, 1.0, 0.15),
        mutation::insert_bytes(rng.random_range(0..=prefix.len()), other_bytes.clone()),
    );

    if prefix.is_empty() {
        return;
    }

    let overwrite_len = other_bytes.len().min(prefix.len());
    let overwrite_start = rng.random_range(0..=prefix.len() - overwrite_len);
    push_mutation(
        mutations,
        profile_weight(profile, 1.0, 0.20),
        mutation::fill_range(overwrite_start, other_bytes[..overwrite_len].to_vec()),
    );

    let replace = random_range(prefix.len(), MAX_COPY_PART, rng);
    push_mutation(
        mutations,
        profile_weight(profile, 1.0, 0.15),
        mutation::replace_bytes(replace.start, replace.len(), other_bytes),
    );
}

fn push_dictionary_mutations(
    mutations: &mut Vec<WeightedMutation>,
    prefix: &[u8],
    rng: &mut SmallRng,
    dictionary: &[Vec<u8>],
    profile: HavocProfile,
) {
    if dictionary.is_empty() {
        return;
    }

    let dictionary_index = rng.random_range(0..dictionary.len());
    let value = &dictionary[dictionary_index];
    if value.is_empty() {
        return;
    }

    if prefix.len().saturating_add(value.len()) <= MAX_PREFIX_LEN {
        push_mutation(
            mutations,
            profile_weight(profile, 1.25, 0.25),
            mutation::insert_dictionary(rng.random_range(0..=prefix.len()), dictionary_index),
        );
    }

    if !prefix.is_empty() {
        let start = rng.random_range(0..prefix.len());
        let len = value.len().min(prefix.len() - start);
        if len > 0 {
            push_mutation(
                mutations,
                profile_weight(profile, 1.0, 0.40),
                mutation::replace_dictionary(start, len, dictionary_index),
            );
        }
    }

    if value.len() <= prefix.len() {
        let start = rng.random_range(0..=prefix.len() - value.len());
        push_mutation(
            mutations,
            profile_weight(profile, 1.0, 0.80),
            mutation::replace_dictionary_exact(start, value.len(), dictionary_index),
        );
        if let Some(start) = near_dictionary_position(prefix, value, rng) {
            push_mutation(
                mutations,
                profile_weight(profile, 1.25, 1.25),
                mutation::replace_dictionary_exact(start, value.len(), dictionary_index),
            );
        }
    }
}

fn near_dictionary_position(prefix: &[u8], value: &[u8], rng: &mut SmallRng) -> Option<usize> {
    if value.is_empty() || value.len() > prefix.len() {
        return None;
    }
    let max_distance = (value.len() / 4).max(1);
    let mut matches = Vec::new();
    for start in 0..=prefix.len() - value.len() {
        let distance = prefix[start..start + value.len()]
            .iter()
            .zip(value)
            .filter(|(left, right)| left != right)
            .count();
        if distance > 0 && distance <= max_distance {
            matches.push(start);
        }
    }
    (!matches.is_empty()).then(|| matches[rng.random_range(0..matches.len())])
}

fn sample_change_ascii_integer(
    prefix: &[u8],
    rng: &mut SmallRng,
    profile: HavocProfile,
) -> Option<Box<dyn RngTraceMutation>> {
    let ranges = ascii_integer_ranges(prefix);
    if ranges.is_empty() {
        return None;
    }
    let range = ranges[rng.random_range(0..ranges.len())].clone();
    let text = std::str::from_utf8(&prefix[range.clone()]).ok()?;
    let current = text.parse::<i64>().unwrap_or(0);
    let target = choose_ascii_integer_target(current, rng, profile);
    Some(mutation::replace_bytes(
        range.start,
        range.len(),
        target.to_string().into_bytes(),
    ))
}

fn ascii_integer_ranges(prefix: &[u8]) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut index = 0;
    while index < prefix.len() {
        let signed =
            prefix[index] == b'-' && index + 1 < prefix.len() && prefix[index + 1].is_ascii_digit();
        if prefix[index].is_ascii_digit() || signed {
            let start = index;
            if signed {
                index += 1;
            }
            while index < prefix.len() && prefix[index].is_ascii_digit() {
                index += 1;
            }
            if index - start <= MAX_ASCII_INTEGER_LEN {
                ranges.push(start..index);
            }
        } else {
            index += 1;
        }
    }
    ranges
}

fn choose_ascii_integer_target(current: i64, rng: &mut SmallRng, profile: HavocProfile) -> i64 {
    let mut targets = Vec::new();
    match profile {
        HavocProfile::Coverage => {
            targets.extend([0, 1, -1, 16, 31, 32, 63, 64, 127, 128, 255, 256]);
            let delta = rng.random_range(1..=35);
            targets.extend([
                current.wrapping_add(delta),
                current.wrapping_sub(delta),
                current.wrapping_neg(),
            ]);
        }
        HavocProfile::Minimizing => {
            targets.extend([0, 1, -1, current / 2]);
            let max_delta = (current.unsigned_abs().min(35) as i64).max(1);
            let delta = rng.random_range(1..=max_delta);
            if current >= 0 {
                targets.push(current.saturating_sub(delta));
            } else {
                targets.push(current.saturating_add(delta));
            }
        }
    }
    targets.retain(|target| *target != current);
    if targets.is_empty() {
        0
    } else {
        targets[rng.random_range(0..targets.len())]
    }
}

fn sample_change_binary_integer(
    prefix: &[u8],
    rng: &mut SmallRng,
    profile: HavocProfile,
) -> Option<Box<dyn RngTraceMutation>> {
    let widths: Vec<_> = [1, 2, 4, 8]
        .into_iter()
        .filter(|width| *width <= prefix.len())
        .collect();
    if widths.is_empty() {
        return None;
    }
    let width = widths.get(rng.random_range(0..widths.len())).copied()?;
    let start = rng.random_range(0..=prefix.len() - width);
    let big_endian = width > 1 && rng.random_bool(0.5);
    let current = read_word(&prefix[start..start + width], big_endian);
    let target = choose_binary_integer_target(current, width, rng, profile)?;
    Some(mutation::set_word_endian(start, width, target, big_endian))
}

fn choose_binary_integer_target(
    current: u64,
    width: usize,
    rng: &mut SmallRng,
    profile: HavocProfile,
) -> Option<u64> {
    let max = max_word_value(width);
    let mut targets = Vec::new();
    match profile {
        HavocProfile::Coverage => {
            targets.extend(
                [
                    0, 1, 16, 31, 32, 63, 64, 127, 128, 255, 256, 511, 512, 1023, 1024,
                ]
                .into_iter()
                .filter(|target| *target <= max),
            );
            targets.extend([max, max.saturating_sub(1)]);
            let sign_bit = 1_u64.checked_shl((width * 8 - 1) as u32).unwrap_or(0);
            targets.extend([sign_bit.saturating_sub(1), sign_bit]);
            let delta = rng.random_range(1..=35);
            targets.extend([
                current.wrapping_add(delta) & max,
                current.wrapping_sub(delta) & max,
                (!current) & max,
                current.wrapping_neg() & max,
            ]);
        }
        HavocProfile::Minimizing => {
            targets.extend(smaller_word_targets(current, width));
            let delta = rng.random_range(1..=current.clamp(1, 35));
            targets.push(current.saturating_sub(delta));
        }
    }
    targets.retain(|target| *target != current && *target <= max);
    targets.sort_unstable();
    targets.dedup();
    if targets.is_empty() {
        None
    } else {
        Some(targets[rng.random_range(0..targets.len())])
    }
}

fn random_chunk_len(max: usize, rng: &mut SmallRng) -> usize {
    if max <= 1 {
        1
    } else {
        1 + rng.random_range(0..max).min(rng.random_range(0..max))
    }
}

fn random_range(len: usize, max_chunk: usize, rng: &mut SmallRng) -> Range<usize> {
    let chunk = random_chunk_len(len.min(max_chunk), rng);
    let start = rng.random_range(0..=len - chunk);
    start..start + chunk
}

fn shuffle_in_place(bytes: &mut [u8], rng: &mut SmallRng) {
    for index in (1..bytes.len()).rev() {
        let other = rng.random_range(0..=index);
        bytes.swap(index, other);
    }
}

fn repeated_byte(rng: &mut SmallRng) -> u8 {
    if rng.random_bool(0.33) {
        0
    } else if rng.random_bool(0.50) {
        255
    } else {
        random_or_special_byte(rng)
    }
}

fn random_or_special_byte(rng: &mut SmallRng) -> u8 {
    if rng.random_bool(0.5) {
        rng.random()
    } else {
        SPECIAL_BYTES[rng.random_range(0..SPECIAL_BYTES.len())]
    }
}

fn read_word(bytes: &[u8], big_endian: bool) -> u64 {
    if big_endian {
        bytes
            .iter()
            .fold(0_u64, |word, byte| (word << 8) | u64::from(*byte))
    } else {
        read_le_word(bytes)
    }
}

fn max_word_value(width: usize) -> u64 {
    if width >= 8 {
        u64::MAX
    } else {
        (1_u64 << (width * 8)) - 1
    }
}

fn sample_mutate_word(
    prefix: &[u8],
    rng: &mut SmallRng,
    width: usize,
) -> Box<dyn RngTraceMutation> {
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
) -> Box<dyn RngTraceMutation> {
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

    let max = max_word_value(width);

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

#[doc(hidden)]
pub fn test_dictionary_mutation(prefix: &mut Vec<u8>, dictionary: &[Vec<u8>]) {
    if let Some(bytes) = dictionary.first() {
        let mut rng = SmallRng::seed_from_u64(1);
        let mutation = mutation::insert_bytes(rng.random_range(0..=prefix.len()), bytes.clone());
        let mut trace = trace_from_bytes(0, prefix.clone());
        let _ = mutation.apply_trace(&mut trace, dictionary);
        *prefix = trace.flatten_prefix();
    }
}

fn trace_from_bytes(seed: u64, bytes: Vec<u8>) -> Trace {
    Trace {
        seed,
        root: TraceNode {
            events: if bytes.is_empty() {
                Vec::new()
            } else {
                vec![TraceEvent::Draw {
                    bytes,
                    affinity: ByteAffinity::Any,
                }]
            },
        },
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

    #[test]
    fn mature_mutation_set_includes_libfuzzer_like_operators() {
        let prefix = b"id=1234;abcdef".to_vec();
        let dictionary = vec![b"abcxef".to_vec()];
        let mut rng = SmallRng::seed_from_u64(7);

        let mutations = curious_mutations(&prefix, &mut rng, Some(b"OTHERPREFIX"), &dictionary, 11);
        let ids: Vec<_> = mutations.iter().map(|mutation| mutation.type_id).collect();

        assert!(ids.contains(&mutation::insert_repeated_bytes(0, 0, 3).as_ref().type_id()));
        assert!(ids.contains(&mutation::shuffle_bytes(0, vec![1, 0]).as_ref().type_id()));
        assert!(ids.contains(&mutation::copy_part(0, 1, 1, true).as_ref().type_id()));
        assert!(ids.contains(&mutation::replace_bytes(0, 1, vec![1]).as_ref().type_id()));
        assert!(ids.contains(&mutation::set_word_endian(0, 1, 1, false).as_ref().type_id()));
        assert!(ids.contains(&mutation::replace_dictionary(0, 1, 0).as_ref().type_id()));
    }

    #[test]
    fn ascii_integer_mutation_changes_numeric_text_without_semantic_spans() {
        let prefix = b"x=-123 y=45".to_vec();
        let mut rng = SmallRng::seed_from_u64(3);
        let mutation = sample_change_ascii_integer(&prefix, &mut rng, HavocProfile::Coverage)
            .expect("ascii integer mutation");
        let mut trace = trace_from_bytes(0, prefix.clone());

        assert!(mutation.apply_trace(&mut trace, &[]));
        let candidate = trace.flatten_prefix();
        assert_ne!(candidate, prefix);
        assert!(candidate.iter().any(u8::is_ascii_digit));
    }

    #[test]
    fn binary_integer_minimization_can_shrink_a_single_byte() {
        let prefix = vec![10];
        let mut rng = SmallRng::seed_from_u64(5);
        let mutation = sample_change_binary_integer(&prefix, &mut rng, HavocProfile::Minimizing)
            .expect("binary integer mutation");
        let mut trace = trace_from_bytes(0, prefix.clone());

        assert!(mutation.apply_trace(&mut trace, &[]));
        let candidate = trace.flatten_prefix();
        assert!(candidate[0] < prefix[0]);
    }

    #[test]
    fn dictionary_near_match_finds_repair_site() {
        let mut rng = SmallRng::seed_from_u64(1);

        assert_eq!(
            near_dictionary_position(b"xxabxdyy", b"abcd", &mut rng),
            Some(2)
        );
    }
}
