//! LLVM source coverage collection for in-process coverage-guided fuzzing.
//!
//! Build the harness with `RUSTFLAGS="-Cinstrument-coverage"` and use
//! [`LlvmCoverage::evaluate`] from a [`crate::InputCaseIteratorExt::explore_coverage`] capture
//! provider. The collector resets LLVM counters before each case, writes a per-case profile,
//! exports source coverage with `llvm-cov`, and returns covered source regions as
//! [`CoverageId`]s.

use crate::{CoverageCapture, CoverageEvaluation, CoverageId, CoverageSet};
use serde_json::Value;
use std::{
    ffi::CString,
    fs,
    os::raw::{c_char, c_int},
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_PROFILE_ID: AtomicU64 = AtomicU64::new(0);

/// In-process LLVM coverage collector.
pub struct LlvmCoverage {
    object: PathBuf,
    sources: Vec<PathBuf>,
    profiles: PathBuf,
    profdata: PathBuf,
    llvm_profdata: PathBuf,
    llvm_cov: PathBuf,
    runtime: LlvmProfileRuntime,
}

impl LlvmCoverage {
    /// Create a collector for `object`, limiting exported coverage to `sources`.
    ///
    /// `workdir` receives per-case `.profraw` and `.profdata` files.
    pub fn new<P, Sources>(
        object: impl Into<PathBuf>,
        sources: Sources,
        workdir: impl Into<PathBuf>,
    ) -> Result<Self, String>
    where
        P: Into<PathBuf>,
        Sources: IntoIterator<Item = P>,
    {
        let workdir = workdir.into();
        let profiles = workdir.join("profiles");
        let profdata = workdir.join("profdata");
        fs::create_dir_all(&profiles)
            .map_err(|error| format!("failed to create {}: {error}", profiles.display()))?;
        fs::create_dir_all(&profdata)
            .map_err(|error| format!("failed to create {}: {error}", profdata.display()))?;

        Ok(Self {
            object: object.into(),
            sources: sources.into_iter().map(Into::into).collect(),
            profiles,
            profdata,
            llvm_profdata: PathBuf::from("llvm-profdata"),
            llvm_cov: PathBuf::from("llvm-cov"),
            runtime: LlvmProfileRuntime::new(),
        })
    }

    /// Override the `llvm-profdata` executable.
    pub fn llvm_profdata(mut self, path: impl Into<PathBuf>) -> Self {
        self.llvm_profdata = path.into();
        self
    }

    /// Override the `llvm-cov` executable.
    pub fn llvm_cov(mut self, path: impl Into<PathBuf>) -> Self {
        self.llvm_cov = path.into();
        self
    }

    /// Evaluate one case and return its replay result plus real source coverage.
    pub fn evaluate<F>(&mut self, run: F) -> Result<CoverageEvaluation, String>
    where
        F: FnOnce() -> Result<(), String>,
    {
        self.start_case()?.run(run)
    }

    /// Start collecting coverage for one case.
    ///
    /// This resets LLVM counters and returns a guard. Run the target while the guard is alive,
    /// then call [`LlvmCoverageCase::finish`] with the replay outcome to export coverage.
    pub fn start_case(&mut self) -> Result<LlvmCoverageCase<'_>, String> {
        let id = NEXT_PROFILE_ID.fetch_add(1, Ordering::Relaxed);
        let raw = self.profiles.join(format!("case-{id:016x}.profraw"));
        let indexed = self.profdata.join(format!("case-{id:016x}.profdata"));

        self.runtime.set_filename(&raw)?;
        self.runtime.reset_counters();
        Ok(LlvmCoverageCase {
            collector: self,
            raw,
            indexed,
        })
    }

    fn export_coverage(&self, raw: &Path, indexed: &Path) -> Result<CoverageSet, String> {
        let output = Command::new(&self.llvm_profdata)
            .arg("merge")
            .arg("-sparse")
            .arg(raw)
            .arg("-o")
            .arg(indexed)
            .output()
            .map_err(|error| {
                format!(
                    "failed to run {} merge: {error}",
                    self.llvm_profdata.display()
                )
            })?;
        ensure_success(&self.llvm_profdata, "merge", output)?;

        let mut command = Command::new(&self.llvm_cov);
        command
            .arg("export")
            .arg(&self.object)
            .arg(format!("-instr-profile={}", indexed.display()))
            .arg("--format=text");
        for source in &self.sources {
            command.arg(source);
        }

        let output = command.output().map_err(|error| {
            format!("failed to run {} export: {error}", self.llvm_cov.display())
        })?;
        let stdout = ensure_success(&self.llvm_cov, "export", output)?;
        coverage_from_export(&stdout)
    }
}

impl CoverageCapture for LlvmCoverage {
    type Token = (PathBuf, PathBuf);

    fn start_capture(&mut self) -> Result<Self::Token, String> {
        let id = NEXT_PROFILE_ID.fetch_add(1, Ordering::Relaxed);
        let raw = self.profiles.join(format!("case-{id:016x}.profraw"));
        let indexed = self.profdata.join(format!("case-{id:016x}.profdata"));

        self.runtime.set_filename(&raw)?;
        self.runtime.reset_counters();
        Ok((raw, indexed))
    }

    fn finish_capture(
        &mut self,
        token: Self::Token,
        outcome: Result<(), String>,
    ) -> Result<CoverageEvaluation, String> {
        let (raw, indexed) = token;
        self.runtime.write_file(&raw)?;
        let coverage = self.export_coverage(&raw, &indexed)?;
        Ok(CoverageEvaluation::from_outcome(outcome, coverage))
    }
}

/// Active LLVM source-coverage collection for a single case.
///
/// Dropping this guard does not export coverage. Call [`finish`](Self::finish) after the target
/// replay completes, or [`run`](Self::run) to execute and finish in one step.
pub struct LlvmCoverageCase<'a> {
    collector: &'a mut LlvmCoverage,
    raw: PathBuf,
    indexed: PathBuf,
}

impl LlvmCoverageCase<'_> {
    /// Run the target, convert panics to failing outcomes, and export coverage.
    pub fn run<F>(self, run: F) -> Result<CoverageEvaluation, String>
    where
        F: FnOnce() -> Result<(), String>,
    {
        let outcome = match catch_unwind(AssertUnwindSafe(run)) {
            Ok(outcome) => outcome,
            Err(payload) => Err(panic_message(payload)),
        };
        self.finish(outcome)
    }

    /// Finish this case by writing and exporting its coverage profile.
    pub fn finish(self, outcome: Result<(), String>) -> Result<CoverageEvaluation, String> {
        self.collector.runtime.write_file(&self.raw)?;
        let coverage = self.collector.export_coverage(&self.raw, &self.indexed)?;
        Ok(CoverageEvaluation::from_outcome(outcome, coverage))
    }
}

/// In-process LLVM counter collector for fast coverage-guided exploration.
///
/// This collector reads LLVM's raw coverage counter array directly after each replay. It is
/// cheaper than exporting source regions for every case, and the resulting IDs are suitable as
/// greybox search features.
pub struct LlvmCounterCoverage {
    counter_count: usize,
}

impl LlvmCounterCoverage {
    /// Initialize counter collection from the current instrumented binary.
    pub fn new() -> Result<Self, String> {
        let (begin, end) = counter_bounds()?;
        let counter_count = unsafe { end.offset_from(begin) };
        if counter_count <= 0 {
            return Err("LLVM coverage runtime reported no counters".to_string());
        }
        Ok(Self {
            counter_count: counter_count as usize,
        })
    }

    /// Reset counters, run one case, and return its outcome plus covered counter IDs.
    pub fn evaluate<F>(&mut self, run: F) -> Result<CoverageEvaluation, String>
    where
        F: FnOnce() -> Result<(), String>,
    {
        self.start_case().run(run)
    }

    /// Start collecting raw counter coverage for one case.
    pub fn start_case(&mut self) -> LlvmCounterCoverageCase<'_> {
        reset_counters();
        LlvmCounterCoverageCase { collector: self }
    }
}

impl CoverageCapture for LlvmCounterCoverage {
    type Token = ();

    fn start_capture(&mut self) -> Result<Self::Token, String> {
        reset_counters();
        Ok(())
    }

    fn finish_capture(
        &mut self,
        _token: Self::Token,
        outcome: Result<(), String>,
    ) -> Result<CoverageEvaluation, String> {
        let coverage = counter_coverage(self.counter_count)?;
        Ok(CoverageEvaluation::from_outcome(outcome, coverage))
    }
}

/// Active LLVM counter-coverage collection for a single case.
pub struct LlvmCounterCoverageCase<'a> {
    collector: &'a mut LlvmCounterCoverage,
}

impl LlvmCounterCoverageCase<'_> {
    /// Run the target, convert panics to failing outcomes, and read counter coverage.
    pub fn run<F>(self, run: F) -> Result<CoverageEvaluation, String>
    where
        F: FnOnce() -> Result<(), String>,
    {
        let outcome = match catch_unwind(AssertUnwindSafe(run)) {
            Ok(outcome) => outcome,
            Err(payload) => Err(panic_message(payload)),
        };
        self.finish(outcome)
    }

    /// Finish this case by reading the current nonzero LLVM counters.
    pub fn finish(self, outcome: Result<(), String>) -> Result<CoverageEvaluation, String> {
        let coverage = counter_coverage(self.collector.counter_count)?;
        Ok(CoverageEvaluation::from_outcome(outcome, coverage))
    }
}

/// Reset the process-wide LLVM coverage counters.
///
/// This is useful when a coverage-guided runner isolates probe coverage during search, then
/// replays an accepted corpus at the end so the process-exit `.profraw` contains cumulative
/// coverage for `llvm-cov` reports.
pub fn reset_process_counters() {
    reset_counters();
}

struct LlvmProfileRuntime {
    filename: Option<CString>,
}

impl LlvmProfileRuntime {
    fn new() -> Self {
        Self { filename: None }
    }

    fn reset_counters(&self) {
        reset_counters();
    }

    fn set_filename(&mut self, path: &Path) -> Result<(), String> {
        let filename = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| format!("profile path contains an interior NUL: {}", path.display()))?;
        self.filename = Some(filename);
        unsafe {
            __llvm_profile_set_filename(
                self.filename
                    .as_ref()
                    .expect("filename was just initialized")
                    .as_ptr(),
            );
        }
        Ok(())
    }

    fn write_file(&self, path: &Path) -> Result<(), String> {
        let status = unsafe { __llvm_profile_write_file() };
        if status == 0 {
            Ok(())
        } else {
            Err(format!(
                "__llvm_profile_write_file failed with status {status} for {}",
                path.display()
            ))
        }
    }
}

unsafe extern "C" {
    fn __llvm_profile_reset_counters();
    fn __llvm_profile_set_filename(filename: *const c_char);
    fn __llvm_profile_write_file() -> c_int;
    fn __llvm_profile_begin_counters() -> *const u64;
    fn __llvm_profile_end_counters() -> *const u64;
}

fn reset_counters() {
    unsafe {
        __llvm_profile_reset_counters();
    }
}

fn counter_bounds() -> Result<(*const u64, *const u64), String> {
    let begin = unsafe { __llvm_profile_begin_counters() };
    let end = unsafe { __llvm_profile_end_counters() };
    if begin.is_null() || end.is_null() {
        return Err("LLVM coverage runtime returned null counter bounds".to_string());
    }
    Ok((begin, end))
}

fn counter_coverage(counter_count: usize) -> Result<CoverageSet, String> {
    let (begin, end) = counter_bounds()?;
    let current_count = unsafe { end.offset_from(begin) };
    if current_count < 0 || current_count as usize != counter_count {
        return Err(format!(
            "LLVM coverage counter count changed from {counter_count} to {current_count}"
        ));
    }

    let mut coverage = CoverageSet::new();
    for index in 0..counter_count {
        let counter = unsafe { std::ptr::read_volatile(begin.add(index)) };
        if counter != 0 {
            coverage.insert(CoverageId(index as u64));
        }
    }
    Ok(coverage)
}

fn ensure_success(
    program: &Path,
    subcommand: &str,
    output: std::process::Output,
) -> Result<Vec<u8>, String> {
    if output.status.success() {
        return Ok(output.stdout);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "{} {subcommand} failed with status {}: {stderr}",
        program.display(),
        output.status
    ))
}

fn coverage_from_export(bytes: &[u8]) -> Result<CoverageSet, String> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("failed to parse llvm-cov export JSON: {error}"))?;
    let mut coverage = CoverageSet::new();
    let data = value
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| "llvm-cov export JSON missing data array".to_string())?;

    for export in data {
        let Some(files) = export.get("files").and_then(Value::as_array) else {
            continue;
        };
        for file in files {
            let filename = file
                .get("filename")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            let Some(segments) = file.get("segments").and_then(Value::as_array) else {
                continue;
            };
            for segment in segments {
                let Some(segment) = segment.as_array() else {
                    continue;
                };
                let line = segment.first().and_then(Value::as_u64).unwrap_or(0);
                let column = segment.get(1).and_then(Value::as_u64).unwrap_or(0);
                let count = segment.get(2).and_then(Value::as_u64).unwrap_or(0);
                let has_count = segment.get(3).and_then(Value::as_bool).unwrap_or(true);
                let is_region_entry = segment.get(4).and_then(Value::as_bool).unwrap_or(true);
                if count > 0 && has_count && is_region_entry {
                    coverage.insert(region_id(filename, line, column));
                }
            }
        }
    }

    Ok(coverage)
}

fn region_id(filename: &str, line: u64, column: u64) -> CoverageId {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in filename.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    for byte in line.to_le_bytes().into_iter().chain(column.to_le_bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    CoverageId(hash)
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        format!("panic: {message}")
    } else if let Some(message) = payload.downcast_ref::<String>() {
        format!("panic: {message}")
    } else {
        "panic with non-string payload".to_string()
    }
}
