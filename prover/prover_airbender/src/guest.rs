//! The guest binary and its runs on Airbender's RISC-V simulator.
//!
//! The simulator decodes the guest as the prover does: the base layer proves the user program on
//! the full-unsigned machine (RV32IM without mulh, mulhsu, div and rem), so a binary that executes
//! one of those fails here too instead of panicking the prover.

use eyre::{bail, eyre, Result};
use field::baby_bear::base::BabyBearField;
use riscv_transpiler::abstractions::non_determinism::QuasiUARTSource;
use riscv_transpiler::common_constants::rom::ROM_SECOND_WORD_BITS;
use riscv_transpiler::common_constants::{INITIAL_TIMESTAMP, TIMESTAMP_STEP};
use riscv_transpiler::ir::simple_instruction_set::{preprocess_bytecode, Instruction};
use riscv_transpiler::ir::FullUnsignedMachineDecoderConfig;
use riscv_transpiler::vm::{
    DelegationsCounters, FlamegraphConfig, RamWithRomRegion, SimpleTape, State,
    VmFlamegraphProfiler, VM,
};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// RAM bound of the simulator in bytes: the guest's 1 GiB memory map.
const RAM_BOUND: usize = 1 << 30;

/// One delegation call per run head: a jump into the middle of a delegation run is illegal, as in
/// airbender-host's simulator.
const PROTECT_AGAINST_MID_DELEGATION_JUMPS: bool = true;

/// The guest's `.bin` (ROM image) and `.text` (instructions) files.
#[derive(Clone, Debug)]
pub struct GuestFiles {
    pub bin: PathBuf,
    pub text: PathBuf,
    pub elf: PathBuf,
}

impl GuestFiles {
    /// The files next to `base`, a path without extension (a trailing `.bin` is dropped).
    pub fn at(base: &Path) -> Result<Self> {
        let base = if base.extension().is_some_and(|e| e == "bin") {
            base.with_extension("")
        } else {
            base.to_path_buf()
        };
        let with = |ext: &str| PathBuf::from(format!("{}.{ext}", base.display()));
        let files = Self {
            bin: with("bin"),
            text: with("text"),
            elf: with("elf"),
        };
        for path in [&files.bin, &files.text] {
            if !path.is_file() {
                bail!("guest file not found: {}", path.display());
            }
        }
        Ok(files)
    }

    pub fn bin_str(&self) -> Result<String> {
        utf8(&self.bin)
    }

    pub fn text_str(&self) -> Result<String> {
        utf8(&self.text)
    }
}

fn utf8(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| eyre!("path {} is not valid UTF-8", path.display()))
}

/// The guest, decoded once for any number of simulator runs.
pub struct Guest {
    pub files: GuestFiles,
    bin_words: Vec<u32>,
    instructions: Vec<Instruction>,
    /// PC of the self-loop that ends the guest's exit sequence (finish_success). Every other way
    /// the guest stops (finish_error, fatal(), abort, the trap handler) is a self-loop elsewhere.
    pub exit_pc: u32,
}

/// The machine state at the end of a simulator run.
#[derive(Clone, Debug)]
pub struct RunOutcome {
    pub cycles: u64,
    /// The run parked in a self-loop before the cycle limit.
    pub reached_end: bool,
    pub final_pc: u32,
    /// The guest's public output: registers a0..a7.
    pub output: [u32; 8],
    pub elapsed: Duration,
}

impl RunOutcome {
    /// The run ended at the guest's exit point, the only successful end.
    pub fn succeeded(&self, exit_pc: u32) -> bool {
        self.reached_end && self.final_pc == exit_pc
    }

    pub fn cycles_per_sec(&self) -> u64 {
        let secs = self.elapsed.as_secs_f64();
        if secs > 0.0 {
            (self.cycles as f64 / secs) as u64
        } else {
            0
        }
    }
}

impl Guest {
    pub fn load(files: GuestFiles) -> Result<Self> {
        let (_, bin_words) = setups::read_binary(&files.bin);
        let (_, text_words) = setups::read_binary(&files.text);
        let instructions = preprocess_bytecode::<
            FullUnsignedMachineDecoderConfig,
            PROTECT_AGAINST_MID_DELEGATION_JUMPS,
        >(&text_words);
        let exit_pc = catch_unwind(|| setups::program_setups::find_binary_exit_point(&bin_words))
            .map_err(|_| eyre!("{} has no unique exit sequence", files.bin.display()))?;
        Ok(Self {
            files,
            bin_words,
            instructions,
            exit_pc,
        })
    }

    /// Runs the guest on `oracle` (the input words it reads from CSR 0x7C0) for at most
    /// `max_cycles` cycles, with a flamegraph written to `flamegraph` if given (slower).
    ///
    /// The simulator panics on an instruction the prover's machine cannot execute (a signed
    /// multiply or divide, among others) and on a read past the input: such a run is an error.
    pub fn run(
        &self,
        oracle: Vec<u32>,
        max_cycles: usize,
        flamegraph: Option<&Path>,
    ) -> Result<RunOutcome> {
        let mut source = QuasiUARTSource::new_with_reads(oracle);
        let tape = SimpleTape::new(&self.instructions);
        let mut ram = RamWithRomRegion::<{ ROM_SECOND_WORD_BITS }>::from_rom_content(
            &self.bin_words,
            RAM_BOUND,
        );
        let mut state = State::initial_with_counters(DelegationsCounters::default());

        let mut profiler = match flamegraph {
            Some(svg) => Some(
                VmFlamegraphProfiler::new(FlamegraphConfig::new(
                    self.files.elf.clone(),
                    svg.to_path_buf(),
                ))
                .map_err(|e| eyre!("flamegraph init: {e}"))?,
            ),
            None => None,
        };

        let started = Instant::now();
        let finished = catch_unwind(AssertUnwindSafe(|| match profiler.as_mut() {
            Some(profiler) => VM::<DelegationsCounters>::run_basic_unrolled_with_flamegraph::<
                _,
                _,
                _,
                BabyBearField,
            >(
                &mut state,
                &mut ram,
                &mut (),
                &tape,
                max_cycles,
                &mut source,
                profiler,
            )
            .map_err(|e| eyre!("flamegraph execution: {e}")),
            None => Ok(VM::<DelegationsCounters>::run_basic_unrolled::<
                _,
                _,
                _,
                BabyBearField,
            >(
                &mut state,
                &mut ram,
                &mut (),
                &tape,
                max_cycles,
                &mut source,
            )),
        }))
        .map_err(|payload| {
            eyre!(
                "the simulator stopped at pc 0x{:08x}: {}",
                state.pc,
                panic_message(payload.as_ref())
            )
        })??;
        let elapsed = started.elapsed();

        if let (Some(profiler), Some(svg)) = (profiler, flamegraph) {
            let stats = profiler.stats();
            eprintln!(
                "Flamegraph: {} samples collected / {} total, written to {}",
                stats.samples_collected,
                stats.samples_total,
                svg.display()
            );
        }

        Ok(RunOutcome {
            cycles: (state.timestamp - INITIAL_TIMESTAMP) / TIMESTAMP_STEP,
            reached_end: finished,
            final_pc: state.pc,
            output: std::array::from_fn(|i| state.registers[10 + i].value),
            elapsed,
        })
    }
}

pub fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}
