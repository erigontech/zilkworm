//! Proving with Airbender v3's prover_pipeline: a `ProgramProver` that proves the guest up to the
//! final unified recursion layer, at 100-bit security.
//!
//! The prover lives on a thread of its own with a 1 GiB stack (the pipeline runs the recursion
//! verifiers natively, which needs it). A panic while proving is not unwind safe: it ends that
//! thread and the prover with it, so the block fails and a new prover is built for the next one.
//!
//! Adapted from matter-labs/airbender-platform crates/airbender-host/src/prover/gpu_prover.rs and
//! matter-labs/ethereum-prover ethereum_prover/src/prover/gpu_prover.rs (MIT OR Apache-2.0).

use crate::guest::{panic_message, GuestFiles};
use crate::public_output::{self, Expected};
use alloy_primitives::B256;
use eyre::{bail, eyre, Result};
use prover_pipeline::{
    ProgramProver, ProgramProverConfig, ProgramSource, ProofArtifact, ProofTarget, ProverBackend,
    MAX_EXECUTION_CYCLES,
};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tracing::{error, info};

/// Stack of the prover thread.
const PROVER_STACK_SIZE: usize = 1 << 30;

/// The cycle limit the prover can take: its JIT encodes timestamps in 32 bits.
pub const MAX_PROVABLE_CYCLES: usize = MAX_EXECUTION_CYCLES;

#[derive(Clone, Debug)]
pub struct ProverSettings {
    pub guest: GuestFiles,
    pub backend: ProverBackend,
    /// The proved run stops here; a longer one does not reach the guest's exit point.
    pub cycles_bound: u32,
}

impl ProverSettings {
    /// `max_cycles` is clamped to what the prover can take.
    pub fn new(guest: GuestFiles, backend: ProverBackend, max_cycles: usize) -> Result<Self> {
        if backend == ProverBackend::Gpu && !cfg!(feature = "gpu") {
            bail!("this prover was built without the gpu feature: no GPU backend (prove takes --backend cpu)");
        }
        Ok(Self {
            guest,
            backend,
            cycles_bound: max_cycles.min(MAX_PROVABLE_CYCLES) as u32,
        })
    }

    fn build(&self) -> Result<ProgramProver, String> {
        let source = ProgramSource::from_paths(
            self.guest.bin_str().map_err(|e| e.to_string())?,
            Some(self.guest.text_str().map_err(|e| e.to_string())?),
        );
        ProgramProver::new(
            source,
            ProgramProverConfig {
                target: ProofTarget::RecursionUnified,
                backend: self.backend,
                cycles_bound: Some(self.cycles_bound),
                ..ProgramProverConfig::default()
            },
        )
    }
}

/// A proof of one block.
pub struct ProvedBlock {
    pub artifact: ProofArtifact,
    /// Time spent proving.
    pub elapsed: Duration,
}

impl ProvedBlock {
    /// Cycles the guest executed (the base layer).
    pub fn program_cycles(&self) -> u64 {
        self.artifact.program_cycles
    }

    /// The guest's public output: registers a0..a7 at the end of the proven run.
    pub fn output(&self) -> [u32; 8] {
        output_words(&self.artifact)
    }

    pub fn proof_count(&self) -> usize {
        let counts = &self.artifact.proof_counts;
        counts.riscv_proof_count
            + counts.inits_and_teardowns_proof_count
            + counts.delegation_proof_count
    }
}

pub fn output_words(artifact: &ProofArtifact) -> [u32; 8] {
    std::array::from_fn(|i| artifact.proof.register_final_values[10 + i].value)
}

/// Accepts a proof only if it commits the input's block: an output of all zeroes means the
/// block execution failed inside the guest (unless no block is expected, as for EEST tests).
pub fn check_output(expected: &Expected, output: &[u32; 8]) -> Result<()> {
    if expected.block_hash != B256::ZERO && output.iter().all(|w| *w == 0) {
        bail!("the proof's output is all zeroes: the block execution failed inside the guest");
    }
    public_output::check(&expected.block_hash, output)
}

/// A reusable prover that rebuilds itself after a panic.
pub struct BlockProver {
    settings: ProverSettings,
    worker: Option<Worker>,
    next_batch_id: u64,
}

impl BlockProver {
    /// Builds the prover (the guest's and the recursion programs' precomputations).
    pub fn new(settings: ProverSettings) -> Result<Self> {
        let started = Instant::now();
        let worker = Worker::spawn(&settings)?;
        info!(
            "{:?} prover ready in {:.1}s (cycle bound {})",
            settings.backend,
            started.elapsed().as_secs_f64(),
            settings.cycles_bound
        );
        Ok(Self {
            settings,
            worker: Some(worker),
            next_batch_id: 0,
        })
    }

    /// Proves the guest on `input_words`. On a panic the prover is replaced before returning
    /// the block's error, outside the block's proving time.
    pub fn prove(&mut self, input_words: Vec<u32>) -> Result<ProvedBlock> {
        if self.worker.is_none() {
            // An earlier rebuild failed.
            self.worker = Some(Worker::spawn(&self.settings)?);
        }
        let batch_id = self.next_batch_id;
        self.next_batch_id += 1;

        let started = Instant::now();
        let result = self
            .worker
            .as_mut()
            .expect("a prover")
            .prove(batch_id, input_words);
        let elapsed = started.elapsed();
        match result {
            Ok(artifact) => Ok(ProvedBlock { artifact, elapsed }),
            Err(Failure::Error(err)) => Err(eyre!("proving failed: {err}")),
            Err(Failure::Panic(message)) => {
                error!("the prover panicked ({message}); replacing it");
                self.worker = None;
                match Worker::spawn(&self.settings) {
                    Ok(worker) => self.worker = Some(worker),
                    Err(err) => {
                        error!("rebuilding the prover failed, retrying at the next block: {err}")
                    }
                }
                Err(eyre!("the prover panicked: {message}"))
            }
        }
    }
}

enum Failure {
    /// The prover returned an error and can be used again.
    Error(String),
    /// The prover panicked: its thread, and the prover, are gone.
    Panic(String),
}

struct Request {
    batch_id: u64,
    input_words: Vec<u32>,
    reply: mpsc::Sender<Result<ProofArtifact, String>>,
}

/// The thread that owns one `ProgramProver`.
struct Worker {
    requests: Option<mpsc::Sender<Request>>,
    handle: Option<JoinHandle<()>>,
}

impl Worker {
    fn spawn(settings: &ProverSettings) -> Result<Self> {
        let (requests, request_rx) = mpsc::channel::<Request>();
        let (init_tx, init_rx) = mpsc::channel::<Result<(), String>>();
        let settings = settings.clone();
        let handle = std::thread::Builder::new()
            .name("airbender-prover".to_string())
            .stack_size(PROVER_STACK_SIZE)
            .spawn(move || {
                // All prover state stays on this thread, so a panic never unwinds through the
                // caller.
                let mut prover = match settings.build() {
                    Ok(prover) => prover,
                    Err(err) => {
                        let _ = init_tx.send(Err(err));
                        return;
                    }
                };
                if init_tx.send(Ok(())).is_err() {
                    return;
                }
                while let Ok(request) = request_rx.recv() {
                    let result = prover.prove_words(request.batch_id, request.input_words);
                    let _ = request.reply.send(result);
                }
            })
            .map_err(|e| eyre!("failed to spawn the prover thread: {e}"))?;

        let mut worker = Self {
            requests: Some(requests),
            handle: Some(handle),
        };
        match init_rx.recv() {
            Ok(Ok(())) => Ok(worker),
            Ok(Err(err)) => Err(eyre!("failed to build the prover: {err}")),
            Err(_) => Err(eyre!(
                "the prover panicked while being built: {}",
                worker.panic_message()
            )),
        }
    }

    fn prove(&mut self, batch_id: u64, input_words: Vec<u32>) -> Result<ProofArtifact, Failure> {
        let (reply, reply_rx) = mpsc::channel();
        let request = Request {
            batch_id,
            input_words,
            reply,
        };
        let sent = self
            .requests
            .as_ref()
            .map(|requests| requests.send(request).is_ok());
        if sent != Some(true) {
            return Err(Failure::Panic(self.panic_message()));
        }
        match reply_rx.recv() {
            Ok(Ok(artifact)) => Ok(artifact),
            Ok(Err(err)) => Err(Failure::Error(err)),
            Err(_) => Err(Failure::Panic(self.panic_message())),
        }
    }

    /// Joins the thread, which has ended, and returns its panic message.
    fn panic_message(&mut self) -> String {
        self.requests = None;
        match self.handle.take().map(JoinHandle::join) {
            Some(Err(payload)) => panic_message(payload.as_ref()),
            _ => "the prover thread exited".to_string(),
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Closing the channel ends the thread's loop.
        self.requests = None;
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
