//! A small mutational fuzzer that needs nothing but the standard library.
//!
//! It is not coverage-guided (that needs compiler instrumentation, which is
//! what the cargo-fuzz harness in `fuzz/` adds on nightly). Instead each
//! target returns a cheap *shape* of what it did — which error, how many
//! results, which branch — and inputs that produce a new shape join the
//! corpus. That keeps the search moving into new behaviour without
//! instrumentation, and it is deterministic for a given seed, so every
//! failure is reproducible from the seed and iteration printed with it.
//!
//! A target fails by panicking: a real panic in the code under test, or a
//! broken invariant asserted by the target. Hangs are caught by a watchdog
//! thread that prints the input and exits.

use std::collections::HashSet;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// One fuzz target.
pub struct Target {
    /// Name used on the command line and for corpus directories.
    pub name: &'static str,
    /// What the target covers, one line.
    pub about: &'static str,
    /// Run one input. Returns a shape value; panics on a failure.
    pub run: fn(&[u8]) -> u64,
    /// Built-in seed inputs (the on-disk corpus is added to these).
    pub seeds: fn() -> Vec<Vec<u8>>,
    /// Tokens the mutator splices in (tags, keys, delimiters).
    pub dict: &'static [&'static [u8]],
    /// Relative cost: the default iteration budget is divided by this.
    pub cost: u32,
}

/// A failing input.
#[derive(Debug)]
pub struct Failure {
    /// Target name.
    pub target: &'static str,
    /// The input that failed.
    pub input: Vec<u8>,
    /// Panic message or "slow".
    pub message: String,
    /// Iteration at which it was found (0 for corpus replay).
    pub iteration: u64,
    /// Where the input was saved, if it was.
    pub saved: Option<PathBuf>,
}

/// Result of a campaign.
#[derive(Debug, Default)]
pub struct Report {
    /// Executions run.
    pub execs: u64,
    /// Distinct shapes seen.
    pub shapes: usize,
    /// Final corpus size.
    pub corpus: usize,
    /// Failures found (deduplicated by message).
    pub failures: Vec<Failure>,
}

/// Campaign settings.
#[derive(Clone, Debug)]
pub struct Config {
    /// RNG seed.
    pub seed: u64,
    /// Stop after this many executions (after corpus replay).
    pub iterations: u64,
    /// Stop after this long, whichever comes first.
    pub time_budget: Duration,
    /// Largest input the mutator produces.
    pub max_len: usize,
    /// An execution slower than this is a failure.
    pub slow: Duration,
    /// Extra corpus directory (seeds and regressions) to replay and extend.
    pub corpus_dir: Option<PathBuf>,
    /// Where failing inputs are written.
    pub crash_dir: Option<PathBuf>,
    /// Stop at the first failure.
    pub stop_on_failure: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            seed: 0x1ab_c0a7,
            iterations: 2_000,
            time_budget: Duration::from_secs(60),
            max_len: 64 * 1024,
            slow: Duration::from_secs(2),
            corpus_dir: None,
            crash_dir: None,
            stop_on_failure: false,
        }
    }
}

/// xorshift64*: fast, deterministic, good enough to pick mutations.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    /// Seeded generator (a zero seed is remapped).
    pub fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    /// Next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// Uniform in `0..n` (`n` > 0).
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() % n as u64) as usize
    }
    /// True with probability 1/n.
    pub fn one_in(&mut self, n: usize) -> bool {
        self.below(n) == 0
    }
}

const INTERESTING: &[u8] = &[
    0, 1, 0x7f, 0x80, 0xff, b'\n', b'\r', b'\t', b' ', b'"', b'\'', b'\\', b'`', b'$', b'=', b'<',
    b'>', b'&', b';', b'/', b'.', b'-', b'{', b'}', b'[', b']', b',', b':', 0x1b,
];

const UNICODE: &[&str] = &[
    "\u{0}",
    "\u{1b}[2J",
    "\u{85}",
    "\u{2028}",
    "\u{202e}",
    "\u{feff}",
    "é",
    "\u{10ffff}",
    "𝔘",
    "ﬀ",
    "İ",
    "\u{200b}",
];

/// Apply one to four random mutations.
pub fn mutate(
    rng: &mut Rng,
    input: &[u8],
    corpus: &[Vec<u8>],
    dict: &[&[u8]],
    max: usize,
) -> Vec<u8> {
    let mut out = input.to_vec();
    let rounds = 1 + rng.below(4);
    for _ in 0..rounds {
        let len = out.len();
        match rng.below(13) {
            // Flip one bit.
            0 if len > 0 => {
                let i = rng.below(len);
                out[i] ^= 1 << rng.below(8);
            }
            // Replace a byte with an interesting one.
            1 if len > 0 => {
                let i = rng.below(len);
                out[i] = INTERESTING[rng.below(INTERESTING.len())];
            }
            // Insert random bytes.
            2 => {
                let i = rng.below(len + 1);
                let n = 1 + rng.below(8);
                let bytes: Vec<u8> = (0..n).map(|_| rng.next_u64() as u8).collect();
                out.splice(i..i, bytes);
            }
            // Delete a range.
            3 if len > 0 => {
                let i = rng.below(len);
                let n = 1 + rng.below((len - i).min(64));
                out.drain(i..i + n);
            }
            // Duplicate a range in place.
            4 if len > 0 => {
                let i = rng.below(len);
                let n = 1 + rng.below((len - i).min(256));
                let chunk = out[i..i + n].to_vec();
                let at = rng.below(out.len() + 1);
                out.splice(at..at, chunk);
            }
            // Insert a dictionary token.
            5 | 6 if !dict.is_empty() => {
                let tok = dict[rng.below(dict.len())];
                let i = rng.below(len + 1);
                out.splice(i..i, tok.iter().copied());
            }
            // Overwrite with a dictionary token.
            7 if !dict.is_empty() && len > 0 => {
                let tok = dict[rng.below(dict.len())];
                let i = rng.below(len);
                let end = (i + tok.len()).min(len);
                out.splice(i..end, tok.iter().copied());
            }
            // Splice with another corpus entry.
            8 if !corpus.is_empty() => {
                let other = &corpus[rng.below(corpus.len())];
                let cut = rng.below(len + 1);
                let from = rng.below(other.len() + 1);
                out.truncate(cut);
                out.extend_from_slice(&other[from..]);
            }
            // Truncate.
            9 if len > 0 => out.truncate(rng.below(len)),
            // Insert a tricky Unicode sequence.
            10 => {
                let s = UNICODE[rng.below(UNICODE.len())].as_bytes();
                let i = rng.below(len + 1);
                out.splice(i..i, s.iter().copied());
            }
            // Repeat a token many times (performance cliffs, deep nesting).
            11 => {
                let tok: Vec<u8> = if !dict.is_empty() && rng.one_in(2) {
                    dict[rng.below(dict.len())].to_vec()
                } else if len > 0 {
                    let i = rng.below(len);
                    out[i..(i + 1 + rng.below(8)).min(len)].to_vec()
                } else {
                    vec![b'[']
                };
                let times = [16, 256, 1024, 4096][rng.below(4)];
                let i = rng.below(len + 1);
                let block: Vec<u8> = tok
                    .iter()
                    .copied()
                    .cycle()
                    .take(tok.len() * times)
                    .collect();
                out.splice(i..i, block);
            }
            // Swap two bytes / set a run of one byte.
            _ if len > 1 => {
                let a = rng.below(len);
                let b = rng.below(len);
                out.swap(a, b);
            }
            _ => out.push(rng.next_u64() as u8),
        }
        if out.len() > max {
            out.truncate(max);
        }
    }
    out
}

/// FNV-1a, for file names of saved inputs.
pub fn fnv(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in data {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// Read every regular file in `dir` (sorted), or nothing.
pub fn read_dir_inputs(dir: &Path) -> Vec<Vec<u8>> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    paths.sort();
    paths
        .into_iter()
        .filter_map(|p| std::fs::read(p).ok())
        .collect()
}

/// Run a target once, catching a panic. `Err` carries the panic message.
pub fn exec(target: &Target, input: &[u8]) -> Result<u64, String> {
    match panic::catch_unwind(AssertUnwindSafe(|| (target.run)(input))) {
        Ok(shape) => Ok(shape),
        Err(e) => Err(if let Some(s) = e.downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = e.downcast_ref::<&str>() {
            (*s).to_owned()
        } else {
            "panic with a non-string payload".to_owned()
        }),
    }
}

/// Silence the default panic hook while fuzzing (each panic is reported
/// once by the engine instead), and restore it afterwards.
type PanicHook = Box<dyn Fn(&panic::PanicHookInfo<'_>) + Sync + Send + 'static>;

struct QuietPanics(Option<PanicHook>);

impl QuietPanics {
    fn new() -> Self {
        let prev = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        QuietPanics(Some(prev))
    }
}

impl Drop for QuietPanics {
    fn drop(&mut self) {
        if let Some(prev) = self.0.take() {
            panic::set_hook(prev);
        }
    }
}

/// Watchdog: if one execution runs longer than `limit`, print the input
/// (escaped) and exit the process, since a hang cannot be unwound.
struct Watchdog {
    stop: Arc<AtomicBool>,
    started_ms: Arc<AtomicU64>,
    current: Arc<Mutex<Vec<u8>>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Watchdog {
    fn start(target: &'static str, limit: Duration, crash_dir: Option<PathBuf>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let started_ms = Arc::new(AtomicU64::new(0));
        let current = Arc::new(Mutex::new(Vec::new()));
        let epoch = Instant::now();
        let (s, st, cur) = (stop.clone(), started_ms.clone(), current.clone());
        let handle = std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(50));
                let t0 = st.load(Ordering::Relaxed);
                if t0 == 0 {
                    continue;
                }
                let now = epoch.elapsed().as_millis() as u64;
                if now.saturating_sub(t0) > limit.as_millis() as u64 {
                    let input = cur.lock().map(|g| g.clone()).unwrap_or_default();
                    eprintln!(
                        "lcoat-fuzz: {target}: execution exceeded {limit:?} (hang); input ({} bytes): {:?}",
                        input.len(),
                        String::from_utf8_lossy(&input[..input.len().min(512)])
                    );
                    if let Some(dir) = &crash_dir {
                        let _ = std::fs::create_dir_all(dir);
                        let p = dir.join(format!("{target}-hang-{:016x}", fnv(&input)));
                        let _ = std::fs::write(&p, &input);
                        eprintln!("lcoat-fuzz: saved {}", p.display());
                    }
                    std::process::exit(3);
                }
            }
        });
        let _ = epoch;
        Watchdog {
            stop,
            started_ms,
            current,
            handle: Some(handle),
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Run a campaign: replay seeds and the corpus directory, then mutate.
pub fn fuzz(target: &'static Target, cfg: &Config) -> Report {
    let _quiet = QuietPanics::new();
    // The watchdog limit is generous: `slow` is the reported failure, the
    // watchdog only stops a true hang.
    let dog = Watchdog::start(target.name, cfg.slow * 10, cfg.crash_dir.clone());
    let epoch = Instant::now();
    let mut rng = Rng::new(cfg.seed ^ fnv(target.name.as_bytes()));
    let mut report = Report::default();
    let mut shapes: HashSet<u64> = HashSet::new();
    let mut seen_messages: HashSet<String> = HashSet::new();

    let mut corpus: Vec<Vec<u8>> = (target.seeds)();
    if let Some(dir) = &cfg.corpus_dir {
        corpus.extend(read_dir_inputs(dir));
    }
    if corpus.is_empty() {
        corpus.push(Vec::new());
    }

    let budget = (cfg.iterations / u64::from(target.cost.max(1))).max(1);
    let replay = corpus.clone();
    let mut iteration: u64 = 0;
    let mut queue = replay.into_iter();
    loop {
        let (input, from_replay) = match queue.next() {
            Some(i) => (i, true),
            None => {
                if iteration >= budget || epoch.elapsed() >= cfg.time_budget {
                    break;
                }
                iteration += 1;
                let base = &corpus[rng.below(corpus.len())];
                (
                    mutate(&mut rng, base, &corpus, target.dict, cfg.max_len),
                    false,
                )
            }
        };
        if let Ok(mut g) = dog.current.lock() {
            g.clear();
            g.extend_from_slice(&input);
        }
        dog.started_ms
            .store(epoch.elapsed().as_millis().max(1) as u64, Ordering::Relaxed);
        let t0 = Instant::now();
        let result = exec(target, &input);
        let took = t0.elapsed();
        dog.started_ms.store(0, Ordering::Relaxed);
        report.execs += 1;

        let failure = match result {
            Err(msg) => Some(msg),
            Ok(_) if took > cfg.slow => Some(format!(
                "slow: {took:?} for a {}-byte input (limit {:?})",
                input.len(),
                cfg.slow
            )),
            Ok(shape) => {
                if shapes.insert(shape) && !from_replay && corpus.len() < 4096 {
                    corpus.push(input.clone());
                }
                None
            }
        };
        if let Some(message) = failure
            && seen_messages.insert(message.clone())
        {
            let saved = cfg.crash_dir.as_ref().and_then(|dir| {
                std::fs::create_dir_all(dir).ok()?;
                let p = dir.join(format!("{}-{:016x}", target.name, fnv(&input)));
                std::fs::write(&p, &input).ok()?;
                Some(p)
            });
            report.failures.push(Failure {
                target: target.name,
                input,
                message,
                iteration: if from_replay { 0 } else { iteration },
                saved,
            });
            if cfg.stop_on_failure {
                break;
            }
        }
    }
    report.shapes = shapes.len();
    report.corpus = corpus.len();
    drop(dog);
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_is_deterministic_and_mutate_respects_max() {
        let mut a = Rng::new(7);
        let mut b = Rng::new(7);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        let mut r = Rng::new(1);
        let corpus = vec![b"hello".to_vec()];
        for _ in 0..2_000 {
            let m = mutate(&mut r, b"seed input", &corpus, &[b"<port ", b"\""], 300);
            assert!(m.len() <= 300);
        }
    }
}
