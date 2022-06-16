//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use core::time::Duration;
use std::{env, path::PathBuf};

use libafl::{
    bolts::{
        current_nanos,
        rands::StdRand,
        shmem::{ShMem, ShMemProvider, StdShMemProvider},
        tuples::{tuple_list, Merge},
        AsSlice,
    },
    corpus::{
        Corpus, IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus, PowerQueueCorpusScheduler,
    },
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::scheduled::{havoc_mutations, tokens_mutations, StdScheduledMutator},
    observers::{ConstMapObserver, HitcountsMapObserver, TimeObserver},
    stages::{
        calibrate::CalibrationStage,
        power::{PowerMutationalStage, PowerSchedule},
    },
    state::{HasCorpus, StdState},
    Error,
};

use libafl_targets::{libfuzzer_initialize, libfuzzer_test_one_input};

const MAP_SIZE: usize = 65536;

extern "C" {
    fn kfx_teardown();
}


/// The main fn, `no_mangle` as it is a C main
#[cfg(not(test))]
#[no_mangle]
pub fn libafl_main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    //RegistryBuilder::register::<Tokens>();

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    // The default, OS-specific privider for shared memory
    let mut shmem_provider = StdShMemProvider::new().unwrap();
    // The coverage map shared between observer and executor
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    // let the forkserver know the shmid
    shmem.write_to_env("__AFL_SHM_ID").unwrap();

    fuzz(
        &[PathBuf::from("./corpus")],
        PathBuf::from("./crashes"),
        &mut shmem,
    )
    .expect("An error occurred while fuzzing");
}

/// The actual fuzzer
fn fuzz(
    corpus_dirs: &[PathBuf],
    objective_dir: PathBuf,
    shmem: &mut impl ShMem,
) -> Result<(), Error> {
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let monitor = MultiMonitor::new(|s| println!("{}", s));

    let mut event_mgr = SimpleEventManager::new(monitor);

    let shmem_buf = shmem.as_mut_slice();

    // Create an observation channel using the signals map
    let edges_observer = HitcountsMapObserver::new(ConstMapObserver::<_, MAP_SIZE>::new(
        "shared_mem",
        shmem_buf,
    ));

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // The state of the edges feedback.
    let feedback_state = MapFeedbackState::with_observer(&edges_observer);

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::new_tracking(&feedback_state, &edges_observer, true, false),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new_with_observer(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    let objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

    // If not restarting, create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        //InMemoryCorpus::new(),
        // We keep the corups on disk for testing
        OnDiskCorpus::new(PathBuf::from("./gencorp")).unwrap(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(objective_dir).unwrap(),
        // States of the feedbacks.
        // They are the data related to the feedbacks that you want to persist in the State.
        tuple_list!(feedback_state),
    );

    // Setup a basic mutator with a mutational stage

    let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));

    let calibration = CalibrationStage::new(&mut state, &edges_observer);
    let power = PowerMutationalStage::new(mutator, PowerSchedule::FAST, &edges_observer);

    let mut stages = tuple_list!(calibration, power);

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(PowerQueueCorpusScheduler::new());

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        if libfuzzer_test_one_input(buf) != 0 {
            ExitKind::Crash // Non-zero return means that VMI detected a sink
        } else {
            ExitKind::Ok
        }
    };

    // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
    let mut executor = TimeoutExecutor::new(
        InProcessExecutor::new(
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut event_mgr,
        )?,
        // 10 seconds timeout
        Duration::new(10, 0),
    );

    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
    let args: Vec<String> = env::args().collect();
    if libfuzzer_initialize(&args) == -1 {
        // The command line arguments probably weren't acceptable by kfx
        println!("Warning: LLVMFuzzerInitialize failed with -1");
        return Err(Error::ShuttingDown);
    }

    println!("Corpus size: {}", state.corpus().count());
    // In case the corpus is empty (on first run), reset
    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut event_mgr, corpus_dirs)
            .unwrap_or_else(|_| panic!("Failed to load initial corpus at {:?}", &corpus_dirs));
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    // This fuzzer restarts after 1 mio `fuzz_one` executions.
    // Each fuzz_one will internally do many executions of the target.
    // If your target is very instable, setting a low count here may help.
    // However, you will lose a lot of performance that way.
    let iters = 1_000_000;

    fuzzer.fuzz_loop_for(
        &mut stages,
        &mut executor,
        &mut state,
        &mut event_mgr,
        iters,
    )?;

    unsafe { kfx_teardown(); }

    Ok(())
}
