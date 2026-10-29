//! One private, non-inherited Windows Job per run. No supervisor-wide Job.
//!
//! `process-wrap` supplies suspended spawn and resumes only after our admission
//! callback and its own nested Job assignment. Our separate kill-on-close Job
//! owns crash cleanup and supplies independent kernel membership observations.
//! Handles are never exposed; a scope admits exactly one initial process.
//!
//! A caller that installs the optional process-lifetime root Job before spawn
//! also contains the suspended child during initial assignment. Without that
//! root, a crash in this interval can leak a suspended process. This is not an
//! isolation boundary against other processes acting as the same OS user.

use process_wrap::std::{ChildWrapper, CommandWrap, JobObject};
use std::{
    io,
    os::windows::io::AsRawHandle,
    process::{Child, Command, ExitStatus},
    sync::OnceLock,
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;
use win32job::{ExtendedLimitInfo, Job};

const CLEANUP_BUDGET: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(10);
static ROOT: OnceLock<std::result::Result<Job, String>> = OnceLock::new();

/// Permanently place this process in a kill-on-close root Job. Every child
/// created afterwards inherits the Job unless an existing external Job permits
/// breakaway. This affects the whole process and its descendants, not just one
/// invocation; embedded callers must opt in deliberately. Failure is sticky and
/// must prevent a contained launch. The non-inherited handle stays open until
/// process termination; closing it sooner would terminate the caller itself.
pub fn install_process_root() -> io::Result<()> {
    ROOT.get_or_init(|| {
        let setup = || -> io::Result<Job> {
            let mut limits = ExtendedLimitInfo::new();
            limits.limit_kill_on_job_close();
            let job = Job::create_with_limit_info(&limits).map_err(job_error)?;
            job.assign_current_process().map_err(job_error)?;
            Ok(job)
        };
        setup().map_err(|error| error.to_string())
    })
    .as_ref()
    .map(|_| ())
    .map_err(|error| io::Error::other(error.clone()))
}

pub(crate) fn process_root_installed() -> bool {
    ROOT.get().is_some_and(std::result::Result::is_ok)
}

/// An unused local scope. Dropping it closes its sole Job handle.
pub struct WindowsJob {
    id: Uuid,
    job: Job,
}

impl WindowsJob {
    pub fn create() -> io::Result<Self> {
        let mut limits = ExtendedLimitInfo::new();
        limits.limit_kill_on_job_close();
        Ok(Self {
            id: Uuid::new_v4(),
            job: Job::create_with_limit_info(&limits).map_err(job_error)?,
        })
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Admit a suspended target, call `admit`, then let the wrapper resume it.
    ///
    /// The callback must durably record the owned PID before returning success.
    /// This backend owns Windows creation flags; flags set on `Command` are
    /// replaced. No caller-supplied wrapper or explicit suspension is allowed.
    /// An error is not a stop receipt: callers must preserve unresolved intent
    /// if they cannot independently establish which admission phase failed.
    pub fn spawn(
        self,
        command: Command,
        admit: impl FnOnce(u32) -> io::Result<()>,
    ) -> io::Result<JobChild> {
        let mut command = CommandWrap::from(command);
        command.wrap(JobObject);
        self.spawn_wrapped(command, |native| admit(native.id()))
    }

    // Private seam for failure injection. Production installs exactly JobObject;
    // tests may prepend a wrapper that always refuses before resume.
    fn spawn_wrapped(
        self,
        mut command: CommandWrap,
        admit: impl FnOnce(&Child) -> io::Result<()>,
    ) -> io::Result<JobChild> {
        let child = command.spawn_with(|command| {
            let child = SuspendedChild(Some(command.spawn()?));
            let native = child.as_child()?;
            // Borrow the owned process handle; never reopen a PID from storage.
            self.job
                .assign_process(native.as_raw_handle() as isize)
                .map_err(job_error)?;
            if self.job.query_process_id_list().map_err(job_error)? != [native.id() as usize] {
                return Err(io::Error::other("unexpected Job membership at admission"));
            }
            admit(native)?;
            child.release()
        })?;
        Ok(JobChild { scope: self, child })
    }
}

/// Owns the running scope. Drop requests termination through owned handles;
/// only `stop_and_observe` can report observed emptiness.
///
/// ```compile_fail
/// use agentswapper_core::supervision::windows_job::JobChild;
/// fn reuse(child: JobChild) {
///     let _ = child.stop_and_observe();
///     let _ = child.id(); // Stop consumes the scope on every outcome.
/// }
/// ```
pub struct JobChild {
    scope: WindowsJob,
    child: Box<dyn ChildWrapper>,
}

impl JobChild {
    pub fn scope_id(&self) -> Uuid {
        self.scope.id
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// Observe the initial process only. Its exit does not mean scope emptiness.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.inner_mut().try_wait()
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        // Exactly one wrapper is constructed here (JobObject). The immediate
        // inner is std Child; no caller can add wrappers or mutate this chain.
        // The dependency's recursive mutable accessor is unsafe, so avoid it.
        self.child.inner_mut().wait()
    }

    /// Terminate remaining local descendants and observe an empty Job within
    /// five seconds. Consumes admission authority even on failure. Query errors,
    /// including membership-buffer overflow, never produce an empty receipt.
    pub fn stop_and_observe(self) -> io::Result<StoppedScope> {
        self.stop_with(Instant::now() + CLEANUP_BUDGET, |job| {
            job.query_process_id_list().map_err(job_error)
        })
    }

    fn stop_with(
        mut self,
        deadline: Instant,
        mut members: impl FnMut(&Job) -> io::Result<Vec<usize>>,
    ) -> io::Result<StoppedScope> {
        self.child.start_kill()?;
        loop {
            if members(&self.scope.job)?.is_empty() {
                return Ok(StoppedScope { id: self.scope.id });
            }
            self.child.start_kill()?;
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "local Job did not become empty before cleanup deadline",
                ));
            }
            thread::sleep(POLL);
        }
    }
}

#[cfg(test)]
mod tests;

impl Drop for JobChild {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        // scope.job then closes its sole, non-inherited handle. No blocking wait
        // or synthesized stop receipt in Drop, including unwind paths.
    }
}

/// Evidence of a kernel-empty, retired local Job. Not serializable/constructible
/// by callers, not cloneable, and not evidence about external runtime work.
///
/// ```compile_fail
/// use agentswapper_core::supervision::windows_job::StoppedScope;
/// fn duplicate(receipt: StoppedScope) { let _ = receipt.clone(); }
/// ```
///
/// ```compile_fail
/// use agentswapper_core::supervision::windows_job::StoppedScope;
/// let fabricated = StoppedScope { id: uuid::Uuid::new_v4() };
/// ```
#[derive(Debug)]
pub struct StoppedScope {
    id: Uuid,
}

impl StoppedScope {
    pub(crate) fn into_id(self) -> Uuid {
        self.id
    }

    pub fn id(&self) -> Uuid {
        self.id
    }
}

fn job_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

// std::process::Child doesn't kill on drop. Cover assignment/admission errors
// and unwind before ownership transfers into process-wrap.
struct SuspendedChild(Option<Child>);

impl SuspendedChild {
    fn as_child(&self) -> io::Result<&Child> {
        self.0
            .as_ref()
            .ok_or_else(|| io::Error::other("child already released"))
    }

    fn release(mut self) -> io::Result<Child> {
        self.0
            .take()
            .ok_or_else(|| io::Error::other("child already released"))
    }
}

impl Drop for SuspendedChild {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let deadline = Instant::now() + CLEANUP_BUDGET;
            while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
                thread::sleep(POLL);
            }
        }
    }
}
