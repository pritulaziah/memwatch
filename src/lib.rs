//! Records resource usage of a tree of Windows processes while it runs.

pub mod collect;
pub mod launch;
pub mod log;
pub mod meta;
pub mod options;
pub mod sampler;
pub mod store;
pub mod win;

pub use options::RunOptions;
pub use sampler::{StopHandle, run};
