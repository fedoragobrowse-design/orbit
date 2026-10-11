//! `BackendRegistry`: returns the active `Arc<dyn AgentBackend>` (or a
//! per-request override). Both backends are compiled in and selectable without
//! rebuild ("both can run").

use super::{AgentBackend, BackendKind};
use crate::claude::ClaudeSdkBackend;
use crate::omp::OmpBackend;
use orbit_sandbox_dispatch::GovernedExec;
use std::collections::HashMap;
use std::sync::Arc;

pub struct BackendRegistry {
    backends: HashMap<&'static str, Arc<dyn AgentBackend>>,
    default: BackendKind,
}

impl BackendRegistry {
    pub fn new(exec: Arc<GovernedExec>, omp_script: impl Into<String>, default: BackendKind) -> Self {
        let omp_script = omp_script.into();
        let mut backends: HashMap<&'static str, Arc<dyn AgentBackend>> = HashMap::new();
        backends.insert("OMP", Arc::new(OmpBackend::new(exec.clone(), omp_script)));
        backends.insert("CLAUDE_SDK", Arc::new(ClaudeSdkBackend::new(exec)));
        Self { backends, default }
    }

    pub fn get(&self, kind: BackendKind) -> Arc<dyn AgentBackend> {
        self.backends[kind.as_str()].clone()
    }

    pub fn active(&self, override_kind: Option<BackendKind>) -> Arc<dyn AgentBackend> {
        self.get(override_kind.unwrap_or(self.default))
    }

    pub fn default(&self) -> BackendKind {
        self.default
    }
}
