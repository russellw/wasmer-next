//! Concrete owners of this submission, destroyed after its outer submit guard.
//! Helpers borrow these slots before acquiring/calling anything that can yield.

use super::{
    kbuf::{Group, Pbuf},
    ops::{Req, Waiting},
    rsrc::{BufferNode, FileNode},
};
use crate::{
    mm::{MemoryRetirement, Retained},
    sync::DropErrors,
};
use std::sync::Arc;

#[derive(Default)]
pub(super) struct SubmissionRetirement {
    pub(super) preparing: Option<Box<Req>>,
    pub(super) issuing: Option<Box<Req>>,
    pub(super) link: Option<Req>,
    pub(super) resources: Resources,
}

#[derive(Default)]
pub(crate) struct Resources {
    pub(super) memory: MemoryRetirement,
    pub(super) requests: Vec<Box<Req>>,
    pub(super) ready: Vec<Option<Req>>,
    pub(super) timers: Vec<Option<crate::timer::Timer>>,
    pub(super) waiting: Vec<Waiting>,
    pub(super) pbufs: Vec<Pbuf>,
    pub(super) buffers: Vec<Option<BufferNode>>,
    pub(super) files: Vec<Option<FileNode>>,
    pub(super) open_files: Vec<Option<Arc<crate::file::OpenFile>>>,
    pub(super) buffer_tables: Vec<Option<Vec<Option<BufferNode>>>>,
    pub(super) file_tables: Vec<Option<Vec<Option<FileNode>>>>,
    pub(super) retained: Vec<Option<Arc<Retained>>>,
    pub(super) buffer_builders: Vec<Vec<(Option<Arc<Retained>>, u64)>>,
    pub(super) file_builders: Vec<Vec<(Option<Arc<crate::file::OpenFile>>, u64)>>,
    pub(super) groups: Vec<Option<Group>>,
}

impl Resources {
    pub(super) fn take_waiting(&mut self, waiting: Waiting) -> Req {
        self.waiting.push(waiting);
        let req = self.waiting.last_mut().unwrap().req_mut();
        std::mem::replace(req, req.taken())
    }
}
impl Drop for SubmissionRetirement {
    fn drop(&mut self) {
        let mut errors = DropErrors::new();
        errors.run(|| drop(self.preparing.take()));
        errors.run(|| drop(self.issuing.take()));
        errors.run(|| drop(self.link.take()));
        errors.run(|| drop(std::mem::take(&mut self.resources)));
        errors.finish();
    }
}
impl Drop for Resources {
    fn drop(&mut self) {
        let mut errors = DropErrors::new();
        for req in self.requests.drain(..) {
            errors.run(|| drop(req));
        }
        for req in self.ready.drain(..) {
            errors.run(|| drop(req));
        }
        for waiting in self.waiting.drain(..) {
            errors.run(|| drop(waiting));
        }
        for timer in self.timers.drain(..) {
            errors.run(|| drop(timer));
        }
        for pbuf in self.pbufs.drain(..) {
            errors.run(|| drop(pbuf));
        }
        for buffer in self.buffers.drain(..) {
            errors.run(|| drop(buffer));
        }
        for file in self.open_files.drain(..) {
            errors.run(|| drop(file));
        }
        for file in self.files.drain(..) {
            errors.run(|| drop(file));
        }
        for table in self.buffer_tables.drain(..).flatten() {
            for buffer in table {
                errors.run(|| drop(buffer));
            }
        }
        for table in self.file_tables.drain(..).flatten() {
            for file in table {
                errors.run(|| drop(file));
            }
        }
        for buffers in self.buffer_builders.drain(..) {
            for (buffer, _) in buffers {
                errors.run(|| drop(buffer));
            }
        }
        for files in self.file_builders.drain(..) {
            for (file, _) in files {
                errors.run(|| drop(file));
            }
        }
        for retained in self.retained.drain(..) {
            errors.run(|| drop(retained));
        }
        for group in self.groups.drain(..) {
            errors.run(|| drop(group));
        }
        errors.run(|| drop(std::mem::take(&mut self.memory)));
        errors.finish();
    }
}
