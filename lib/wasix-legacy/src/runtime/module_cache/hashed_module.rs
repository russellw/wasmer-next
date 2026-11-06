use crate::bin_factory::BinaryPackageCommand;
use shared_buffer::OwnedBuffer;
use wasmer_types::ModuleHash;

/// Immutable module bytes and their hash, with legacy package-command convenience.
#[derive(Clone, PartialEq, Eq)]
pub struct HashedModuleData(wasmer_cache::module_cache::HashedModuleData);

impl std::fmt::Debug for HashedModuleData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl HashedModuleData {
    pub fn new(bytes: impl Into<OwnedBuffer>) -> Self {
        Self(wasmer_cache::module_cache::HashedModuleData::new(bytes))
    }

    /// Retain the command's signed hash and bytes without hashing them again.
    pub fn from_command(command: &BinaryPackageCommand) -> Self {
        Self(wasmer_cache::module_cache::HashedModuleData::from_parts(
            *command.hash(),
            command.atom(),
        ))
    }

    pub fn hash(&self) -> &ModuleHash {
        self.0.hash()
    }
    pub fn wasm(&self) -> &OwnedBuffer {
        self.0.wasm()
    }
    pub fn into_parts(self) -> (ModuleHash, OwnedBuffer) {
        self.0.into_parts()
    }
}
