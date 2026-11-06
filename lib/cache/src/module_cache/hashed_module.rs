use shared_buffer::OwnedBuffer;
use wasmer_types::ModuleHash;

/// A wrapper around Webassembly code and its hash.
///
/// Keeps immutable compiler input alongside its cache key.
///
/// [`Self::new`] computes the hash. [`Self::from_parts`] accepts an embedder's
/// trusted precomputed hash and does not validate that it matches the bytes.
///
/// Can be cloned cheaply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashedModuleData {
    hash: ModuleHash,
    wasm: OwnedBuffer,
}

impl HashedModuleData {
    /// Compute a cache key for these immutable compiler-input bytes.
    pub fn new(bytes: impl Into<OwnedBuffer>) -> Self {
        let wasm = bytes.into();
        let hash = ModuleHash::new(&wasm);
        Self { hash, wasm }
    }

    /// Retain immutable bytes with their trusted precomputed cache key.
    ///
    /// The caller must supply the hash of these exact bytes. This constructor
    /// does not hash or validate them, so it also supports signed package atom
    /// digests without reading the atom again.
    pub fn from_parts(hash: ModuleHash, wasm: impl Into<OwnedBuffer>) -> Self {
        Self {
            hash,
            wasm: wasm.into(),
        }
    }

    /// Get the module hash.
    pub fn hash(&self) -> &ModuleHash {
        &self.hash
    }

    /// Get the WASM code.
    pub fn wasm(&self) -> &OwnedBuffer {
        &self.wasm
    }

    /// Take the key and its retained module bytes.
    pub fn into_parts(self) -> (ModuleHash, OwnedBuffer) {
        (self.hash, self.wasm)
    }
}
