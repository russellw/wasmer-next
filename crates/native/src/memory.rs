//! Stable 32-bit aliases for native addresses. WLK pointers are wasm32, so native pointers
//! stay in these per-address-space aliases and are copied through process_vm_* at syscall time.

use std::{collections::HashMap, io};

const FIRST_ALIAS: u32 = 0x1000;
const ALIAS_GUARD: u32 = 256;
const TRANSIENT_BASE: u32 = 0x4000_0000;
const LOCAL_SCRATCH_BASE: u32 = 0x8000_0000;
const NATIVE_ALIAS_LIMIT: u32 = 0x3000_0000;

#[derive(Default)]
pub(super) struct AliasRegistry {
    next: u32,
    aliases: HashMap<(u64, u64), u32>,
}

impl AliasRegistry {
    pub(super) fn alias(&mut self, mm: u64, native: u64) -> io::Result<u32> {
        if let Some(alias) = self.aliases.get(&(mm, native)) {
            return Ok(*alias);
        }
        let next = if self.next == 0 {
            FIRST_ALIAS
        } else {
            self.next
        };
        let aligned = next
            .checked_add(ALIAS_GUARD - 1)
            .ok_or_else(|| io::Error::other("native address alias overflow"))?
            & !(ALIAS_GUARD - 1);
        let span = ALIAS_GUARD * 2;
        self.next = aligned
            .checked_add(span)
            .ok_or_else(|| io::Error::other("native address aliases exhausted"))?;
        if self.next >= NATIVE_ALIAS_LIMIT {
            return Err(io::Error::other("native address aliases exhausted"));
        }
        self.aliases.insert((mm, native), aligned);
        Ok(aligned)
    }

    pub(super) fn clone_mm(&mut self, parent: u64, child: u64) {
        let inherited: Vec<_> = self
            .aliases
            .iter()
            .filter(|((mm, _), _)| *mm == parent)
            .map(|((_, native), alias)| ((child, *native), *alias))
            .collect();
        self.aliases.extend(inherited);
    }

    pub(super) fn clear_mm(&mut self, mm: u64) {
        self.aliases.retain(|(owner, _), _| *owner != mm);
    }

    pub(super) fn resolve(&self, mm: u64, alias: u32, len: usize) -> Option<u64> {
        let end = u64::from(alias).checked_add(len as u64)?;
        self.aliases.iter().find_map(|((owner, native), guest)| {
            let guest_end = u64::from(*guest).checked_add(ALIAS_GUARD as u64)?;
            (*owner == mm && u64::from(alias) >= u64::from(*guest) && end <= guest_end)
                .then(|| native.checked_add(u64::from(alias - *guest)))
                .flatten()
        })
    }
}

pub(super) fn local_scratch_base() -> u32 {
    LOCAL_SCRATCH_BASE
}

pub(super) fn transient_base() -> u32 {
    TRANSIENT_BASE
}
