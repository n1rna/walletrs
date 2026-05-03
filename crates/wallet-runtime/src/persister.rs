use bdk_wallet::{chain::Merge, ChangeSet, WalletPersister};

/// Minimal `WalletPersister` that holds a `ChangeSet` in memory. Useful for
/// tests and for short-lived ephemeral wallets where on-disk durability is
/// not required.
#[derive(Debug, Default)]
pub struct InMemoryPersister {
    changeset: ChangeSet,
}

impl InMemoryPersister {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn changeset(&self) -> &ChangeSet {
        &self.changeset
    }
}

impl WalletPersister for InMemoryPersister {
    type Error = std::convert::Infallible;

    fn initialize(persister: &mut Self) -> Result<ChangeSet, Self::Error> {
        Ok(persister.changeset.clone())
    }

    fn persist(persister: &mut Self, changeset: &ChangeSet) -> Result<(), Self::Error> {
        persister.changeset.merge(changeset.clone());
        Ok(())
    }
}
