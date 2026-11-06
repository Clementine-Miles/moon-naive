use std::{borrow::Cow, collections::BTreeMap};

use blake2::Digest;

use crate::key::{Blake2b128, HashBinary};

/// A builder for variance keys, used for distinguishing multiple cached assets
/// at the same URL. This is intended to be easily passed to helper functions,
/// which can each populate a portion of the variance.
pub struct VarianceBuilder<'a> {
    values: BTreeMap<Cow<'a, str>, Cow<'a, [u8]>>,
}

impl<'a> VarianceBuilder<'a> {
    /// Create an empty variance key. Has no variance by default - add some variance using
    /// [`Self::add_value`].
    pub fn new() -> Self {
        VarianceBuilder {
            values: BTreeMap::new(),
        }
    }

    /// Add a byte string to the variance key. Not sensitive to insertion order.
    /// `value` is intended to take either `&str` or `&[u8]`.
    pub fn add_value(&mut self, name: &'a str, value: &'a (impl AsRef<[u8]> + ?Sized)) {
        self.values
            .insert(name.into(), Cow::Borrowed(value.as_ref()));
    }

    /// Move a byte string to the variance key. Not sensitive to insertion order. Useful when
    /// writing helper functions which generate a value then add said value to the VarianceBuilder.
    /// Without this, the helper function would have to move the value to the calling function
    /// to extend its lifetime to at least match the VarianceBuilder.
    pub fn add_owned_value(&mut self, name: &'a str, value: Vec<u8>) {
        self.values.insert(name.into(), Cow::Owned(value));
    }

    /// Move String name and byte string value to the variance key. Not sensitive to insertion order.
    /// Useful when both the name and value are generated at runtime.
    pub fn add_owned_name_value(&mut self, name: String, value: Vec<u8>) {
        self.values.insert(Cow::Owned(name), Cow::Owned(value));
    }

    /// Check whether this variance key actually has variance, or just refers to the root asset
    pub fn has_variance(&self) -> bool {
        !self.values.is_empty()
    }

    /// Hash this variance key. Returns [`None`] if [`Self::has_variance`] is false.
    pub fn finalize(self) -> Option<HashBinary> {
        const SALT: &[u8; 1] = &[0u8; 1];
        if self.has_variance() {
            let mut hash = Blake2b128::new();
            for (name, value) in self.values.iter() {
                hash.update(name.as_bytes());
                hash.update(SALT);
                hash.update(value);
                hash.update(SALT);
            }
            Some(hash.finalize().into())
        } else {
            None
        }
    }
}
