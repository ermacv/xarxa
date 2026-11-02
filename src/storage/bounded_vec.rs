//! A growable array bounded in both modes.

use core::fmt;
use core::ops::{Deref, DerefMut};

use crate::error::Full;

/// A growable array holding at most `N` items, with or without `alloc`.
///
/// For tables whose bound is a policy rather than an allocator limit, and for
/// temporaries that are bounded by the table they are built from.
pub(crate) struct BoundedVec<T, const N: usize> {
    inner: heapless::Vec<T, N>,
}

impl<T, const N: usize> BoundedVec<T, N> {
    pub const fn new() -> Self {
        Self {
            inner: heapless::Vec::new(),
        }
    }

    /// Append an item, handing it back if there is no room.
    pub fn push(&mut self, item: T) -> Result<(), T> {
        self.inner.push(item)
    }

    /// Append every item of `iter`, stopping at the first that does not fit.
    pub fn try_extend(&mut self, iter: impl IntoIterator<Item = T>) -> Result<(), Full> {
        for item in iter {
            self.push(item).map_err(|_| Full)?;
        }
        Ok(())
    }

    pub fn is_full(&self) -> bool {
        self.inner.is_full()
    }

    /// Remove the item at `index`, shifting the ones after it down.
    ///
    /// # Panics
    /// Panics if `index` is out of bounds.
    pub fn remove(&mut self, index: usize) -> T {
        self.inner.remove(index)
    }

    /// Remove the item at `index`, moving the last item into its place.
    ///
    /// # Panics
    /// Panics if `index` is out of bounds.
    pub fn swap_remove(&mut self, index: usize) -> T {
        self.inner.swap_remove(index)
    }

    pub fn clear(&mut self) {
        self.inner.clear()
    }

    pub fn retain(&mut self, f: impl FnMut(&T) -> bool) {
        self.inner.retain(f)
    }

    pub fn as_slice(&self) -> &[T] {
        &self.inner
    }
}

impl<T, const N: usize> Default for BoundedVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Deref for BoundedVec<T, N> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.inner
    }
}

impl<T, const N: usize> DerefMut for BoundedVec<T, N> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.inner
    }
}

impl<T: fmt::Debug, const N: usize> fmt::Debug for BoundedVec<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_slice(), f)
    }
}

#[cfg(feature = "defmt")]
impl<T: defmt::Format, const N: usize> defmt::Format for BoundedVec<T, N> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "{=[?]}", self.as_slice())
    }
}

impl<T, const N: usize> IntoIterator for BoundedVec<T, N> {
    type Item = T;
    type IntoIter = <heapless::Vec<T, N> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a BoundedVec<T, N> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a mut BoundedVec<T, N> {
    type Item = &'a mut T;
    type IntoIter = core::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}
