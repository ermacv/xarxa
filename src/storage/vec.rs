//! A growable array, bounded only without `alloc`.

use core::fmt;
use core::ops::{Deref, DerefMut};

use crate::error::Full;

/// A growable array, bounded to `N` items without `alloc`.
pub(crate) struct Vec<T, const N: usize> {
    #[cfg(feature = "alloc")]
    inner: alloc::vec::Vec<T>,
    #[cfg(not(feature = "alloc"))]
    inner: heapless::Vec<T, N>,
}

impl<T, const N: usize> Vec<T, N> {
    pub const fn new() -> Self {
        #[cfg(feature = "alloc")]
        let inner = alloc::vec::Vec::new();
        #[cfg(not(feature = "alloc"))]
        let inner = heapless::Vec::new();
        Self { inner }
    }

    /// Append an item, handing it back if there is no room.
    pub fn push(&mut self, item: T) -> Result<(), T> {
        #[cfg(feature = "alloc")]
        {
            self.inner.push(item);
            Ok(())
        }
        #[cfg(not(feature = "alloc"))]
        {
            self.inner.push(item)
        }
    }

    /// Append every item of `iter`, stopping at the first that does not fit.
    pub fn try_extend(&mut self, iter: impl IntoIterator<Item = T>) -> Result<(), Full> {
        for item in iter {
            self.push(item).map_err(|_| Full)?;
        }
        Ok(())
    }

    /// Whether another `push` would fail. Never true with `alloc`.
    pub fn is_full(&self) -> bool {
        #[cfg(feature = "alloc")]
        {
            false
        }
        #[cfg(not(feature = "alloc"))]
        {
            self.inner.is_full()
        }
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

impl<T, const N: usize> Default for Vec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Deref for Vec<T, N> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.inner
    }
}

impl<T, const N: usize> DerefMut for Vec<T, N> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.inner
    }
}

impl<T: fmt::Debug, const N: usize> fmt::Debug for Vec<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_slice(), f)
    }
}

#[cfg(feature = "defmt")]
impl<T: defmt::Format, const N: usize> defmt::Format for Vec<T, N> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "{=[?]}", self.as_slice())
    }
}

impl<T: Clone, const N: usize> Clone for Vec<T, N> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: PartialEq, const N: usize> PartialEq for Vec<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: Eq, const N: usize> Eq for Vec<T, N> {}

impl<T, const N: usize> IntoIterator for Vec<T, N> {
    type Item = T;
    #[cfg(feature = "alloc")]
    type IntoIter = alloc::vec::IntoIter<T>;
    #[cfg(not(feature = "alloc"))]
    type IntoIter = <heapless::Vec<T, N> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a Vec<T, N> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a mut Vec<T, N> {
    type Item = &'a mut T;
    type IntoIter = core::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}
