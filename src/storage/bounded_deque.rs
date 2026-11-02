//! A FIFO queue bounded in both modes.

use core::fmt;

/// A FIFO queue of at most `N` items, with or without `alloc`.
pub(crate) struct BoundedDeque<T, const N: usize> {
    inner: heapless::Deque<T, N>,
}

impl<T, const N: usize> BoundedDeque<T, N> {
    pub const fn new() -> Self {
        Self {
            inner: heapless::Deque::new(),
        }
    }

    /// Append an item at the back, handing it back if the queue is full.
    pub fn push_back(&mut self, item: T) -> Result<(), T> {
        self.inner.push_back(item)
    }

    pub fn pop_front(&mut self) -> Option<T> {
        self.inner.pop_front()
    }

    pub fn front(&self) -> Option<&T> {
        self.inner.front()
    }

    pub fn front_mut(&mut self) -> Option<&mut T> {
        self.inner.front_mut()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn clear(&mut self) {
        self.inner.clear()
    }

    pub fn retain(&mut self, f: impl FnMut(&T) -> bool) {
        self.inner.retain(f)
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.inner.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.inner.iter_mut()
    }
}

impl<T, const N: usize> Default for BoundedDeque<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: fmt::Debug, const N: usize> fmt::Debug for BoundedDeque<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_deque_bounded() {
        let mut queue: BoundedDeque<u32, 2> = BoundedDeque::new();
        assert_eq!(queue.push_back(1), Ok(()));
        assert_eq!(queue.push_back(2), Ok(()));
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.push_back(3), Err(3));
        assert_eq!(queue.pop_front(), Some(1));
        queue.retain(|&x| x != 2);
        assert!(queue.is_empty());
    }
}
