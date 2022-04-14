// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{EncryptedArc, EncryptedArcInner};
use crate::util::{decrypt, encrypt, generate_key_and_iv, AesIv, AesKey, EncryptedPointer};
use std::{
	fmt,
	marker::PhantomData,
	ptr::NonNull,
	sync::atomic::{
		AtomicUsize,
		Ordering::{Acquire, Relaxed, Release},
	},
};

struct EncryptedWeakInner<'a> {
	weak: &'a AtomicUsize,
	strong: &'a AtomicUsize,
}

pub struct EncryptedWeak<T: 'static> {
	pub(super) key: AesKey,
	pub(super) iv: AesIv,
	pub(super) encrypted_ptr: EncryptedPointer,
	pub(super) _phantom: PhantomData<T>,
}

unsafe impl<T: Sync + Send + 'static> Send for EncryptedWeak<T> {}
unsafe impl<T: Sync + Send + 'static> Sync for EncryptedWeak<T> {}
impl<T: fmt::Debug + 'static> fmt::Debug for EncryptedWeak<T> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "(Weak)")
	}
}

impl<T: 'static> EncryptedWeak<T> {
	#[must_use]
	fn decrypt(&self) -> NonNull<EncryptedArcInner<T>> {
		let ptr = decrypt::<EncryptedArcInner<T>>(self.encrypted_ptr, self.key, self.iv);
		NonNull::new(ptr as *mut EncryptedArcInner<T>).unwrap_or_else(|| unreachable!())
	}

	#[inline]
	#[must_use]
	fn inner(&self) -> Option<EncryptedWeakInner<'_>> {
		if is_dangling(self.decrypt().as_ptr()) {
			None
		} else {
			// We are careful to *not* create a reference covering the "data" field, as
			// the field may be mutated concurrently (for example, if the last `Arc`
			// is dropped, the data field will be dropped in-place).
			Some(unsafe {
				let ptr = self.decrypt().as_ptr();
				EncryptedWeakInner {
					strong: &(*ptr).strong,
					weak: &(*ptr).weak,
				}
			})
		}
	}

	#[must_use]
	pub fn upgrade(&self) -> Option<EncryptedArc<T>> {
		// We use a CAS loop to increment the strong count instead of a
		// fetch_add as this function should never take the reference count
		// from zero to one.
		let inner = self.inner()?;

		// Relaxed load because any write of 0 that we can observe
		// leaves the field in a permanently zero state (so a
		// "stale" read of 0 is fine), and any other value is
		// confirmed via the CAS below.
		let mut n = inner.strong.load(Relaxed);

		loop {
			if n == 0 {
				return None;
			}

			// See comments in `Arc::clone` for why we do this (for `mem::forget`).
			if n > (isize::MAX as usize) {
				panic!()
			}

			// Relaxed is fine for the failure case because we don't have any expectations about the new state.
			// Acquire is necessary for the success case to synchronise with `Arc::new_cyclic`, when the inner
			// value can be initialized after `Weak` references have already been created. In that case, we
			// expect to observe the fully initialized value.
			match inner
				.strong
				.compare_exchange_weak(n, n + 1, Acquire, Relaxed)
			{
				Ok(_) => return Some(unsafe { EncryptedArc::from_inner(self.decrypt()) }), // null checked above
				Err(old) => n = old,
			}
		}
	}
}

impl<T: 'static> Drop for EncryptedWeak<T> {
	fn drop(&mut self) {
		let inner = if let Some(inner) = self.inner() {
			inner
		} else {
			return;
		};
		if inner.weak.fetch_sub(1, Release) == 1 {
			inner.weak.load(Acquire);
			let ptr = self.decrypt();
			unsafe {
				std::alloc::dealloc(
					ptr.as_ptr() as _,
					std::alloc::Layout::for_value(ptr.as_ref()),
				)
			}
		}
	}
}

impl<T: 'static> Clone for EncryptedWeak<T> {
	#[inline]
	fn clone(&self) -> Self {
		let (key, iv) = generate_key_and_iv();
		let inner = if let Some(inner) = self.inner() {
			inner
		} else {
			let encrypted_ptr =
				encrypt::<EncryptedArcInner<T>>(unsafe { self.decrypt().as_ref() }, key, iv);
			return EncryptedWeak {
				key,
				iv,
				encrypted_ptr,
				_phantom: PhantomData,
			};
		};
		// See comments in Arc::clone() for why this is relaxed.  This can use a
		// fetch_add (ignoring the lock) because the weak count is only locked
		// where are *no other* weak pointers in existence. (So we can't be
		// running this code in that case).
		let old_size = inner.weak.fetch_add(1, Relaxed);

		// See comments in Arc::clone() for why we do this (for mem::forget).
		if old_size > isize::MAX as usize {
			panic!();
		}

		let encrypted_ptr =
			encrypt::<EncryptedArcInner<T>>(unsafe { self.decrypt().as_ref() }, key, iv);
		EncryptedWeak {
			key,
			iv,
			encrypted_ptr,
			_phantom: PhantomData,
		}
	}
}

pub(super) fn is_dangling<T: ?Sized>(ptr: *mut T) -> bool {
	let address = ptr as *mut () as usize;
	address == usize::MAX
}
