// SPDX-License-Identifier: MIT OR Apache-2.0

mod weak;

use crate::util::{decrypt, encrypt, generate_key_and_iv, AesIv, AesKey, EncryptedPointer};
use std::{
	borrow::Borrow,
	marker::PhantomData,
	ops::Deref,
	panic::{RefUnwindSafe, UnwindSafe},
	ptr::NonNull,
	sync::atomic::{
		AtomicUsize,
		Ordering::{Acquire, Relaxed, Release, SeqCst},
	},
};

pub use weak::EncryptedWeak;

struct EncryptedArcInner<T: 'static> {
	strong: AtomicUsize,
	weak: AtomicUsize,
	data: T,
}

pub struct EncryptedArc<T: 'static> {
	key: AesKey,
	iv: AesIv,
	encrypted_ptr: EncryptedPointer,
	_phantom: PhantomData<EncryptedArcInner<T>>,
}

#[allow(clippy::missing_safety_doc)]
impl<T: 'static> EncryptedArc<T> {
	#[must_use]
	fn decrypt(&self) -> NonNull<EncryptedArcInner<T>> {
		let ptr = decrypt::<EncryptedArcInner<T>>(self.encrypted_ptr, self.key, self.iv);
		NonNull::new(ptr as *mut EncryptedArcInner<T>).unwrap_or_else(|| unreachable!())
	}

	#[must_use]
	unsafe fn from_inner(ptr: NonNull<EncryptedArcInner<T>>) -> Self {
		let (key, iv) = generate_key_and_iv();
		let encrypted_ptr = encrypt::<EncryptedArcInner<T>>(ptr.as_ref(), key, iv);
		Self {
			key,
			iv,
			encrypted_ptr,
			_phantom: PhantomData,
		}
	}

	#[inline]
	#[must_use]
	fn inner(&self) -> &EncryptedArcInner<T> {
		unsafe { self.decrypt().as_ref() }
	}

	#[must_use]
	pub fn new(data: T) -> Self {
		let x = Box::new(EncryptedArcInner {
			strong: AtomicUsize::new(1),
			weak: AtomicUsize::new(1),
			data,
		});
		let leaked: &'static EncryptedArcInner<T> = Box::leak(x);
		let (key, iv) = generate_key_and_iv();
		let encrypted_ptr = encrypt(leaked, key, iv);
		Self {
			key,
			iv,
			encrypted_ptr,
			_phantom: PhantomData,
		}
	}

	#[must_use]
	pub fn strong_count(&self) -> usize {
		self.inner().strong.load(SeqCst)
	}

	#[must_use]
	pub fn weak_count(&self) -> usize {
		self.inner().weak.load(SeqCst)
	}

	pub unsafe fn get_mut_unchecked(this: &mut Self) -> &mut T {
		// We are careful to *not* create a reference covering the "count" fields, as
		// this would alias with concurrent access to the reference counts (e.g. by `Weak`).
		&mut (*this.decrypt().as_ptr()).data
	}

	#[inline(never)]
	unsafe fn drop_slow(&mut self) {
		// Destroy the data at this time, even though we must not free the box
		// allocation itself (there might still be weak pointers lying around).
		std::ptr::drop_in_place(Self::get_mut_unchecked(self));

		// Drop the weak ref collectively held by all strong references
		let (key, iv) = (AesKey::default(), AesIv::default());
		let encrypted_ptr = encrypt(self.decrypt().as_ref(), key, iv);
		std::mem::drop(EncryptedWeak::<T> {
			key,
			iv,
			encrypted_ptr,
			_phantom: PhantomData,
		});
	}
}

unsafe impl<T: Sync + Send + 'static> Send for EncryptedArc<T> {}
unsafe impl<T: Sync + Send + 'static> Sync for EncryptedArc<T> {}
impl<T: RefUnwindSafe + 'static> UnwindSafe for EncryptedArc<T> {}

impl<T: 'static> Clone for EncryptedArc<T> {
	#[inline]
	fn clone(&self) -> Self {
		let old_size = self.inner().strong.fetch_add(1, Relaxed);
		if old_size > (isize::MAX) as usize {
			panic!();
		}
		let (key, iv) = generate_key_and_iv();
		let encrypted_ptr = encrypt(unsafe { self.decrypt().as_ref() }, key, iv);
		Self {
			key,
			iv,
			encrypted_ptr,
			_phantom: PhantomData,
		}
	}
}

impl<T: 'static> Deref for EncryptedArc<T> {
	type Target = T;

	#[inline]
	fn deref(&self) -> &Self::Target {
		&self.inner().data
	}
}

impl<T: 'static> AsRef<T> for EncryptedArc<T> {
	fn as_ref(&self) -> &T {
		&**self
	}
}

impl<T: 'static> Borrow<T> for EncryptedArc<T> {
	fn borrow(&self) -> &T {
		&**self
	}
}

impl<T: 'static> Unpin for EncryptedArc<T> {}

impl<T: 'static> Drop for EncryptedArc<T> {
	fn drop(&mut self) {
		let inner = self.inner();
		if inner.strong.fetch_sub(1, Release) != 1 {
			return;
		}
		inner.strong.load(Acquire);
		unsafe {
			self.drop_slow();
		}
	}
}
