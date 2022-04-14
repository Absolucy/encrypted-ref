// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::util::{decrypt, encrypt, generate_key_and_iv, AesIv, AesKey, EncryptedPointer};
use std::{
	marker::PhantomData,
	ops::{Deref, DerefMut},
};
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
pub struct EncryptedRef<'a, T> {
	key: AesKey,
	iv: AesIv,
	ptr: EncryptedPointer,
	_marker: PhantomData<&'a T>,
}

impl<'a, T> EncryptedRef<'a, T> {
	pub fn new(data: &'a T) -> Self {
		let (key, iv) = generate_key_and_iv();
		let ptr = encrypt(data, key, iv);
		Self {
			key,
			iv,
			ptr,
			_marker: PhantomData,
		}
	}

	unsafe fn decrypt(&self) -> *const T {
		decrypt(self.ptr, self.key, self.iv)
	}

	unsafe fn decrypt_mut(&self) -> *mut T {
		self.decrypt() as *mut T
	}
}

impl<'a, T> Deref for EncryptedRef<'a, T> {
	type Target = T;

	fn deref(&self) -> &Self::Target {
		unsafe { &*self.decrypt() }
	}
}

impl<'a, T> AsRef<T> for EncryptedRef<'a, T> {
	fn as_ref(&self) -> &T {
		unsafe { &*self.decrypt() }
	}
}

impl<'a, T> Drop for EncryptedRef<'a, T> {
	fn drop(&mut self) {
		self.key.zeroize();
		self.iv.zeroize();
		self.ptr.zeroize();
	}
}

#[repr(transparent)]
#[derive(Clone, Zeroize)]
pub struct EncryptedMutRef<'a, T>(EncryptedRef<'a, T>);

impl<'a, T> Deref for EncryptedMutRef<'a, T> {
	type Target = T;

	fn deref(&self) -> &Self::Target {
		unsafe { &*self.0.decrypt() }
	}
}

impl<'a, T> DerefMut for EncryptedMutRef<'a, T> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		unsafe { &mut *self.0.decrypt_mut() }
	}
}

impl<'a, T> AsRef<T> for EncryptedMutRef<'a, T> {
	fn as_ref(&self) -> &T {
		unsafe { &*self.0.decrypt() }
	}
}

impl<'a, T> AsMut<T> for EncryptedMutRef<'a, T> {
	fn as_mut(&mut self) -> &mut T {
		unsafe { &mut *self.0.decrypt_mut() }
	}
}

pub fn eref<T>(data: &'_ T) -> EncryptedRef<'_, T> {
	EncryptedRef::new(data)
}

pub fn emref<T>(data: &'_ mut T) -> EncryptedMutRef<'_, T> {
	EncryptedMutRef(EncryptedRef::new(data))
}
