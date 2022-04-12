// SPDX-License-Identifier: MIT OR Apache-2.0
use aes::{
	cipher::{
		block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, KeyIvInit,
		KeySizeUser, Unsigned,
	},
	Aes128,
};
use cbc::{Decryptor, Encryptor};
use rand::RngCore;
use std::{
	marker::PhantomData,
	ops::{Deref, DerefMut},
};
use zeroize::Zeroize;

type AesEnc = Encryptor<Aes128>;
type AesDec = Decryptor<Aes128>;

const ENCRYPTED_PTR_SIZE: usize = std::mem::size_of::<usize>()
	+ (std::mem::size_of::<usize>() % <Aes128 as BlockSizeUser>::BlockSize::USIZE);

#[derive(Clone, Zeroize)]
pub struct EncryptedRef<'a, T> {
	key: [u8; <Aes128 as KeySizeUser>::KeySize::USIZE],
	iv: [u8; 16],
	ptr: [u8; ENCRYPTED_PTR_SIZE],
	_marker: PhantomData<&'a T>,
}

impl<'a, T> EncryptedRef<'a, T> {
	pub fn new(data: &'a T) -> Self {
		let mut key = [0_u8; <Aes128 as KeySizeUser>::KeySize::USIZE];
		let mut iv = [0_u8; 16];
		let mut rng = rand::thread_rng();
		rng.fill_bytes(&mut key);
		rng.fill_bytes(&mut iv);
		let mut ptr = [0_u8; ENCRYPTED_PTR_SIZE];
		ptr[..std::mem::size_of::<usize>()]
			.copy_from_slice(&(data as *const T as usize).to_le_bytes());
		AesEnc::new(&key.into(), &iv.into())
			.encrypt_padded_mut::<Pkcs7>(&mut ptr, std::mem::size_of::<usize>())
			.unwrap_or_else(|_| unreachable!());
		Self {
			key,
			iv,
			ptr,
			_marker: PhantomData,
		}
	}

	unsafe fn decrypt(&self) -> *const T {
		let mut ptr_buf = self.ptr;
		let decrypted_ptr = AesDec::new(&self.key.into(), &self.iv.into())
			.decrypt_padded_mut::<Pkcs7>(&mut ptr_buf)
			.unwrap_or_else(|_| unreachable!());
		let mut ptr_to_usize = [0_u8; std::mem::size_of::<usize>()];
		ptr_to_usize.copy_from_slice(&decrypted_ptr[..std::mem::size_of::<usize>()]);
		usize::from_le_bytes(ptr_to_usize) as *const T
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
