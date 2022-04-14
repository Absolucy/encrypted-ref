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
use std::hint::unreachable_unchecked;

type AesEnc = Encryptor<Aes128>;
type AesDec = Decryptor<Aes128>;

pub const ENCRYPTED_PTR_SIZE: usize = std::mem::size_of::<usize>()
	+ (std::mem::size_of::<usize>() % <Aes128 as BlockSizeUser>::BlockSize::USIZE);

pub type AesKey = [u8; <Aes128 as KeySizeUser>::KeySize::USIZE];
pub type AesIv = [u8; 16];
pub type EncryptedPointer = [u8; ENCRYPTED_PTR_SIZE];

pub fn generate_key_and_iv() -> (AesKey, AesIv) {
	let mut key = AesKey::default();
	let mut iv = AesIv::default();
	let mut rng = rand::thread_rng();
	rng.fill_bytes(&mut key);
	rng.fill_bytes(&mut iv);
	(key, iv)
}

pub fn encrypt<T>(ptr: &T, key: AesKey, iv: AesIv) -> EncryptedPointer {
	let mut encrypted_ptr = EncryptedPointer::default();
	encrypted_ptr[..std::mem::size_of::<usize>()]
		.copy_from_slice(&(ptr as *const T as usize).to_le_bytes());
	AesEnc::new(&key.into(), &iv.into())
		.encrypt_padded_mut::<Pkcs7>(&mut encrypted_ptr, std::mem::size_of::<usize>())
		.unwrap_or_else(|_| unsafe { unreachable_unchecked() });
	encrypted_ptr
}

pub fn decrypt<T>(mut encrypted_ptr: EncryptedPointer, key: AesKey, iv: AesIv) -> *const T {
	let decrypted_ptr = AesDec::new(&key.into(), &iv.into())
		.decrypt_padded_mut::<Pkcs7>(&mut encrypted_ptr)
		.unwrap_or_else(|_| unsafe { unreachable_unchecked() });
	let mut ptr_to_usize = [0_u8; std::mem::size_of::<usize>()];
	ptr_to_usize.copy_from_slice(&decrypted_ptr[..std::mem::size_of::<usize>()]);
	usize::from_le_bytes(ptr_to_usize) as *const T
}
