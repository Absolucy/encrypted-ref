use encrypted_ref::EncryptedArc;

#[test]
fn encrypted_arc() {
	let string = String::from("hello world!");
	let string_arc = EncryptedArc::new(string.clone());
	println!("Normal string ref: {}", &string);
	println!("Encrypted string ref: {}", &*string_arc);
	assert_eq!(string, *string_arc);
}

#[test]
fn encrypted_weak() {
	let string = String::from("hello world!");
	let string_arc = EncryptedArc::new(string.clone());
	println!("Normal string ref: {}", &string);
	let weak = string_arc.downgrade();
	{
		let weak = weak.clone();
		assert_eq!(weak.upgrade().as_deref(), Some(&string));
	}
	std::mem::drop(string_arc);
	assert_eq!(weak.upgrade().as_deref(), None);
}
