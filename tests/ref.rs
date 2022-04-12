use encrypted_ref::{emref, eref};

#[test]
fn encrypted_ref_string() {
	let string = String::from("hello world!");
	let string_ref = eref(&string);
	println!("Normal string ref: {}", &string);
	println!("Encrypted string ref: {}", &*string_ref);
}

#[test]
fn encrypted_mut_ref_string() {
	let mut string = String::from("hello world!");
	let mut string_ref = emref(&mut string);
	string_ref.push_str(" hello from encrypted mut ref!");
	println!("Encrypted string ref: {}", &*string_ref);
}
