use encrypted_ref::eref;

#[test]
fn encrypted_ref_string() {
	let string = String::from("hello world!");
	let string_ref = eref(&string);
	println!("Normal string ref: {}", &string);
	println!("Encrypted string ref: {}", &*string_ref);
}
