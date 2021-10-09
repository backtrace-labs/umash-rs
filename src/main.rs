use std::hash::Hasher;

// Implements example.c from the original source.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let input = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "default input".to_string());
    let seed = 42u64;
    let my_params = umash::Params::derive(0, "hello example.c".as_bytes());
    let fprint = umash::Fingerprint::generate(&my_params, seed, input.as_bytes());

    println!("Input: {}", input);
    println!("Fingerprint: {:x}, {:x}", fprint.hash[0], fprint.hash[1]);
    println!("Hash 0: {:x}", umash::full_str(&my_params, seed, 0, &input));
    println!("Hash 1: {:x}", umash::full_str(&my_params, seed, 1, &input));

    let mut h: umash::Hasher = (&my_params).into();
    h.write(input.as_bytes());
    println!("Hash: {:x}", h.finish());
}
