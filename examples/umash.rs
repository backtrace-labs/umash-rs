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
    let fprint = my_params
        .fingerprinter(seed)
        .write(input.as_bytes())
        .digest();

    println!("Input: {}", input);
    println!("Fingerprint: {:x}, {:x}", fprint.hash[0], fprint.hash[1]);
    println!(
        "Hash 0: {:x}",
        my_params.hasher(seed).write(input.as_bytes()).digest()
    );
    println!(
        "Hash 1: {:x}",
        my_params
            .secondary_hasher(seed)
            .write(input.as_bytes())
            .digest()
    );

    let mut h: umash::Hasher = (&my_params).into();
    h.write(input.as_bytes());
    println!("Hash: {:x}", h.finish());
}
