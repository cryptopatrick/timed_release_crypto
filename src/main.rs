fn main() {
    let _plaintext = b"General Kenobi, years ago you served my father in the
    Clone Wars. Now, he begs you to help him in his struggle against the
    Empire. I regret I am unable to present my father's request to you in
    person, but my ship has fallen under attack, and fear my mission to
    return with you to Alderaan has failed.
    I have fed information vital to the survival of all free planets into
    the memory of systems of this R-2 unit. My father will know how to
    retrieve it. You must see this droid safely delivered to him on Alderaan.
    This is our most desperate hour. You must help me Obi-Wan Kenobi,
    you are my only hope.";

    // Blueprint _ Dry Run Sequence:
    // - Create a Capsule to manage the process of creating the Puzzle.
    // - Arming capsule with the following...
    /*
    TODO: Make these more informative...
    println!("Key (Base64): {}", base64::encode(&key));
    println!("Nonce (Base64): {}", base64::encode(&nonce));
    println!("Message: {}", String::from_utf8_lossy(plaintext));
    println!("Ciphertext (Base64): {}", base64::encode(&ciphertext));
    */
    // - Print Log
    println!("--- Puzzle Successfully Created");
    println!("--- Puzzle Stored in Capsule");
    println!("--- Locking Capsule");
    println!("--- Arming Capsule");
    println!("--- Process Successfully Completed.\n");
}
