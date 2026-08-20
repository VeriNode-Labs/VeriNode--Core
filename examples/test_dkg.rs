//! Simple manual test for DKG serialization

use sorosusu_contracts::crypto::bls_keys::{
    deserialize_shared_public_key, serialize_shared_public_key, G1Point, SharedPublicKey,
};

fn main() {
    println!("Testing DKG Serialization Fix...\n");

    // Test 1: Basic round-trip
    println!("Test 1: Basic G1Point round-trip");
    let point1 = G1Point::new(0x1234567890ABCDEF, true);
    let bytes1 = point1.to_bytes();
    let point1_recovered = G1Point::from_bytes(&bytes1);
    println!("  Original: x={:#x}, y_sign={}", point1.x, point1.y_sign);
    println!(
        "  Recovered: x={:#x}, y_sign={}",
        point1_recovered.x, point1_recovered.y_sign
    );
    println!("  Match: {}\n", point1 == point1_recovered);

    // Test 2: Verify big-endian format
    println!("Test 2: Verify big-endian x-coordinate storage");
    let point2 = G1Point::new(0x0102030405060708, false);
    let bytes2 = point2.to_bytes();
    println!("  x-coordinate bytes (should be big-endian):");
    println!("    bytes[40..48] = {:02X?}", &bytes2[40..48]);
    println!("    Expected: [01, 02, 03, 04, 05, 06, 07, 08]");
    let is_big_endian = bytes2[40] == 0x01 && bytes2[47] == 0x08;
    println!("    Big-endian: {}\n", is_big_endian);

    // Test 3: Verify y-sign bit location
    println!("Test 3: Verify y-sign bit in MSB of byte[0]");
    let point_pos = G1Point::new(42, false);
    let point_neg = G1Point::new(42, true);
    let bytes_pos = point_pos.to_bytes();
    let bytes_neg = point_neg.to_bytes();
    println!(
        "  y_sign=false: byte[0] = {:#04X} (bit 7 = {})",
        bytes_pos[0],
        (bytes_pos[0] & 0x80) >> 7
    );
    println!(
        "  y_sign=true:  byte[0] = {:#04X} (bit 7 = {})",
        bytes_neg[0],
        (bytes_neg[0] & 0x80) >> 7
    );
    let y_sign_correct = (bytes_pos[0] & 0x80) == 0 && (bytes_neg[0] & 0x80) == 0x80;
    println!("    Correct: {}\n", y_sign_correct);

    // Test 4: SharedPublicKey round-trip
    println!("Test 4: SharedPublicKey round-trip");
    let a0 = G1Point::new(0xDEADBEEFCAFEBABE, true);
    let a1 = G1Point::new(0xFEEDFACEDEADC0DE, false);
    let shared_key = SharedPublicKey::new(a0, a1);
    let serialized = serialize_shared_public_key(&shared_key);
    let deserialized = deserialize_shared_public_key(&serialized);
    println!(
        "  Original a0: x={:#x}, y_sign={}",
        shared_key.a0.x, shared_key.a0.y_sign
    );
    println!(
        "  Recovered a0: x={:#x}, y_sign={}",
        deserialized.a0.x, deserialized.a0.y_sign
    );
    println!(
        "  Original a1: x={:#x}, y_sign={}",
        shared_key.a1.x, shared_key.a1.y_sign
    );
    println!(
        "  Recovered a1: x={:#x}, y_sign={}",
        deserialized.a1.x, deserialized.a1.y_sign
    );
    println!("  Match: {}\n", shared_key == deserialized);

    // Test 5: Verify 96-byte serialization
    println!("Test 5: Verify serialization size");
    println!("  SharedPublicKey size: {} bytes", serialized.len());
    println!("  Expected: 96 bytes (48 + 48)");
    println!("  Correct: {}\n", serialized.len() == 96);

    println!("All manual tests completed!");
}
