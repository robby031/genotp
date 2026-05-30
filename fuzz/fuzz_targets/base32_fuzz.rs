#![no_main]
use libfuzzer_sys::fuzz_target;
use genotp::{encode, decode};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    
    let encoded = encode(data);
    if let Ok(decoded) = decode(&encoded) {
        assert_eq!(data, &decoded[..data.len()]);
    }
    
    if let Ok(decoded) = decode(&String::from_utf8_lossy(data)) {
        let _ = encode(&decoded);
    }
});
