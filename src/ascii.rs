pub fn from_bytes(input: &[u8]) -> Option<String> {
    input
        .iter()
        .map(|c| (*c).into())
        .filter_map(|c: char| {
            if c.is_ascii_control() {
                None
            } else {
                Some(c.is_ascii().then_some(c).ok_or(()))
            }
        })
        .inspect(|c| {
            if let Ok(ref c) = *c {
                assert!(c.is_ascii(), "non-ascii character found");
            }
        })
        .collect::<Result<String, ()>>()
        .ok()
}
