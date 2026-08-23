#[kani::proof]
fn addition_preserves_value() {
    let value: u8 = kani::any();
    assert_eq!(value.wrapping_add(1).wrapping_sub(1), value);
}
