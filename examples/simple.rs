use binsig::Pattern;

pub fn main() {
    let haystack = &[
        0x11, 0x22, 0x33, 0x0, 0x0, 0x11, 0x22, 0x33, 0x11, 0x0, 0x33,
    ];
    let pattern = Pattern::from_ida("11 ?? 33").expect("Should be valid signature");
    for (pos, view) in pattern.scan(haystack) {
        println!("found needle at {} with bytes {:?}!", pos, view);
    }
}
