# About `binsig`

This crate provides an easy way to deal with searching for byte patterns using partial byte signatures.

## Usage

```rs
use binsig::Pattern;

let haystack = &[
    0x11, 0x22, 0x33, 0x0, 0x0, 0x11, 0x22, 0x33, 0x11, 0x0, 0x33,
];
let pattern = Pattern::from_ida("11 ?? 33").expect("Should be valid signature");
for (pos, view) in pattern.scan(haystack) {
    println!("found needle at {} with bytes {:?}!", pos, view);
}
```

### Output

```txt
found needle at 0 with bytes [17, 34, 51]!
found needle at 5 with bytes [17, 34, 51]!
found needle at 8 with bytes [17, 0, 51]!
```
