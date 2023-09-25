use std::{iter::Enumerate, mem::size_of, slice::Windows};

use itertools::Itertools;

#[derive(Debug, thiserror::Error)]
pub enum ScannerError {
    #[error("Invalid atom size {0}")]
    InvalidAtomSize(usize),

    #[error("Utf8 error {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("Try from slice failed {0}")]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    #[error("Parse int failed {0}")]
    ParseInt(#[from] std::num::ParseIntError),
}

// TODO: Rename Atom to something else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Atom {
    LongLong(u64),
    Long(u32),
    Short(u16),
    Byte(u8),
    Mask(usize),
}

impl Atom {
    fn from_bytes(bytes: &[u8]) -> Result<Vec<Self>, ScannerError> {
        match bytes.len() {
            8 => Ok(vec![Self::LongLong(u64::from_ne_bytes(bytes.try_into()?))]),
            7 => Ok(vec![
                Self::Long(u32::from_ne_bytes(bytes[0..=3].try_into()?)),
                Self::Short(u16::from_ne_bytes(bytes[4..=5].try_into()?)),
                Self::Byte(bytes[6]),
            ]),
            6 => Ok(vec![
                Self::Long(u32::from_ne_bytes(bytes[0..=3].try_into()?)),
                Self::Short(u16::from_ne_bytes(bytes[4..=5].try_into()?)),
            ]),
            5 => Ok(vec![
                Self::Long(u32::from_ne_bytes(bytes[0..=3].try_into()?)),
                Self::Byte(bytes[4]),
            ]),
            4 => Ok(vec![Self::Long(u32::from_ne_bytes(bytes.try_into()?))]),
            3 => Ok(vec![
                Self::Short(u16::from_ne_bytes(bytes[0..=1].try_into()?)),
                Self::Byte(bytes[2]),
            ]),
            2 => Ok(vec![Self::Short(u16::from_ne_bytes(bytes.try_into()?))]),
            1 => Ok(vec![Self::Byte(bytes[0])]),
            invalid_len => Err(ScannerError::InvalidAtomSize(invalid_len)),
        }
    }

    fn size(&self) -> usize {
        match self {
            Atom::LongLong(_) => 8,
            Atom::Long(_) => 4,
            Atom::Short(_) => 2,
            Atom::Byte(_) => 1,
            Atom::Mask(len) => *len,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pattern {
    atoms: Vec<Atom>,
}

// TODO: pull this out into a trait then impl for Ida and byte mask
impl Pattern {
    pub fn new(atoms: Vec<Atom>) -> Self {
        Self { atoms }
    }

    pub fn size(&self) -> usize {
        self.atoms.iter().fold(0, |accum, atom| accum + atom.size())
    }

    pub fn scan<'a>(&self, bytes: &'a [u8]) -> Scanner<'a> {
        Scanner::new(self.clone(), bytes)
    }

    pub fn is_matching<'a>(&self, mut bytes: &'a [u8]) -> bool {
        let take_forward = |b: &mut &'a [u8], n: usize| -> &'a [u8] {
            let (taken, untouched) = b.split_at(n);
            *b = untouched;
            taken
        };

        self.atoms.iter().all(|a| match a {
            Atom::LongLong(val) => {
                u64::from_ne_bytes(
                    take_forward(&mut bytes, size_of::<u64>())
                        .try_into()
                        .unwrap(),
                ) == *val
            }
            Atom::Long(val) => {
                u32::from_ne_bytes(
                    take_forward(&mut bytes, size_of::<u32>())
                        .try_into()
                        .unwrap(),
                ) == *val
            }
            Atom::Short(val) => {
                u16::from_ne_bytes(
                    take_forward(&mut bytes, size_of::<u16>())
                        .try_into()
                        .unwrap(),
                ) == *val
            }
            Atom::Byte(val) => {
                u8::from_ne_bytes(
                    take_forward(&mut bytes, size_of::<u8>())
                        .try_into()
                        .unwrap(),
                ) == *val
            }
            Atom::Mask(len) => {
                take_forward(&mut bytes, *len);
                true
            }
        })
    }

    pub fn from_ida(str: &str) -> Result<Self, ScannerError> {
        // TODO: Add checks to make sure its valid.
        let masked_bytes = &str
            .split(" ")
            .enumerate()
            .filter_map(|(pos, s)| match s {
                "??" => Some(pos),
                _ => None,
            })
            .collect::<Vec<usize>>();

        let pat = Self::from_bytes(
            &str.replace("??", "CC")
                .as_str()
                .replace(" ", "")
                .as_bytes()
                .chunks(2)
                .map(std::str::from_utf8)
                .collect::<Result<Vec<&str>, _>>()?
                .into_iter()
                .map(|hex| u8::from_str_radix(hex, 16))
                .collect::<Result<Vec<u8>, _>>()?,
            masked_bytes,
        );

        Ok(pat)
    }

    pub fn from_bytes(bytes: &[u8], mask_bytes: &[usize]) -> Self {
        let atoms = bytes
            .into_iter()
            .enumerate()
            .group_by(|(idx, _)| mask_bytes.contains(idx))
            .into_iter()
            .map(|(m, g)| (m, g.map(|(_, b)| *b).collect::<Vec<u8>>()))
            .flat_map(|(masked, segment)| -> Vec<Atom> {
                match masked {
                    true => vec![Atom::Mask(segment.len())],
                    false => segment
                        .chunks(8)
                        .flat_map(|c| Atom::from_bytes(c).unwrap())
                        .collect::<Vec<Atom>>(),
                }
            })
            .collect();

        Self::new(atoms)
    }
}

pub struct Scanner<'a> {
    it: Enumerate<Windows<'a, u8>>,
    pattern: Pattern,
}

impl<'a> Scanner<'a> {
    pub fn new(pattern: Pattern, bytes: &'a [u8]) -> Self {
        Self {
            it: bytes.windows(pattern.size()).enumerate(),
            pattern,
        }
    }
}

impl<'a> Iterator for Scanner<'a> {
    type Item = (usize, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        self.it
            .find_map(|(pos, view)| self.pattern.is_matching(view).then(|| (pos, view)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes() {
        assert_eq!(
            Pattern::new(vec![Atom::Byte(0x11)]),
            Pattern::from_bytes(&[0x11], &[])
        );
        assert_eq!(
            Pattern::new(vec![Atom::Short(0x2211)]),
            Pattern::from_bytes(&[0x11, 0x22], &[])
        );
        assert_eq!(
            Pattern::new(vec![Atom::Short(0x2211), Atom::Byte(0x33)]),
            Pattern::from_bytes(&[0x11, 0x22, 0x33], &[])
        );
        assert_eq!(
            Pattern::new(vec![Atom::Long(0x44332211)]),
            Pattern::from_bytes(&[0x11, 0x22, 0x33, 0x44], &[])
        );
    }

    #[test]
    fn test_masked_bytes() {
        assert_eq!(
            Pattern::new(vec![Atom::Byte(0x11), Atom::Mask(1), Atom::Byte(0x22)]),
            Pattern::from_bytes(&[0x11, 0x0, 0x22], &[1])
        );
        assert_eq!(
            Pattern::new(vec![Atom::Byte(0x11), Atom::Mask(2), Atom::Byte(0x22)]),
            Pattern::from_bytes(&[0x11, 0x0, 0x0, 0x22], &[1, 2])
        );
        assert_eq!(
            Pattern::new(vec![
                Atom::Byte(0x11),
                Atom::Mask(2),
                Atom::Byte(0x22),
                Atom::Mask(1),
                Atom::Byte(0x33)
            ]),
            Pattern::from_bytes(&[0x11, 0x0, 0x0, 0x22, 0x0, 0x33], &[1, 2, 4])
        );
    }

    #[test]
    fn test_str() {
        assert_eq!(
            Pattern::new(vec![Atom::Byte(0x11)]),
            Pattern::from_ida("11").unwrap()
        );
        assert_eq!(
            Pattern::new(vec![Atom::Short(0x2211)]),
            Pattern::from_ida("11 22").unwrap()
        );
        assert_eq!(
            Pattern::new(vec![Atom::Short(0x2211)]),
            Pattern::from_ida("1122").unwrap()
        );
        assert_eq!(
            Pattern::new(vec![Atom::Short(0x2211), Atom::Byte(0x33)]),
            Pattern::from_ida("11 22 33").unwrap()
        );

        assert_eq!(
            Pattern::new(vec![Atom::Long(0x44332211)]),
            Pattern::from_ida("11 22 33 44").unwrap()
        );
    }

    #[test]
    fn test_masked_str() {
        assert_eq!(
            Pattern::new(vec![Atom::Byte(0x11), Atom::Mask(1), Atom::Byte(0x22)]),
            Pattern::from_ida("11 ?? 22").unwrap()
        );
        assert_eq!(
            Pattern::new(vec![Atom::Byte(0x11), Atom::Mask(2), Atom::Byte(0x22)]),
            Pattern::from_ida("11 ?? ?? 22").unwrap()
        );
        assert_eq!(
            Pattern::new(vec![
                Atom::Byte(0x11),
                Atom::Mask(2),
                Atom::Byte(0x22),
                Atom::Mask(2),
                Atom::Byte(0x33)
            ]),
            Pattern::from_ida("11 ?? ?? 22 ?? ?? 33").unwrap()
        );
    }

    #[test]
    fn test_matching() {
        assert_eq!(
            true,
            Pattern::new(vec![Atom::Byte(0x11), Atom::Mask(1), Atom::Byte(0x22)])
                .is_matching(&[0x11, 0x44, 0x22])
        );
        assert_eq!(
            false,
            Pattern::new(vec![Atom::Byte(0x11), Atom::Mask(1), Atom::Byte(0x22)])
                .is_matching(&[0x11, 0x44, 0x00])
        );
        assert_eq!(
            true,
            Pattern::new(vec![Atom::Byte(0x11), Atom::Mask(2), Atom::Byte(0x22)])
                .is_matching(&[0x11, 0x44, 0x00, 0x22])
        );
        assert_eq!(
            false,
            Pattern::new(vec![
                Atom::Byte(0x11),
                Atom::Mask(2),
                Atom::Byte(0x22),
                Atom::Mask(1),
                Atom::Byte(0x33)
            ])
            .is_matching(&[0x11, 0x44, 0x00, 0x00, 0x00, 0x33])
        );
    }

    #[test]
    fn test_find_all() {
        let haystack = &[
            0x11, 0x22, 0x33, 0x0, 0x0, 0x11, 0x22, 0x33, 0x11, 0x0, 0x33,
        ];
        assert_eq!(
            vec![0, 5, 8],
            Pattern::new(vec![Atom::Byte(0x11), Atom::Mask(1), Atom::Byte(0x33)])
                .scan(haystack)
                .map(|t| t.0)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            vec![0],
            Pattern::new(vec![Atom::Long(0x332211)])
                .scan(haystack)
                .map(|t| t.0)
                .collect::<Vec<_>>()
        );
    }
}
