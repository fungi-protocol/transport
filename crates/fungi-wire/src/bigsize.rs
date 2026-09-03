use crate::DecodeError;

pub(crate) const fn encoded_len(value: u64) -> usize {
    match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

pub(crate) fn encode(value: u64, out: &mut Vec<u8>) {
    match value {
        0..=0xfc => out.push(value as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

pub(crate) fn decode(bytes: &[u8]) -> Result<(u64, usize), DecodeError> {
    let (&first, rest) = bytes.split_first().ok_or(DecodeError::UnexpectedEof)?;
    let (value, width, floor) = match first {
        0xfd => (u64::from(u16::from_be_bytes(take(rest)?)), 3, 0xfd),
        0xfe => (u64::from(u32::from_be_bytes(take(rest)?)), 5, 0x1_0000),
        0xff => (u64::from_be_bytes(take(rest)?), 9, 0x1_0000_0000),
        small => return Ok((u64::from(small), 1)),
    };
    if value < floor {
        return Err(DecodeError::NonMinimalInteger);
    }
    Ok((value, width))
}

fn take<const N: usize>(bytes: &[u8]) -> Result<[u8; N], DecodeError> {
    bytes
        .get(..N)
        .ok_or(DecodeError::UnexpectedEof)?
        .try_into()
        .map_err(|_| DecodeError::UnexpectedEof)
}
