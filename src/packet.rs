use anyhow::{Result, bail};

#[derive(Debug, Clone)]
pub struct PacketData {
    _type: u8,
    code: u8,
    chksum: u16,
    identifier: u16,
    seq_no: u16,
    message: Vec<u8>,
}

impl PacketData {
    pub fn new(
        _type: u8,
        code: u8,
        mut chksum: Option<u16>,
        mut identifier: Option<u16>,
        mut seq_no: Option<u16>,
        mut message: Option<Vec<u8>>,
    ) -> Result<Self> {
        if chksum.is_none() {
            chksum = Some(0);
        }

        if identifier.is_none() {
            identifier = Some(0);
        }

        if seq_no.is_none() {
            seq_no = Some(0);
        }

        if message.is_none() {
            message = Some(Vec::<u8>::new());
        }

        Ok(Self {
            _type,
            code,
            chksum: chksum.unwrap(),
            identifier: identifier.unwrap(),
            seq_no: seq_no.unwrap(),
            message: message.unwrap(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        // 0                   1                   2                   3
        // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |     Type      |     Code      |          Checksum             |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |           Identifier          |        Sequence Number        |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |     Data ...
        // +-+-+-+-+-
        let mut data = Vec::new();

        data.push(self._type);

        data.push(self.code);

        // Set checksum to zero
        data.push(0);
        data.push(0);

        let identifier_bytes = self.identifier.to_be_bytes();
        data.push(identifier_bytes[0]);
        data.push(identifier_bytes[1]);

        let seq_no_bytes = self.seq_no.to_be_bytes();
        data.push(seq_no_bytes[0]);
        data.push(seq_no_bytes[1]);

        data.append(&mut self.message.clone());

        let checksum: u16 = pnet::util::checksum(&data, 1);

        let checksum_bytes = checksum.to_be_bytes();

        // Set checksum to computed value
        data[2] = checksum_bytes[0];
        data[3] = checksum_bytes[1];

        data
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        let _type = data[0];
        let code = data[1];

        let chksum = ((data[2] as u16) << 8) + data[3] as u16;

        let identifier = u16::from_be_bytes([data[4], data[5]]);
        let seq_no = u16::from_be_bytes([data[6], data[7]]);

        let message = Vec::from(&data[8..]);

        Ok(Self {
            _type,
            code,
            chksum,
            identifier,
            seq_no,
            message,
        })
    }
}

// BROKEN!
// fn calculate_checksum(data: &Vec<u8>) -> u16 {
//     let mut data = data.clone();

//     let mut checksum: u16 = 0;

//     // Pad with 00000000
//     if data.len() % 2 != 0 {
//         data.push(0);
//     }

//     let mut index = 0;
//     loop {
//         if index == data.len() {
//             break;
//         }

//         let word = ((data[index] as u16) << 8) + (data[index + 1] as u16);

//         const MOD: u32 = (1 << 16) as u32;
//         if (checksum as u32 + word as u32) <= MOD {
//             checksum = checksum + word;
//         } else {
//             checksum = ((checksum as u32 + word as u32 + 1u32) % MOD as u32) as u16;
//         }

//         index += 2;
//     }
//     checksum
// }
