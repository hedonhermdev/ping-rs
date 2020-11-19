use anyhow::{Result, bail};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IcmpMessageType {
    EchoResponse,
    EchoRequest,
    DestinationUnreachable(u8),
    SourceQuench,
    Redirect(u8),
    TimeExceeded(u8),
    ParameterProblem,
    Timestamp,
    TimestampReply,
    InformationRequest,
    InformationReply,
}


impl IcmpMessageType {
    pub fn into_type_and_code(&self) -> (u8, u8) {
        use IcmpMessageType::*;
        match *self {
            EchoRequest => (8, 0),
            EchoResponse => (0, 0),
            DestinationUnreachable(code) => (3, code),
            SourceQuench => (4, 0),
            Redirect(code) => (5, code),
            TimeExceeded(code) => (11, code),
            ParameterProblem => (12, 0),
            Timestamp => (13, 0),
            TimestampReply => (14, 0),
            InformationRequest => (15, 0),
            InformationReply => (16, 0),
        }
    }

    pub fn from_type_and_code(icmp_type: u8, icmp_code: u8) -> Result<Self> {
        use IcmpMessageType::*;
        match (icmp_type, icmp_code) {
            (0, _) => Ok(EchoResponse),
            (8, _) => Ok(EchoRequest),
            (3, code) => Ok(DestinationUnreachable(code)),
            (4, _) => Ok(SourceQuench),
            (5, code) => Ok(Redirect(code)),
            (11, code) => Ok(TimeExceeded(code)),
            (12, _) => Ok(ParameterProblem),
            (13, _) => Ok(Timestamp),
            (14, _) => Ok(TimestampReply),
            (15, _) => Ok(InformationRequest),
            (16, _) => Ok(InformationReply),
            (_, _) => bail!("Invalid type or code")
        }
    }
}


#[derive(Debug, Clone)]
pub struct IcmpData {
    _type: IcmpMessageType,
    chksum: u16,
    identifier: u16,
    seq_no: u16,
    message: Vec<u8>,
}

impl IcmpData {
    pub fn new(
        mut _type: IcmpMessageType,
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

        let (icmp_type, icmp_code) = self._type.into_type_and_code();
        
        data.push(icmp_type);
        data.push(icmp_code);

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
        let icmp_type = data[0];
        let icmp_code = data[1];

        let _type = IcmpMessageType::from_type_and_code(icmp_type, icmp_code)?;

        let chksum = ((data[2] as u16) << 8) + data[3] as u16;

        let identifier = u16::from_be_bytes([data[4], data[5]]);
        let seq_no = u16::from_be_bytes([data[6], data[7]]);

        let message = Vec::from(&data[8..]);

        Ok(Self {
            _type,
            chksum,
            identifier,
            seq_no,
            message,
        })
    }

    pub fn get_type(&self) -> &IcmpMessageType {
        &self._type
    }

    pub fn get_seq_no(&self) -> u16 {
        self.seq_no
    }
}

pub fn new_echo_request(message: Vec<u8>, identifier: u16, seq_no: u16) -> IcmpData {
    IcmpData::new(IcmpMessageType::EchoRequest, None, Some(identifier), Some(seq_no), Some(message)).expect("Panic! at the Disco")
}
