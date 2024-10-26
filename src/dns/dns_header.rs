#[derive(Debug)]
pub struct DnsHeader {
    packet_identifier: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_record_count: u16,
    pub authority_record_count: u16,
    pub additional_record_count: u16,
}

impl From<&[u8]> for DnsHeader {
    fn from(bytes: &[u8]) -> Self {
        if bytes.len() != 12 {
            panic!("only slices of length 12 can be converted into a DnsHeader");
        }
        let packet_identifier = u16::from_be_bytes(bytes[0..=1].try_into().unwrap());
        let flags = u16::from_be_bytes(bytes[2..=3].try_into().unwrap());
        let question_count = u16::from_be_bytes(bytes[4..=5].try_into().unwrap());
        let answer_record_count = u16::from_be_bytes(bytes[6..=7].try_into().unwrap());
        let authority_record_count = u16::from_be_bytes(bytes[8..=9].try_into().unwrap());
        let additional_record_count = u16::from_be_bytes(bytes[10..=11].try_into().unwrap());
        DnsHeader {
            packet_identifier,
            flags,
            question_count,
            answer_record_count,
            authority_record_count,
            additional_record_count,
        }
    }
}

impl Into<[u8; 12]> for DnsHeader {
    fn into(self) -> [u8; 12] {
        let mut bytes = [0u8; 12];

        bytes[0..=1].copy_from_slice(&self.packet_identifier.to_be_bytes());
        bytes[2..=3].copy_from_slice(&self.flags.to_be_bytes());
        bytes[4..=5].copy_from_slice(&self.question_count.to_be_bytes());
        bytes[6..=7].copy_from_slice(&self.answer_record_count.to_be_bytes());
        bytes[8..=9].copy_from_slice(&self.authority_record_count.to_be_bytes());
        bytes[10..=11].copy_from_slice(&self.additional_record_count.to_be_bytes());
        bytes
    }
}

impl DnsHeader {
    pub fn set_header_flag(&mut self, flag: DnsHeaderFlag) {
        match flag {
            DnsHeaderFlag::Qr(qri) => match qri {
                // Ensures flag is set to '0' regardless of whether current value is 1 or 0
                QueryResponseIndicator::Query() => self.flags &= qri.value(),
                // Ensures flag is set to '1' regardless of whether current value is 1 or 0
                QueryResponseIndicator::Response() => self.flags |= qri.value(),
            },
            DnsHeaderFlag::RCode(code) => {
                // clear the response code bits
                self.flags &= 0b1111111111110000;
                self.flags |= (code as u16) & 0b0000000000001111;
            }
            _ => {}
        }
    }
    pub fn get_op_code(&self) -> OperationCode {
        // isolate the op code bits and convert to a u8 by shifting
        let op_bits = (self.flags & 0b0111100000000000) >> 11;
        OperationCode::try_from(op_bits as u8).unwrap()
    }
}

pub enum DnsHeaderFlag {
    Qr(QueryResponseIndicator),
    OpCode(OperationCode),
    Aa(bool),
    Tc(bool),
    Rd(bool),
    Ra(bool),
    Z(Reserved),
    RCode(ResponseCode),
}

pub enum QueryResponseIndicator {
    Query(),
    Response(),
}

impl QueryResponseIndicator {
    pub fn value(&self) -> u16 {
        match *self {
            QueryResponseIndicator::Query() => 0b0000_0000_0000_0000,
            QueryResponseIndicator::Response() => 0b1000_0000_0000_0000,
        }
    }
}

pub enum OperationCode {
    Query(),
    IQuery(),
    Unassigned(),
    Status(),
    Notify(),
    Update(),
    DnsStatefulOperations(),
}

impl OperationCode {
    fn value(&self) -> u8 {
        match *self {
            OperationCode::Query() => 0,
            OperationCode::IQuery() => 1,
            OperationCode::Unassigned() => 2,
            OperationCode::Status() => 3,
            OperationCode::Notify() => 4,
            OperationCode::Update() => 5,
            OperationCode::DnsStatefulOperations() => 6,
        }
    }
}

impl TryFrom<u8> for OperationCode {
    type Error = String;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(OperationCode::Query()),
            1 => Ok(OperationCode::IQuery()),
            2 => Ok(OperationCode::Status()),
            3 => Ok(OperationCode::Unassigned()),
            4 => Ok(OperationCode::Notify()),
            5 => Ok(OperationCode::Update()),
            6 => Ok(OperationCode::DnsStatefulOperations()),
            _ => unreachable!(),
        }
    }
}

pub enum Reserved {
    Unassigned(),
}

#[derive(Debug)]
pub enum ResponseCode {
    NoError = 0,      // No Error [RFC1035]
    FormErr = 1,      // Format Error [RFC1035]
    ServFail = 2,     // Server Failure [RFC1035]
    NXDomain = 3,     // Non-Existent Domain [RFC1035]
    NotImp = 4,       // Not Implemented [RFC1035]
    Refused = 5,      // Query Refused [RFC1035]
    YXDomain = 6,     // Name Exists when it should not [RFC2136][RFC6672]
    YXRRSet = 7,      // RR Set Exists when it should not [RFC2136]
    NXRRSet = 8,      // RR Set that should exist does not [RFC2136]
    NotAuth = 9,      // Not Authorized [RFC8945]; Server Not Authoritative for zone [RFC2136]
    NotZone = 10,     // Name not contained in zone [RFC2136]
    DSOTYPENI = 11,   // DSO-TYPE Not Implemented [RFC8490]
    Unassigned = 12,  // Unassigned
    BADVERS = 16,     // Bad OPT Version [RFC6891]; TSIG Signature Failure [RFC8945]
    BADKEY = 17,      // Key not recognized [RFC8945]
    BADTIME = 18,     // Signature out of time window [RFC8945]
    BADMODE = 19,     // Bad TKEY Mode [RFC2930]
    BADNAME = 20,     // Duplicate key name [RFC2930]
    BADALG = 21,      // Algorithm not supported [RFC2930]
    BADTRUNC = 22,    // Bad Truncation [RFC8945]
    BADCOOKIE = 23,   // Bad/missing Server Cookie [RFC7873]
    Reserved = 65535, // Reserved, can be allocated by Standards Action
}
