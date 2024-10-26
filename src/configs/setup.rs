#[derive(Debug)]
pub struct DnsHeader {
    pub packet_identifier: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_record_count: u16,
    pub authority_record_count: u16,
    pub additional_record_count: u16,
}

impl DnsHeader {
    fn from(bytes: &[u8]) -> Self {
        if bytes.len() != 12 {
            panic!("only slices of length 12 can be converted into a DNS header");
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

pub enum QueryResponseIndicator {
    Query(),
    Response(),
}

impl QueryResponseIndicator {
    fn value(&self) -> u16 {
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

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub position: u8,
}

impl BytePacketBuffer {
    pub fn new() -> Self {
        Self {
            buf: [0; 512],
            position: 0,
        }
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

pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<u8>,
    pub answer: Vec<u8>,
    pub authority: Vec<u8>,
    pub extra: Vec<u8>,
}

impl From<&[u8; 512]> for DnsMessage {
    fn from(message: &[u8; 512]) -> Self {
        let header = DnsHeader::from(&message[..=11]);
        DnsMessage {
            header,
            questions: Vec::with_capacity(500),
            answer: Vec::with_capacity(500),
            authority: Vec::with_capacity(512),
            extra: Vec::with_capacity(512),
        }
    }
}

impl DnsMessage {
    pub fn set_header_flag(&mut self, flag: DnsHeaderFlag) {
        match flag {
            DnsHeaderFlag::Qr(qri) => match qri {
                // Ensures flag is set to '0' regardless of whether current value is 1 or 0
                QueryResponseIndicator::Query() => self.header.flags &= qri.value(),

                // Ensures flag is set to '1' regardless of whether current value is 1 or 0
                QueryResponseIndicator::Response() => self.header.flags |= qri.value(),
            },
            _ => panic!("not implemented"),
        }
    }

    pub fn serialize_as_be(self) -> [u8; 512] {
        let mut bytes: [u8; 512] = [0; 512];

        let header_bytes: [u8; 12] = self.header.into();
        bytes[0..=11].copy_from_slice(&header_bytes);

        bytes
    }
}