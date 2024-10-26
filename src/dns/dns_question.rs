#[derive(Debug, Clone)]
pub struct DomainName {
    pub content: Vec<String>,
}

impl DomainName {
    pub fn new() -> Self {
        let content = Vec::<String>::new();
        DomainName { content }
    }
}

impl From<&[u8]> for DomainName {
    fn from(input: &[u8]) -> DomainName {
        let mut domain_name = DomainName::new();

        if input.len() < 1 {
            return domain_name;
        }

        let mut content_length = input[0] as usize;
        let mut i: usize = 1;

        while i < input.len() {
            if input[i] == 0 {
                break;
            }

            let end_of_content = std::cmp::min(i + content_length, input.len());
            // I thought end_of_content could be len+1 because it's non-inclusive but that's not the case.
            // this needs to take min(end_of_content, len)
            let new_content = String::from_utf8_lossy(&input[i..end_of_content]).to_string();
            domain_name.content.push(new_content);

            let old_i = i;
            i = i + content_length + 1;

            // Set length of next content block
            content_length = input[old_i + content_length] as usize;
        }

        domain_name
    }
}

impl Into<Vec<u8>> for DomainName {
    fn into(self) -> Vec<u8> {
        let mut encoded = Vec::<u8>::new();

        for content in &self.content {
            let content_length = content.len() as u8;

            encoded.push(content_length);
            encoded.extend_from_slice(content.as_bytes());
        }

        encoded.push(0);

        encoded
    }
}

/////////////////////////////////////////////////////
// RESOURCE TYPE
/////////////////////////////////////////////////////
#[derive(Clone)]
pub enum ResourceType {
    A,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
}

impl TryFrom<u16> for ResourceType {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ResourceType::A),
            2 => Ok(ResourceType::NS),
            3 => Ok(ResourceType::MD),
            4 => Ok(ResourceType::MF),
            5 => Ok(ResourceType::CNAME),
            6 => Ok(ResourceType::SOA),
            7 => Ok(ResourceType::MB),
            8 => Ok(ResourceType::MG),
            9 => Ok(ResourceType::MR),
            10 => Ok(ResourceType::NULL),
            11 => Ok(ResourceType::WKS),
            12 => Ok(ResourceType::PTR),
            13 => Ok(ResourceType::HINFO),
            14 => Ok(ResourceType::MINFO),
            15 => Ok(ResourceType::MX),
            16 => Ok(ResourceType::TXT),
            _ => Err("Cannot map value {value}".to_string()),
        }
    }
}

impl ResourceType {
    pub fn value(&self) -> u16 {
        match *self {
            ResourceType::A => 1,
            ResourceType::NS => 2,
            ResourceType::MD => 3,
            ResourceType::MF => 4,
            ResourceType::CNAME => 5,
            ResourceType::SOA => 6,
            ResourceType::MB => 7,
            ResourceType::MG => 8,
            ResourceType::MR => 9,
            ResourceType::NULL => 10,
            ResourceType::WKS => 11,
            ResourceType::PTR => 12,
            ResourceType::HINFO => 13,
            ResourceType::MINFO => 14,
            ResourceType::MX => 15,
            ResourceType::TXT => 16,
        }
    }
}

/////////////////////////////////////////////////////
// RESOURCE CLASS
/////////////////////////////////////////////////////
#[derive(Clone)]
pub enum ResourceClass {
    IN,
    CS,
    CH,
    HS,
    QClassAny,
}
impl TryFrom<u16> for ResourceClass {
    type Error = String;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ResourceClass::IN),
            2 => Ok(ResourceClass::CS),
            3 => Ok(ResourceClass::CH),
            4 => Ok(ResourceClass::HS),
            255 => Ok(ResourceClass::QClassAny),
            _ => Err("Unable to map value {value}".to_string()),
        }
    }
}

impl ResourceClass {
    pub fn value(&self) -> u16 {
        match *self {
            ResourceClass::IN => 1,
            ResourceClass::CS => 2,
            ResourceClass::CH => 3,
            ResourceClass::HS => 4,
            ResourceClass::QClassAny => 255,
        }
    }
}

/////////////////////////////////////////////////////
// QUESTION
/////////////////////////////////////////////////////
#[derive(Clone)]
pub struct Question {
    pub name: DomainName,
    pub resource_type: ResourceType,
    pub resource_class: ResourceClass,
}

impl From<&[u8]> for Question {
    fn from(input: &[u8]) -> Self {
        let len = input.len();

        // The name should be all the bytes up to -4
        let name_end_index = len - 4;
        let slice = &input[..name_end_index];

        let name = DomainName::from(slice);

        // Type should be the bytes -4 to -2
        let (type_start_index, type_end_index) = (len - 4, len - 2);
        let resource_type_bytes = &input[type_start_index..type_end_index];
        let resource_type_u16 = u16::from_be_bytes(resource_type_bytes.try_into().unwrap());
        let resource_type = ResourceType::try_from(resource_type_u16).unwrap();

        // Class should be the last two bytes
        let (class_start_index, class_end_index) = (len - 2, len);
        let class_type_bytes = &input[class_start_index..class_end_index];
        let class_type_u16 = u16::from_be_bytes(class_type_bytes.try_into().unwrap());
        let resource_class = ResourceClass::try_from(class_type_u16).unwrap();

        Question {
            name,
            resource_type,
            resource_class,
        }
    }
}

impl Into<Vec<u8>> for Question {
    fn into(self) -> Vec<u8> {
        let mut output = Vec::<u8>::new();
        let name_bytes: Vec<u8> = self.name.into();
        output.extend_from_slice(&name_bytes.as_slice());

        output.extend_from_slice(&u16::to_be_bytes(1));
        output.extend_from_slice(&u16::to_be_bytes(1));

        output
    }
}
