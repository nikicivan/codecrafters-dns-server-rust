use crate::dns::dns_header::DnsHeader;
use crate::dns::dns_question::Question;

use super::dns_question::{DomainName, ResourceClass, ResourceType};

pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<Question>,
    pub answers: Vec<Answer>,
    pub authority: Vec<u8>,
    pub extra: Vec<u8>,
}

impl From<&[u8; 512]> for DnsMessage {
    fn from(message: &[u8; 512]) -> Self {
        let header = DnsHeader::from(&message[..=11]);

        let question_count = header.question_count;

        let (questions, q_section_len) =
            DnsMessage::parse_question_section(&message[12..], question_count).unwrap();

        let answer_count = header.answer_record_count;
        let (answers, _a_section_len) =
            DnsMessage::parse_answer_section(&message[12 + q_section_len..], answer_count).unwrap();

        DnsMessage {
            header,
            questions,
            answers,
            authority: Vec::with_capacity(512),
            extra: Vec::with_capacity(512),
        }
    }
}

impl DnsMessage {
    pub fn parse_question_section(
        input: &[u8],
        count: u16,
    ) -> Result<(Vec<Question>, usize), String> {
        let mut questions = Vec::<Question>::new();
        let count_size = count as usize;

        if input.is_empty() {
            return Ok((questions, 0));
        }

        let mut offset = 0;
        for _i in 0..(count_size) {
            // One byte for the '0' terminator, two bytes for the type, two bytes for the class
            // let end = end_points[i] + 5;

            // let q = Question::from(&input[offset..end]);
            let (q, q_end_index) = Question::deserialize(&input, offset);
            questions.push(q);
            offset = q_end_index + 1;
        }

        Ok((questions, offset))
    }

    pub fn parse_answer_section(input: &[u8], count: u16) -> Result<(Vec<Answer>, usize), String> {
        let mut answers = Vec::<Answer>::new();
        let count_usize = count as usize;
        if input.is_empty() {
            return Ok((answers, 0));
        }
        let mut offset = 0;
        for _i in 0..count_usize {
            let (a, a_end_index) = Answer::deserialize(&input, offset);
            answers.push(a);
            offset = a_end_index + 1;
        }
        Ok((answers, offset))
    }

    pub fn generate_answers(&mut self) {
        let mut answers = Vec::<Answer>::new();
        for q in self.questions.iter() {
            let answer = Answer {
                name: q.name.clone(),
                resource_type: q.resource_type.clone(),
                resource_class: q.resource_class.clone(),
                ttl: 60,
                length: 4,
                data: vec![8, 8, 8, 8],
            };
            answers.push(answer);
            self.header.answer_record_count += 1;
        }
    }

    pub fn serialize_as_be(self) -> [u8; 512] {
        let mut bytes: [u8; 512] = [0; 512];

        // header
        let header_bytes: [u8; 12] = self.header.into();
        bytes[0..=11].copy_from_slice(&header_bytes);

        let mut start = 12;

        for q in self.questions {
            let q_bytes: Vec<u8> = q.clone().into();

            let end = start + q_bytes.len();
            bytes[start..end].copy_from_slice(&q_bytes);
            start = end;
        }

        for a in self.answers {
            let a_bytes: Vec<u8> = a.into();
            dbg!(String::from_utf8_lossy(&a_bytes));
            let end = start + a_bytes.len();
            bytes[start..end].copy_from_slice(&a_bytes);
            start = end;
        }

        bytes
    }
}

pub struct Answer {
    name: DomainName,
    resource_type: ResourceType,
    resource_class: ResourceClass,
    ttl: u32,
    length: u16,
    data: Vec<u8>,
}

impl Answer {
    // pub fn new() -> Self {
    //     Answer {
    //         name: DomainName { content: vec![] },
    //         resource_type: ResourceType::A,
    //         resource_class: ResourceClass::IN,
    //         ttl: 60,
    //         length: 0,
    //         data: vec![],
    //     }
    // }

    pub fn deserialize(input: &[u8], offset: usize) -> (Self, usize) {
        // Deserialize each section of the answer
        // Domain name
        let (name, name_end_index) = DomainName::deserialize(input, offset);

        // resource type
        let (type_start_index, type_end_index) = (name_end_index + 1, name_end_index + 2);
        let resource_type_bytes = &input[type_start_index..=type_end_index];
        let resource_type_u16 = u16::from_be_bytes(resource_type_bytes.try_into().unwrap());
        let resource_type = ResourceType::try_from(resource_type_u16).unwrap();

        // resource class
        let (class_start_index, class_end_index) = (type_end_index + 1, type_end_index + 2);
        let class_type_bytes = &input[class_start_index..=class_end_index];
        let class_type_u16 = u16::from_be_bytes(class_type_bytes.try_into().unwrap());
        let resource_class = ResourceClass::try_from(class_type_u16).unwrap();

        // ttl
        let (ttl_start, ttl_end) = (class_end_index + 1, class_end_index + 4);
        let ttl_bytes = &input[ttl_start..=ttl_end];
        let ttl = u32::from_be_bytes(ttl_bytes.try_into().unwrap());

        // length
        let (length_start, length_end) = (ttl_end + 1, ttl_end + 2);
        let length_bytes = &input[length_start..=length_end];
        let length = u16::from_be_bytes(length_bytes.try_into().unwrap());
        dbg!(&name, &resource_type, &resource_class, ttl, length);

        // data
        let data_start = length_end + 1;
        let data_end = data_start + (length as usize) - 1;
        let data: Vec<u8> = input[data_start..=data_end].to_vec();

        dbg!(data_start, data_end, &input[data_start..=data_end + 1]);
        println!("Data is: {}", String::from_utf8_lossy(&data));
        (
            Answer {
                name,
                resource_type,
                resource_class,
                ttl,
                length,
                data,
            },
            data_end,
        )
    }
}
impl Into<Vec<u8>> for Answer {
    fn into(self) -> Vec<u8> {
        let mut output = Vec::<u8>::new();
        let name_bytes: Vec<u8> = self.name.into();
        output.extend_from_slice(&name_bytes.as_slice());
        //self.resource_type.value()
        // self.resource_class.value()
        output.extend_from_slice(&u16::to_be_bytes(self.resource_type.value()));
        output.extend_from_slice(&u16::to_be_bytes(self.resource_class.value()));
        output.extend_from_slice(&u32::to_be_bytes(self.ttl));
        output.extend_from_slice(&u16::to_be_bytes(self.length));
        output.extend_from_slice(&self.data);
        output
    }
}
