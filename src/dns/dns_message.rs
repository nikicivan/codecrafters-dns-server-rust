use crate::dns::dns_header::{DnsHeader, DnsHeaderFlag, QueryResponseIndicator};
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
        let mut header = DnsHeader::from(&message[..=11]);
        let question_count = header.question_count;

        let (questions, section_len) =
            DnsMessage::parse_question_section(&message[12..], question_count).unwrap();

        let mut answers = Vec::<Answer>::new();

        for q in questions.iter() {
            let answer = Answer {
                name: q.name.clone(),
                resource_type: q.resource_type.clone(),
                resource_class: q.resource_class.clone(),
                ttl: 60,
                length: 4,
                data: 8888,
            };

            answers.push(answer);
            header.answer_record_count += 1;
        }

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

        // let end_points: Vec<usize> = input
        //     .iter()
        //     .enumerate()
        //     .filter_map(|(i, &b)| if b == 0 { Some(i) } else { None })
        //     .collect();

        // if end_points.len() < count_size {
        //     panic!("There are less endpoints then questions");
        // }

        let mut offset = 0;
        for i in 0..(count_size) {
            // One byte for the '0' terminator, two bytes for the type, two bytes for the class
            // let end = end_points[i] + 5;

            // let q = Question::from(&input[offset..end]);
            let (q, q_end_index) = Question::deserialize(&input, offset);
            questions.push(q);
            offset = q_end_index + 1;
        }

        Ok((questions, offset))
    }

    // pub fn set_header_flag(&mut self, flag: DnsHeaderFlag) {
    //     match flag {
    //         DnsHeaderFlag::Qr(qri) => match qri {
    //             // Ensures flag is set to '0' regardless of whether current value is 1 or 0
    //             QueryResponseIndicator::Query() => self.header.flags &= qri.value(),

    //             // Ensures flag is set to '1' regardless of whether current value is 1 or 0
    //             QueryResponseIndicator::Response() => self.header.flags |= qri.value(),
    //         },
    //         _ => panic!("not implemented"),
    //     }
    // }

    pub fn serialize_as_be(self) -> [u8; 512] {
        let mut bytes: [u8; 512] = [0; 512];

        // header
        let header_bytes: [u8; 12] = self.header.into();
        bytes[0..=11].copy_from_slice(&header_bytes);

        let mut start = 12;
        let mut end = 0;

        for q in self.questions {
            let q_bytes: Vec<u8> = q.clone().into();

            end = start + q_bytes.len();
            bytes[start..end].copy_from_slice(&q_bytes);
            start = end;
        }

        for a in self.answers {
            let a_bytes: Vec<u8> = a.into();
            dbg!(String::from_utf8_lossy(&a_bytes));
            end = start + a_bytes.len();
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
    data: u32,
}
impl Answer {
    pub fn new() -> Self {
        Answer {
            name: DomainName { content: vec![] },
            resource_type: ResourceType::A,
            resource_class: ResourceClass::IN,
            ttl: 60,
            length: 0,
            data: 0,
        }
    }
}
impl Into<Vec<u8>> for Answer {
    fn into(self) -> Vec<u8> {
        let mut output = Vec::<u8>::new();
        let name_bytes: Vec<u8> = self.name.into();
        output.extend_from_slice(&name_bytes.as_slice());
        //self.resource_type.value()
        // self.resource_class.value()
        output.extend_from_slice(&u16::to_be_bytes(1));
        output.extend_from_slice(&u16::to_be_bytes(1));
        output.extend_from_slice(&u32::to_be_bytes(self.ttl));
        output.extend_from_slice(&u16::to_be_bytes(self.length));
        output.extend_from_slice(&u32::to_be_bytes(self.data));
        output
    }
}
