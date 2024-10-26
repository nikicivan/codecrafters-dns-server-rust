use crate::dns::dns_header::{DnsHeader, DnsHeaderFlag, QueryResponseIndicator};
use crate::dns::dns_question::Question;

pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<Question>,
    pub answer: Vec<u8>,
    pub authority: Vec<u8>,
    pub extra: Vec<u8>,
}

impl From<&[u8; 512]> for DnsMessage {
    fn from(message: &[u8; 512]) -> Self {
        let header = DnsHeader::from(&message[..=11]);
        let question_count = header.question_count;

        let (questions, section_len) =
            DnsMessage::parse_question_section(&message[12..], question_count).unwrap();

        DnsMessage {
            header,
            questions,
            answer: Vec::with_capacity(500),
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

        let end_points: Vec<usize> = input
            .iter()
            .enumerate()
            .filter_map(|(i, &b)| if b == 0 { Some(i) } else { None })
            .collect();

        if end_points.len() < count_size {
            panic!("There are less endpoints then questions");
        }

        let mut offset = 0;
        for i in 0..(count_size) {
            // One byte for the '0' terminator, two bytes for the type, two bytes for the class
            let end = end_points[i] + 5;

            let q = Question::from(&input[offset..end]);
            questions.push(q);
            offset = end + 1;
        }

        Ok((questions, offset))
    }

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

        // header
        let header_bytes: [u8; 12] = self.header.into();
        bytes[0..=11].copy_from_slice(&header_bytes);

        let mut start = 12;
        let mut end = 0;

        for q in self.questions {
            let q_bytes: Vec<u8> = q.into();

            end = start + q_bytes.len();
            bytes[start..end].copy_from_slice(&q_bytes);
            start = end;
        }

        bytes
    }
}
