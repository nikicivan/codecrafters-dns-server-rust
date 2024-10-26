use dns::{
    buffer_packets::BytePacketBuffer,
    dns_header::{DnsHeaderFlag, OperationCode, QueryResponseIndicator, ResponseCode},
    dns_message::DnsMessage,
};
use std::convert::From;
#[allow(unused_imports)]
use std::net::UdpSocket;

mod dns;

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let resolver_address = std::env::args()
        .nth(2)
        .unwrap_or("127.0.0.1:2053".to_string());

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    // let mut buf = [0; 512];

    let mut packet = BytePacketBuffer::new();

    println!("Resolver: {}", resolver_address);

    loop {
        match udp_socket.recv_from(&mut packet.buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);

                let mut dns_msg = DnsMessage::from(&packet.buf);

                if resolver_address != "127.0.0.1:2053" {
                    let resolver_socket = UdpSocket::bind("127.0.0.1:0")
                        .expect("Failed to bind to address for resolver");

                    // break into one request per question
                    for i in 0..dns_msg.questions.len() {
                        // Duplicate dns message, but only send one question at a time.
                        let mut partial_dns_msg = DnsMessage {
                            header: dns_msg.header.clone(),
                            questions: vec![dns_msg.questions[i].clone()],
                            answers: vec![],
                            authority: vec![],
                            extra: vec![],
                        };
                        partial_dns_msg.header.question_count = 1;
                        partial_dns_msg.header.additional_record_count = 0;
                        partial_dns_msg.header.answer_record_count = 0;
                        partial_dns_msg.header.authority_record_count = 0;

                        // Send message and parse response
                        let request = partial_dns_msg.serialize_as_be();
                        resolver_socket
                            .send_to(&request, &resolver_address)
                            .unwrap();
                        // Parse response
                        let mut response = BytePacketBuffer::new();
                        match resolver_socket.recv_from(&mut response.buf) {
                            Ok((_size, _source)) => {
                                dbg!(String::from_utf8_lossy(&response.buf));
                                let mut resolver_dns_msg = DnsMessage::from(&response.buf);

                                if resolver_dns_msg.answers.len() > 0 {
                                    let answer = resolver_dns_msg.answers.remove(0);
                                    dns_msg.answers.push(answer);
                                    dns_msg.header.answer_record_count += 1;
                                }
                            }
                            Err(e) => {
                                eprintln!("Error receiving data: {}", e);
                                break;
                            }
                        }
                    }
                } else {
                    dns_msg.generate_answers();
                }

                dns_msg
                    .header
                    .set_header_flag(DnsHeaderFlag::Qr(QueryResponseIndicator::Response()));

                // For some reason the response code is based on the op code?
                match dns_msg.header.get_op_code() {
                    OperationCode::Query() => dns_msg
                        .header
                        .set_header_flag(DnsHeaderFlag::RCode(ResponseCode::NoError)),
                    _ => dns_msg
                        .header
                        .set_header_flag(DnsHeaderFlag::RCode(ResponseCode::NotImp)),
                }

                println!("Flags after modification: {:016b}", dns_msg.header.flags);
                let response: [u8; 512] = dns_msg.serialize_as_be();

                println!("Flags after encoding: {:#?}", &response[..=11]);

                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
