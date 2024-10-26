use configs::setup::{BytePacketBuffer, DnsHeaderFlag, DnsMessage, QueryResponseIndicator};
use std::convert::From;
#[allow(unused_imports)]
use std::net::UdpSocket;

mod configs;

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    // let mut buf = [0; 512];

    let mut packet = BytePacketBuffer::new();

    loop {
        match udp_socket.recv_from(&mut packet.buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                // let response = [];

                let mut dns_msg = DnsMessage::from(&packet.buf);

                println!("Flags received {}", dns_msg.header.flags);
                dns_msg.set_header_flag(DnsHeaderFlag::Qr(QueryResponseIndicator::Response()));

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
