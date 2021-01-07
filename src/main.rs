use std::net::SocketAddr;

use std::{io, io::Write};
use trust_dns_proto::op::{Header, Message, MessageType, OpCode, ResponseCode};
use trust_dns_proto::serialize::binary::{BinDecoder, BinDecodable, BinEncodable, BinEncoder};
use trust_dns_client::udp::UdpClientStream;
use trust_dns_client::client::{Client, AsyncClient, ClientHandle};
use trust_dns_proto::xfer::DnsResponse;
use trust_dns_proto::rr::{DNSClass, RecordType, Record, Name};
use trust_dns_server::authority::{MessageResponseBuilder, MessageRequest};
use trust_dns_client::op::LowerQuery;
use std::fs::File;
use std::path::Path;
use std::io::{BufRead, BufReader};
use tokio::sync::mpsc;
use tokio::net::UdpSocket;
use std::sync::Arc;
use tokio::runtime::Runtime;


async fn recurse(query: &LowerQuery) -> Option<Vec<Record>> {
    let stream = UdpClientStream::<UdpSocket>::new(([8,8,8,8], 53).into());
    let (mut client, dns_background) = AsyncClient::connect(stream).await.ok()?;

    // Create a query future
    let name: Name = query.name().into();
    let response = client.query(name, DNSClass::IN, RecordType::A).await.ok()?;

    // validate it's what we expected
    let answers = response.answers().to_owned();

    return Some(answers);
}

fn parse_denylist() -> Option<Vec<String>> {
    let file = File::open("./denylist.txt").ok()?;
    let reader = BufReader::new(file);
    let mut deny_entries:Vec<String> = Vec::with_capacity(4096);

    for line in reader.lines() {
        if let Ok(domain) = line{
            deny_entries.push(domain.trim_start_matches("||").trim_end_matches("^").to_string());
        }
    }

    return Some(deny_entries);
}



async fn handle_request(socket: Arc<UdpSocket>, src: SocketAddr, partial_buf: Vec<u8>, deny_entries: Vec<String>) {
    let mut decoder = BinDecoder::new(&partial_buf);
    let request = MessageRequest::read(&mut decoder).unwrap();

    let header: Header = Header::new();
    let mut message = Message::new();
    message
        .set_id(request.id())
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_authoritative(true)
        .set_recursion_desired(true)
        .set_recursion_available(true)
        .set_authentic_data(true)
        .set_checking_disabled(true);

    let domain = &(request.queries()[0].name().to_string().trim_end_matches(".").to_string());
    if (deny_entries.contains(domain)) {
        message.set_response_code(ResponseCode::NXDomain);
    } else {
        let answers = recurse(&request.queries()[0]).await.unwrap();
        message.add_answers(answers)
            .set_response_code(ResponseCode::NoError);
    }

    let mut byte_vec: Vec<u8> = Vec::with_capacity(512);
    {
        let mut encoder = BinEncoder::new(&mut byte_vec);
        message.emit(&mut encoder).unwrap();
    }

    // tx.send(byte_vec);
    socket.send_to(byte_vec.as_slice(), src).await;
}


#[tokio::main]
async fn main() -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:53").await?;
    let r = Arc::new(socket);

    let mut buf = [0u8; 1024];
    let deny_entries = parse_denylist().unwrap();

    loop {
        let (len, addr) = r.recv_from(&mut buf).await?;
        let deny_list = deny_entries.to_owned();
        let partial_buf = (&mut buf[..len]).to_vec();
        let s = r.clone();
        tokio::spawn(async move {
            handle_request(s, addr, partial_buf, deny_list).await;
        });
    }
}

