use std::net::SocketAddr;

use std::{io};
use std::sync::Arc;
use std::time::SystemTime;
use std::collections::HashMap;
use trust_dns_proto::op::{Message, MessageType, OpCode, ResponseCode};
use trust_dns_proto::serialize::binary::{BinDecoder, BinDecodable, BinEncodable, BinEncoder};
use trust_dns_client::udp::UdpClientStream;
use trust_dns_client::client::{AsyncClient, ClientHandle};
use trust_dns_proto::rr::{DNSClass, RecordType, Record, Name};
use trust_dns_server::authority::{MessageRequest};
use trust_dns_client::op::{LowerQuery};
use std::fs::File;
use std::io::{BufRead, BufReader};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::Duration;
use std::ops::Add;

#[derive(Debug, Clone)]
struct Answer {
    expires: SystemTime,
    records: Vec<Record>
}

async fn recurse(query: &LowerQuery) -> Option<Vec<Record>> {
    let stream = UdpClientStream::<UdpSocket>::new(([8,8,8,8], 53).into());
    let (mut client, dns_background) = AsyncClient::connect(stream).await.unwrap();

    tokio::spawn(dns_background);

    // Create a query future
    let name: Name = query.name().into();
    let response = client.query(name, DNSClass::IN, RecordType::A).await.unwrap();

    // validate it's what we expected
    let answers = response.answers().to_owned();

    return Some(answers);
}

fn parse_denylist() -> Option<HashMap<String, bool>> {
    let file = File::open("./denylist.txt").unwrap();
    let reader = BufReader::new(file);
    let mut deny_entries = HashMap::<String, bool>::new();

    for line in reader.lines() {
        if let Ok(domain) = line{
            deny_entries.insert(domain.trim_start_matches("||").trim_end_matches("^").to_string(), true);
            // deny_entries.push(domain.trim_start_matches("||").trim_end_matches("^").to_string());
        }
    }

    return Some(deny_entries);
}



async fn handle_request(socket: Arc<UdpSocket>, src: SocketAddr, partial_buf: Vec<u8>,
                        deny_entries: Arc<HashMap<String, bool>>,
                        query_cache: Arc<RwLock<HashMap<(String, RecordType), Answer>>>) {
    let mut decoder = BinDecoder::new(&partial_buf);
    let request = MessageRequest::read(&mut decoder).unwrap();

    let mut message = Message::new();
    message
        .set_id(request.id())
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_authoritative(false)
        .set_recursion_desired(request.recursion_desired())
        .set_recursion_available(true)
        .set_authentic_data(false)
        .set_checking_disabled(false);

    let query = request.queries()[0].to_owned();
    let domain = query.name().to_string().trim_end_matches(".").to_string();
    if deny_entries.contains_key(&domain) {
        message.set_response_code(ResponseCode::NXDomain)
               .set_authoritative(true);
    } else  {
        let maybe_answers = {
            let read_lock = query_cache.read().await;
            read_lock.get(&(domain.clone(), query.query_type())).cloned()
        };
        let answers = if let Some(answer) = maybe_answers {
            answer.records
        } else {
            let server_answers = recurse(&query).await.unwrap();
            let mut write_cache = query_cache.write().await;
            write_cache.insert((domain.clone(), query.query_type()),
                               Answer {
                                   expires: SystemTime::now()
                                       .add(Duration::from_secs(server_answers[0].ttl() as u64)),
                                   records: server_answers.clone()});
            server_answers
        };

        message.add_query(request.queries()[0].original().to_owned())
            .add_answers(answers)
            .set_response_code(ResponseCode::NoError);
    }

    let mut byte_vec: Vec<u8> = Vec::with_capacity(512);
    {
        let mut encoder = BinEncoder::new(&mut byte_vec);
        message.emit(&mut encoder).unwrap();
    }

    // tx.send(byte_vec);
    socket.send_to(byte_vec.as_slice(), src).await.unwrap();
}

async fn cache_invalidator(query_cache: Arc<RwLock<HashMap<(String, RecordType), Answer>>>) {
    loop {
        let now = SystemTime::now();
        query_cache.write().await.retain(|_, answer| answer.expires > now);
        tokio::time::sleep(Duration::from_secs(1*60)).await;
    }
}


#[tokio::main]
async fn main() -> io::Result<()> {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:53").await?);
    let query_cache: Arc<RwLock<HashMap<(String, RecordType), Answer>>> = Arc::new(RwLock::new(HashMap::new()));

    let mut buf = [0u8; 1024];
    let deny_entries = Arc::new(parse_denylist().unwrap());

    let write_cache = query_cache.clone();
    tokio::spawn(async move {
        cache_invalidator(write_cache).await;
    });

    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        let partial_buf = (&mut buf[..len]).to_vec();
        let sock = socket.clone();
        let deny = deny_entries.clone();
        let cache = query_cache.clone();

        tokio::spawn(async move {
            handle_request(sock, addr, partial_buf, deny, cache).await;
        });
    }
}

