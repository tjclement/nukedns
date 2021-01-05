use std::net::{UdpSocket};
use std::{io, io::Write};
use trust_dns_proto::op::{Header, Message, MessageType, OpCode, ResponseCode};
use trust_dns_proto::serialize::binary::{BinDecoder, BinDecodable, BinEncodable, BinEncoder};
use trust_dns_client::udp::UdpClientConnection;
use trust_dns_client::client::{SyncClient, Client};
use trust_dns_proto::xfer::DnsResponse;
use trust_dns_proto::rr::{DNSClass, RecordType, Record, Name};
use trust_dns_server::authority::{MessageResponseBuilder, MessageRequest};
use trust_dns_client::op::LowerQuery;

fn recurse(query: &LowerQuery) -> Vec<Record> {
    let address = "8.8.8.8:53".parse().unwrap();
    let conn = UdpClientConnection::new(address).unwrap();
    let client = SyncClient::new(conn);

    // Specify the name, note the final '.' which specifies it's an FQDN
    let name: Name = query.name().into();

    // NOTE: see 'Setup a connection' example above
    // Send the query and get a message response, see RecordType for all supported options
    let response: DnsResponse = client.query(&name, DNSClass::IN, RecordType::A).unwrap();

    // Messages are the packets sent between client and server in DNS, DnsResonse's can be
    //  dereferenced to a Message. There are many fields to a Message, It's beyond the scope
    //  of these examples to explain them. See trust_dns::op::message::Message for more details.
    //  generally we will be interested in the Message::answers
    let answers = response.answers().to_owned();
    return answers;
}

fn main() -> std::io::Result<()> {
    {
        let socket = UdpSocket::bind("127.0.0.1:1053")?;
        // Receives a single datagram message on the socket. If `buf` is too small to hold
        // the message, it will be cut off.
        let mut buf = [0u8; 1024];
        // let mut byte_vec: Vec<u8> = Vec::with_capacity(512);
        let (amt, src) = socket.recv_from(&mut buf)?;
        let buf = &mut buf[..amt];
        io::stdout().write(&buf)?;
        let mut decoder = BinDecoder::new(&buf);
        let request = MessageRequest::read(&mut decoder).unwrap();
        let answers = recurse(&request.queries()[0]);


        let header: Header = Header::new();
        let mut message = Message::new();
        message
            .set_id(request.id())
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .set_authoritative(true)
            .add_answers(answers)
            .set_recursion_desired(true)
            .set_recursion_available(true)
            .set_authentic_data(true)
            .set_checking_disabled(true)
            .set_response_code(ResponseCode::NoError);

        message.add_answer(Record::new());
        message.add_name_server(Record::new());
        message.add_additional(Record::new());

        let mut byte_vec: Vec<u8> = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut byte_vec);
            message.emit(&mut encoder).unwrap();
        }

        socket.send_to(byte_vec.as_slice(), &src)?;
    } // the socket is closed here
    Ok(())
}