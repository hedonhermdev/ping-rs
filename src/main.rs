use anyhow::{bail, Result};
use dns_lookup::lookup_host;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::ipv4_packet_iter;
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use std::net::{IpAddr, Ipv4Addr};
use std::thread::sleep;
use std::time::Duration;

mod icmp;

use icmp::new_echo_request;
use icmp::IcmpData;
use icmp::IcmpMessageType;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let hostname = args[1].clone();

    let ipaddr = get_ipv4_addr(&hostname).expect("Ip lookup failed");

    println!("{}", ipaddr.to_string());

    let protocol = IpNextHeaderProtocols::Icmp;

    let channel_type = Layer4(Ipv4(protocol));

    let (mut tx, mut rx) = match transport_channel(4096, channel_type) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occured while creating the transport channel: {}",
            e
        ),
    };

    let mut iter = ipv4_packet_iter(&mut rx);

    let mut seq_no: u16 = 0;
    loop {
        let message = String::from("Hello, world").into_bytes();

        let identifier: u16 = 0;
        let packet_data = new_echo_request(message, identifier, seq_no);

        // Increment seq_no
        seq_no += 1;

        let mut v: Vec<u8> = Vec::new();
        for _ in 1..100 {
            v.push(0);
        }

        let payload = packet_data.encode();
        let mut buf: [u8; 20] = [0u8; 20];
        let mut packet = match MutableIpv4Packet::new(&mut buf[..]) {
            Some(packet) => packet,
            None => panic!("Failed here"),
        };

        packet.set_destination(ipaddr);
        packet.set_source(Ipv4Addr::new(192, 168, 1, 100));
        packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);

        let p = packet.packet_mut();
        p[..payload.len()].copy_from_slice(&payload[..]);

        tx.send_to(packet, IpAddr::from(ipaddr))?;

        match iter.next() {
            Ok((packet, address)) => {
                let size = packet.packet().len();
                let ttl = packet.get_ttl();
                let icmp_data = IcmpData::parse(packet.packet())?;

                match icmp_data.get_type() {
                    &IcmpMessageType::EchoResponse => {
                        println!(
                            "{} bytes from {}: icmp_seq={} ttl={} time={}",
                            size,
                            address,
                            icmp_data.get_seq_no(),
                            ttl,
                            0
                        );
                    },
                    _ => {
                        println!("{:?}", icmp_data.get_type());
                    }
                }
            }
            Err(_) => {
                eprintln!("Invalid packet");
            }
        }

        sleep(Duration::from_secs(1));
    }

    Ok(())
}

fn get_ipv4_addr(hostname: &str) -> Result<Ipv4Addr> {
    if let Ok(ips) = lookup_host(hostname) {
        for ip in ips.iter() {
            match *ip {
                IpAddr::V4(ipv4) => {
                    return Ok(ipv4);
                }
                IpAddr::V6(_) => {}
            }
        }
    }

    bail!("Cannot convert hostname to ip address");
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     pub fn test_verify_checkfum() -> Result<()> {
//         let message = String::from("Hello, world").into_bytes();
//         if encoded.len() % 2 != 0 {
//             encoded.push(0);
//         }

//         let mut sum = 0;
//         let mut i = 0;
//         loop {
//             if i == encoded.len() {
//                 break;
//             }
//             let word: u16 = ((encoded[i] as u16) << 8) + encoded[i + 1] as u16;
//             println!("word: {:0>16b}", word);
//             sum += word;
//             i += 2;
//         }

//         println!("sum: {:0>16b}", sum);

//         Ok(())
//     }
// }
