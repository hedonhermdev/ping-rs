use anyhow::{bail, Result};
use dns_lookup::lookup_host;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use pnet::packet::{MutablePacket, Packet};
use pnet::packet::ipv4::*;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::packet::ip::{IpNextHeaderProtocols, IpNextHeaderProtocol};
use pnet::transport::transport_channel;
use pnet::transport::{ipv4_packet_iter};

mod packet;


use packet::PacketData;

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

    {
        let message = String::from("Hello, world").into_bytes();

        let packet_data = PacketData::new(8, 0, None, None, None, Some(message))?;

        let mut v: Vec<u8> = Vec::new();
        for _ in 1..100 {
            v.push(0);
        }
        let mut payload = packet_data.encode();
        let mut buf: [u8; 20] = [0u8; 20];
        let mut packet = match MutableIpv4Packet::new(&mut buf[..]){
            Some(packet) => packet,
            None => panic!("Failed here")
        };

        packet.set_destination(ipaddr);
        packet.set_source(Ipv4Addr::new(192, 168, 1, 100));
        packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);

        let p = packet.packet_mut();
        p[..payload.len()].copy_from_slice(&payload[..]);
        println!("{:?}", p);

        println!("TTL {}", packet.get_ttl());
        tx.send_to(packet, IpAddr::from(ipaddr))?;
    }

    {
        let mut iter = ipv4_packet_iter(&mut rx);

        loop {
            match iter.next() {
                Ok((packet, address)) => { 
                    println!("{:?}", packet.packet());
                    // println!("Recv {} {:?}", new_packet.get_next_level_protocol(), new_packet.payload());
                    let packet_data = PacketData::parse(packet.packet())?;
                    println!("{:?}", packet_data);
                },
                Err(_) => {
                    bail!("Panic here")
                }
            }
        }
    }

}


fn get_ipv4_addr(hostname: &str) -> Result<Ipv4Addr> {
    if let Ok(ips) = lookup_host(hostname) {
        for ip in ips.iter() {
            match *ip {
                IpAddr::V4(ipv4) => { return Ok(ipv4); },
                IpAddr::V6(_) => { }

            }
        }
    }

    bail!("Cannot convert hostname to ip address");
}



#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // pub fn test_calculate_checksum() -> Result<()> {
    //     let message: Vec<u8> = String::from("Hello, world!").into_bytes();

    //     let pack_data = PacketData {
    //         _type: 8,
    //         code: 0,
    //         chksum: 0,
    //         identifier: 0,
    //         seq_no: 0,
    //         message,
    //     };

    //     let encoded = pack_data.encode();

    //     for b in &encoded {
    //         print!("{:0>8b} ", b);
    //     }

    //     println!("");

    //     Ok(())
    // }

    #[test]
    pub fn test_verify_checkfum() -> Result<()> {
        let message = String::from("Hello, world").into_bytes();
        let packet_data = PacketData::new(8, 0, None, None, None, Some(message))?;
        let mut encoded = packet_data.encode();
        if encoded.len() % 2 != 0 {
            encoded.push(0);
        }

        let mut sum = 0;
        let mut i = 0;
        loop {
            if i == encoded.len() {
                break;
            }
            let word: u16 = ((encoded[i] as u16) << 8) + encoded[i+1] as u16; 
            println!("word: {:0>16b}", word);
            sum += word;
            i += 2;
        }

        println!("sum: {:0>16b}", sum);

        Ok(())
    }
}
