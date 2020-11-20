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
use nix::ifaddrs;
use nix::sys::socket::InetAddr;
use nix::sys::socket::SockAddr;

mod icmp;
mod packet;

use icmp::new_echo_request;
use icmp::IcmpData;
use icmp::IcmpMessageType;



fn get_self_ipaddr() -> Result<Ipv4Addr> {
    // This is ugly pls refactor
    let addrs = ifaddrs::getifaddrs().expect("Unable to get host IP address");
    let mut ipv4_addr = Ipv4Addr::new(0, 0, 0, 0);
    for addr in addrs {
        match addr.address {
            Some(address) => {
                match address {
                    SockAddr::Inet(inet_addr) => {
                        let ip_addr = inet_addr.ip();
                        match ip_addr.to_std() {
                            IpAddr::V4(a) => {
                                ipv4_addr = a;
                            },
                            _ => {
                                 continue;
                            }
                        }
                    },
                    _ => {}
                }
            },
            None => {}
        }
    }

    Ok(ipv4_addr)

}


fn main() -> Result<()> {
    let src_ip = get_self_ipaddr()?;
    let args: Vec<String> = std::env::args().collect();
    let hostname = args[1].clone();

    let ipaddr = get_ipv4_addr(&hostname).expect("Ip lookup failed");

    println!("PONG {}({})", args[1], ipaddr.to_string());

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
        let message = String::from("Hello world!").into_bytes();

        let identifier: u16 = 0;
        let icmp_data = new_echo_request(message, identifier, seq_no);

        // Increment seq_no
        seq_no += 1;

        let payload = icmp_data.encode();
        let mut buf: [u8; 20] = [0u8; 20];
        let mut packet = match MutableIpv4Packet::new(&mut buf[..]) {
            Some(packet) => packet,
            None => panic!("Failed here"),
        };

        packet.set_destination(ipaddr);
        packet.set_source(src_ip);
        packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);

        let p = packet.packet_mut();
        p[..payload.len()].copy_from_slice(&payload[..]);


        let instant = std::time::Instant::now();
        tx.send_to(packet, IpAddr::from(ipaddr))?;

        match iter.next() {
            Ok((packet, address)) => {
                let rtt = instant.elapsed().as_secs_f64() * 1000f64;
                let size = packet.packet().len();
                let ttl = packet.get_ttl();
                let icmp_data = IcmpData::parse(packet.packet())?;

                match icmp_data.get_type() {
                    &IcmpMessageType::EchoResponse => {
                        println!(
                            "{} bytes from {}: icmp_seq={} ttl={} time={:.2}ms",
                            size,
                            address,
                            icmp_data.get_seq_no(),
                            ttl,
                            rtt,
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

        // Wait one second before sending next packet
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

