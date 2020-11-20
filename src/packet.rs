use crate::icmp::*;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::{MutablePacket, Packet};

const ICMP_HEADER_LEN: usize = 8;
const ICMP_DATA_LEN: usize = 12;
const PACKET_BUF_LEN: usize = ICMP_HEADER_LEN + ICMP_DATA_LEN;

pub struct IcmpPacket<'a> {
    packet: MutableIpv4Packet<'a>,
    icmp_data: IcmpData,
}

impl<'a> IcmpPacket<'a> {
    pub fn new(buf: &'a mut[u8], icmp_data: IcmpData) -> Self {
        let mut packet = MutableIpv4Packet::new(buf).expect("Unable to create ICMP packet");

        IcmpPacket {
            icmp_data,
            packet,
        }
    }
}


impl Packet for IcmpPacket<'_> {
    fn packet(&self) -> &[u8] {
        return self.packet.packet();
    }

    fn payload(&self) -> &[u8] {
        return self.packet.payload();
    }
}

