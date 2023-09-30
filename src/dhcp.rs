use heapless::Vec;
use defmt::*;
use embassy_net::Ipv4Address;

#[repr(u8)]
#[derive(Format, Copy, Clone, PartialEq, Eq)]
pub enum Opcode {
    BootRequest = 1,
    BootReply = 2,
}

impl Opcode {
    fn new(op: u8) -> Option<Self> {
        match op {
            1 => Some(Opcode::BootRequest),
            2 => Some(Opcode::BootReply),
            _ => None,
        }
    }
}

// https://www.rfc-editor.org/rfc/rfc1700
#[repr(u8)]
#[derive(Format, Copy, Clone, PartialEq, Eq)]
pub enum HardwareAddressType {
    Ethernet10Mb = 1,
    ExperimentalEthernet3Mb = 2,
    AmateurRadioAx25 = 3,
    ProteonProNetTokenRing = 4,
    Chaos = 5,
    Ieee802Networks = 6,
    Arcnet = 7,
    Hyperchannel = 8,
    Lanstar = 9,
    AutonetShortAddress = 10,
    LocalTalk = 11,
    LocalNet = 12,
    Ultralink = 13,
    Smds = 14,
    FrameRelay = 15,
    AsynchronousTransmissionMode16 = 16,
    Hdlc = 17,
    FibreChannel = 18,
    AsynchronousTransmissionMode19 = 19,
    SerialLine = 20,
    AsynchronousTransmissionMode21 = 21,
}

impl HardwareAddressType {
    fn new(htype: u8) -> Option<Self> {
        use HardwareAddressType::*;

        match htype {
            1 => Some(Ethernet10Mb),
            2 => Some(ExperimentalEthernet3Mb),
            3 => Some(AmateurRadioAx25),
            4 => Some(ProteonProNetTokenRing),
            5 => Some(Chaos),
            6 => Some(Ieee802Networks),
            7 => Some(Arcnet),
            8 => Some(Hyperchannel),
            9 => Some(Lanstar),
            10 => Some(AutonetShortAddress),
            11 => Some(LocalTalk),
            12 => Some(LocalNet),
            13 => Some(Ultralink),
            14 => Some(Smds),
            15 => Some(FrameRelay),
            16 => Some(AsynchronousTransmissionMode16),
            17 => Some(Hdlc),
            18 => Some(FibreChannel),
            19 => Some(AsynchronousTransmissionMode19),
            20 => Some(SerialLine),
            21 => Some(AsynchronousTransmissionMode21),
            _ => None,
        }
    }
}

#[repr(u16)]
#[derive(Format, Copy, Clone, PartialEq, Eq)]
pub enum Flags {
    Unicast = 0,
    Broadcast = 0b1000_0000_0000_0000,
}

impl Flags {
    fn new(flags: u16) -> Option<Self> {
        // invalid flags
        if (flags << 1) != 0 {
            return None;
        }

        if flags == 0 {
            Some(Flags::Unicast)
        } else {
            Some(Flags::Broadcast)
        }
    }
}

#[repr(u8)]
#[derive(Format, Copy, Clone, PartialEq, Eq)]
pub enum DhcpMessageKind {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
}

impl DhcpMessageKind {
    fn new(kind: u8) -> Option<Self> {
        match kind {
            1 => Some(DhcpMessageKind::Discover),
            2 => Some(DhcpMessageKind::Offer),
            3 => Some(DhcpMessageKind::Request),
            4 => Some(DhcpMessageKind::Decline),
            5 => Some(DhcpMessageKind::Ack),
            6 => Some(DhcpMessageKind::Nak),
            7 => Some(DhcpMessageKind::Release),
            _ => None,
        }
    }
}

#[derive(Format, Clone, PartialEq, Eq)]
pub enum DhcpOption<'a> {
    Pad,
    End,
    Hostname { name: &'a [u8] },
    RequestedIpAddress { address: Ipv4Address },
    IpAddressLeaseTime { lease_time: u32 },
    DhcpMessageType { kind: DhcpMessageKind },
    ServerIdentifier { id: Ipv4Address },
    ParameterRequestList { requested_params: &'a [u8] },
    Message { text: &'a [u8] },
    MaximumDhcpMessageSize { size: u16 },
    RenewalTimeValue { time: u32 },
    RebindingTimeValue { time: u32 },
    Unsupported {
        code: u8,
        len: u8,
        data: &'a [u8],
    }
}

#[derive(Format, Clone, PartialEq, Eq)]
pub struct DhcpMessage<'a> {
    /// Message op code / message type.
    pub op: Opcode,

    /// Hardware address type
    pub htype: HardwareAddressType,

    /// Hardware address len
    pub hlen: u8,

    /// Client sets to zero, optionally used by relay agents when booting via a relay agent.
    pub hops: u8, 

    /// Transaction ID, a random number chosen by the client, used by the client and server to associate
    /// messages and responses between a client and a server.
    pub xid: u32,

    /// Filled in by client, seconds elapsed since client began address acquisition or renewal process.
    pub secs: u16,

    pub flags: Flags,

    /// Client IP address; only filled in if client is in BOUND, RENEW or REBINDING state and can respond
    /// to ARP requests.
    pub ciaddr: Ipv4Address,        

    /// 'your' (client) IP address.
    pub yiaddr: Ipv4Address,

    /// IP address of next server to use in bootstrap; returned in DHCPOFFER, DHCPACK by server.
    pub siaddr: Ipv4Address,

    /// Relay agent IP address, used in booting via a relay agent.
    pub giaddr: Ipv4Address,

    /// Client hardware address.
    pub chaddr: [u8; 16],

    /// Optional server host name, null terminated string.
    pub sname: [u8; 64], 

    /// Boot file name, null terminated string; "generic" name or null in DHCPDISCOVER, fully qualified
    /// directory-path name in DHCPOFFER.
    pub file: [u8; 128],

    /// Optional parameters field.  See the options documents for a list of defined options.
    pub options: heapless::Vec<DhcpOption<'a>, 50>,
}

impl<'a> DhcpMessage<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Option<Self> {
        let mut msg = Self {
            op: Opcode::new(data[0])?,
            htype: HardwareAddressType::new(data[1])?,
            hlen: data[2],
            hops: data[3], 
            xid: u32::from_ne_bytes(data[4..8].try_into().ok()?),
            secs: u16::from_ne_bytes(data[8..10].try_into().ok()?),
            flags: Flags::new(u16::from_ne_bytes(data[10..12].try_into().ok()?))?,
            ciaddr: Ipv4Address::from_bytes(&data[12..16]),
            yiaddr: Ipv4Address::from_bytes(&data[16..20]),
            siaddr: Ipv4Address::from_bytes(&data[20..24]),
            giaddr: Ipv4Address::from_bytes(&data[24..28]),
            chaddr: data[28..44].try_into().ok()?,
            sname: data[44..108].try_into().ok()?,
            file: data[108..236].try_into().ok()?,
            options: Vec::new(),
        };

        let mut options = &data[236..];

        // ensure starts with magic cookie
        if &options[..4] != [99, 130, 83, 99] {
            return None;
        }
        options = &options[4..];

        while !options.is_empty() {
            let code = options[0];
            options = &options[1..];

            if code == 0 {
                msg.options.push(DhcpOption::Pad).ok()?;
                continue;
            }

            if code == 255 {
                msg.options.push(DhcpOption::End).ok()?;
                break;
            }

            let len = options[0];
            options = &options[1..];
            let opt_data = &options[..len as usize];
            options = &options[len as usize..];

            // parse all client options
            let option = match code {
                12 => DhcpOption::Hostname { name: opt_data },
                50 => {
                    if len != 4 { warn!("requested IP Address len != 4"); }
                    
                    DhcpOption::RequestedIpAddress { address: Ipv4Address::from_bytes(opt_data) }
                }
                51 => {
                    if len != 4 { warn!("IP Address lease time len != 4"); }

                    DhcpOption::IpAddressLeaseTime { lease_time: u32::from_ne_bytes(opt_data.try_into().ok()?) }
                }
                53 => {
                    if len != 1 { warn!("DHCP Message type len != 1"); }

                    DhcpOption::DhcpMessageType { kind: DhcpMessageKind::new(opt_data[0])? }
                }
                55 => DhcpOption::ParameterRequestList { requested_params: opt_data },
                57 => DhcpOption::MaximumDhcpMessageSize { size: u16::from_ne_bytes(opt_data.try_into().ok()?) },
                58 => DhcpOption::RenewalTimeValue { time: u32::from_ne_bytes(opt_data.try_into().ok()?) },
                59 => DhcpOption::RebindingTimeValue { time: u32::from_ne_bytes(opt_data.try_into().ok()?) },
                _ => {
                    DhcpOption::Unsupported { code, len, data: opt_data }
                }
            };

            msg.options.push(option).ok()?;
        }

        Some(msg)
    }

    pub fn serialise(&self, out_buf: &mut [u8; 4096]) -> usize {
        // fields
        out_buf[0] = self.op as u8;
        out_buf[1] = self.htype as u8;
        out_buf[2] = self.hlen;
        out_buf[3] = self.hops;
        out_buf[4..8].copy_from_slice(&self.xid.to_ne_bytes());
        out_buf[8..10].copy_from_slice(&self.secs.to_ne_bytes());
        out_buf[10..12].copy_from_slice(&u16::to_ne_bytes(self.flags as u16));
        out_buf[12..16].copy_from_slice(&self.ciaddr.0);
        out_buf[16..20].copy_from_slice(&self.yiaddr.0);
        out_buf[20..24].copy_from_slice(&self.siaddr.0);
        out_buf[24..28].copy_from_slice(&self.giaddr.0);
        out_buf[28..44].copy_from_slice(&self.chaddr);
        out_buf[44..108].copy_from_slice(&self.sname);
        out_buf[108..236].copy_from_slice(&self.file);

        // magic cookie! yum!
        out_buf[236..240].copy_from_slice(&[99, 130, 83, 99]);

        // options
        let mut o: usize = 240;
        for opt in &self.options {
            match opt {
                DhcpOption::Pad => {
                    out_buf[o] = 0;
                    o += 1;
                }

                DhcpOption::End => {
                    out_buf[o] = 255;
                    o += 1;
                }

                DhcpOption::Hostname { name } => {
                    out_buf[o] = 12;
                    out_buf[o+1] = name.len().try_into().unwrap();
                    o += 2;
                    out_buf[o..o + name.len()].copy_from_slice(name);
                    o += name.len();
                }

                DhcpOption::RequestedIpAddress { address } => {
                    out_buf[o] = 50;
                    out_buf[o+1] = 4;
                    o += 2;
                    out_buf[o..o+4].copy_from_slice(address.as_bytes());
                    o += 4;
                }

                DhcpOption::IpAddressLeaseTime { lease_time } => {
                    out_buf[o] = 51;
                    out_buf[o+1] = 4;
                    o += 2;
                    out_buf[o..o+4].copy_from_slice(&lease_time.to_ne_bytes());
                    o += 4;
                }

                DhcpOption::DhcpMessageType { kind } => {
                    out_buf[o] = 53;
                    out_buf[o+1] = 1;
                    out_buf[o+2] = *kind as u8;
                    o += 3;
                }

                DhcpOption::ServerIdentifier { id } => {
                    out_buf[o] = 54;
                    out_buf[o+1] = 4;
                    o += 2;
                    out_buf[o..o+4].copy_from_slice(id.as_bytes());
                    o += 4;
                }

                DhcpOption::ParameterRequestList { requested_params } => {
                    out_buf[o] = 55;
                    out_buf[o+1] = requested_params.len().try_into().unwrap();
                    o += 2;
                    out_buf[o..o + requested_params.len()].copy_from_slice(requested_params);
                    o += requested_params.len();
                }

                DhcpOption::Message { text } => {
                    out_buf[o] = 56;
                    out_buf[o+1] = text.len().try_into().unwrap();
                    o += 2;
                    out_buf[o..o + text.len()].copy_from_slice(text);
                    o += text.len();
                }

                DhcpOption::MaximumDhcpMessageSize { size } => {
                    out_buf[o] = 57;
                    out_buf[o+1] = 2;
                    o += 2;
                    out_buf[o..o+2].copy_from_slice(&size.to_ne_bytes());
                    o += 2;
                }

                DhcpOption::RenewalTimeValue { time } => {
                    out_buf[o] = 58;
                    out_buf[o+1] = 4;
                    o += 2;
                    out_buf[o..o+4].copy_from_slice(&time.to_ne_bytes());
                    o += 4;
                }

                DhcpOption::RebindingTimeValue { time } => {
                    out_buf[o] = 59;
                    out_buf[o+1] = 4;
                    o += 2;
                    out_buf[o..o+4].copy_from_slice(&time.to_ne_bytes());
                    o += 4;
                }

                DhcpOption::Unsupported { code, len, data } => {
                    out_buf[o] = *code;
                    out_buf[o + 1] = *len;
                    o += 2;
                    out_buf[o..o + *len as usize].copy_from_slice(data);
                }
            }
        }

        o
    }
}
