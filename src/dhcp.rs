use heapless::Vec;
use defmt::*;
use embassy_net::Ipv4Address;

#[repr(u8)]
#[derive(Format)]
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
#[derive(Format)]
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
#[derive(Format)]
pub enum Flags {
    Empty = 0,
    Broadcast = 0b1000_0000_0000_0000,
}

impl Flags {
    fn new(flags: u16) -> Option<Self> {
        // invalid flags
        if (flags << 1) != 0 {
            return None;
        }

        if flags == 0 {
            Some(Flags::Empty)
        } else {
            Some(Flags::Broadcast)
        }
    }
}

#[repr(u8)]
#[derive(Format)]
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

#[derive(Format)]
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

#[derive(Format)]
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
}
