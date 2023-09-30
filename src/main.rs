#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

use defmt::*;
use embassy_executor::Spawner;
use embassy_net::tcp::client::{TcpClient, TcpClientState};
use embassy_net::udp::{UdpSocket, PacketMetadata};
use embassy_net::{Stack, StackResources, Ipv4Address, Ipv4Cidr, IpEndpoint, IpAddress};
use embassy_stm32::eth::generic_smi::GenericSMI;
use embassy_stm32::eth::{Ethernet, PacketQueue};
use embassy_stm32::peripherals::ETH;
use embassy_stm32::rng::Rng;
use embassy_stm32::{bind_interrupts, eth, peripherals, rng, Config};
use embassy_time::{Duration, Timer};
use embedded_io_async::Write;
use embedded_nal_async::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpConnect};
use rand_core::RngCore;
use static_cell::make_static;
use {defmt_rtt as _, panic_probe as _};
use heapless::Vec;

mod dhcp;
use dhcp::{DhcpMessage, DhcpOption};

bind_interrupts!(struct Irqs {
    ETH => eth::InterruptHandler;
    RNG => rng::InterruptHandler<peripherals::RNG>;
});

type Device = Ethernet<'static, ETH, GenericSMI>;

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
const SERVER_IP: Ipv4Address = Ipv4Address::new(10, 8, 3, 1);
const ASSIGNED_CLIENT_IP: Ipv4Address = Ipv4Address::new(10, 8, 3, 2);
const DHCP_REMOTE_ENDPOINT: IpEndpoint = IpEndpoint { 
    addr: IpAddress::Ipv4(Ipv4Address::BROADCAST),
    port: DHCP_CLIENT_PORT,
};

#[embassy_executor::task]
async fn net_task(stack: &'static Stack<Device>) -> ! {
    stack.run().await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) -> ! {
    let mut config = Config::default();
    {
        use embassy_stm32::rcc::*;
        config.rcc.hsi = Some(Hsi::Mhz64);
        config.rcc.csi = true;
        config.rcc.hsi48 = true; // needed for RNG
        config.rcc.pll_src = PllSource::Hsi;
        config.rcc.pll1 = Some(Pll {
            prediv: 4,
            mul: 50,
            divp: Some(2),
            divq: None,
            divr: None,
        });
        config.rcc.sys = Sysclk::Pll1P; // 400 Mhz
        config.rcc.ahb_pre = AHBPrescaler::DIV2; // 200 Mhz
        config.rcc.apb1_pre = APBPrescaler::DIV2; // 100 Mhz
        config.rcc.apb2_pre = APBPrescaler::DIV2; // 100 Mhz
        config.rcc.apb3_pre = APBPrescaler::DIV2; // 100 Mhz
        config.rcc.apb4_pre = APBPrescaler::DIV2; // 100 Mhz
        config.rcc.voltage_scale = VoltageScale::Scale1;
    }
    let p = embassy_stm32::init(config);
    info!("Initialised clocks");

    // Generate random seed.
    let mut rng = Rng::new(p.RNG, Irqs);
    let mut seed = [0; 8];
    rng.fill_bytes(&mut seed);
    let seed = u64::from_le_bytes(seed);

    let mac_addr = [0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];

    let device = Ethernet::new(
        make_static!(PacketQueue::<16, 16>::new()),
        p.ETH,
        Irqs,
        p.PA1,
        p.PA2,
        p.PC1,
        p.PA7,
        p.PC4,
        p.PC5,
        p.PG13,
        p.PB13,
        p.PG11,
        GenericSMI::new(),
        mac_addr,
        0,
    );

    let config = embassy_net::Config::ipv4_static(embassy_net::StaticConfigV4 {
        address: Ipv4Cidr::new(SERVER_IP, 24),
        dns_servers: Vec::new(),
        gateway: None,
    });

    // Init network stack
    let stack = &*make_static!(Stack::new(
        device,
        config,
        make_static!(StackResources::<2>::new()),
        seed
    ));

    // Launch network task
    unwrap!(spawner.spawn(net_task(stack)));

    // Ensure DHCP configuration is up before trying connect
    stack.wait_config_up().await;

    info!("Network task initialized");

    static STATE: TcpClientState<1, 1024, 1024> = TcpClientState::new();
    let client = TcpClient::new(stack, &STATE);

    let mut rx_meta = [PacketMetadata::EMPTY; 16];
    let mut rx_buffer = [0; 4096];
    let mut tx_meta = [PacketMetadata::EMPTY; 16];
    let mut tx_buffer = [0; 4096];
    let mut buf = [0; 4096];
    let mut udp_sock = UdpSocket::new(
        stack,
        &mut rx_meta,
        &mut rx_buffer,
        &mut tx_meta,
        &mut tx_buffer,
    );
    udp_sock.bind(DHCP_SERVER_PORT).unwrap();
    info!("Udp socket bound!");
    loop {
        let (n, ep) = udp_sock.recv_from(&mut buf).await.unwrap();

        let Some(msg) = DhcpMessage::from_bytes(&buf[..n]) else {
            continue
        };
        debug!("Parsed DHCP message: {:?}", msg);

        for opt in &msg.options {
            let DhcpOption::Hostname { name } = opt else {
                continue
            };

            let Ok(hostname) = core::str::from_utf8(name) else {
                warn!("hostname contained invalid ASCII data.");
                continue;
            };

            info!("Got hostname: {=str}", hostname);
        }

        for opt in &msg.options {
            let DhcpOption::DhcpMessageType { kind } = opt else {
                continue
            };

            info!("DHCP message kind: {}", kind);
        }

        let transaction_id = msg.xid;
        let client_hardware_address = msg.chaddr;
        let client_hardware_address_len = msg.hlen;

        drop(msg);

        // respond with DHCPOFFER
        let reply = DhcpMessage {
            op: dhcp::Opcode::BootReply,
            htype: dhcp::HardwareAddressType::Ethernet10Mb,
            hlen: client_hardware_address_len,
            hops: 0,
            xid: transaction_id,
            secs: 0,
            flags: dhcp::Flags::Unicast,
            ciaddr: Ipv4Address::UNSPECIFIED,
            yiaddr: ASSIGNED_CLIENT_IP,
            siaddr: SERVER_IP,
            giaddr: Ipv4Address::UNSPECIFIED,
            chaddr: client_hardware_address,
            sname: [0u8; 64],
            file: [0u8; 128],
            options: Vec::from_slice(&[
                DhcpOption::DhcpMessageType { kind: dhcp::DhcpMessageKind::Offer },
                DhcpOption::ServerIdentifier { id: SERVER_IP },
                DhcpOption::End
            ]).unwrap(),
        };
        debug!("Sending response: {}", reply);

        let reply_ser_len = reply.serialise(&mut buf);
        info!("Serialised response into {} bytes: {:02x}", reply_ser_len, &buf[..reply_ser_len]);

        info!("Sending DHCPOFFER message to {}", DHCP_REMOTE_ENDPOINT);
        udp_sock.send_to(&buf[..reply_ser_len], DHCP_REMOTE_ENDPOINT).await.unwrap();
        // let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 8, 3, 2), 80));

        // info!("connecting...");
        // let r = client.connect(addr).await;
        // if let Err(e) = r {
        //     info!("connect error: {:?}", e);
        //     Timer::after(Duration::from_secs(1)).await;
        //     continue;
        // }
        // let mut connection = r.unwrap();
        // info!("connected!");
        // loop {
        //     let r = connection.write_all(b"Hello\n").await;
        //     if let Err(e) = r {
        //         info!("write error: {:?}", e);
        //         break;
        //     }
        //     Timer::after(Duration::from_secs(1)).await;
        // }
    }
}

