use pnet::datalink::{self, Config};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::env;

fn main() {
    // Get the blocked IP address from command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <blocked_ip>", args[0]);
        return;
    }
    let blocked_ip = args[1]
        .parse::<std::net::IpAddr>()
        .expect("Invalid IP address");

    // Set up the network interface for packet capturing
    let interface_name = "en0"; // Change this to your network interface name
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Failed to find the specified network interface");

    // Create a configuration for the channel
    let config = Config {
        // Customize configuration options here if needed
        ..Default::default()
    };

    // Create a channel to capture packets
    let channel = datalink::channel(&interface, config).expect("Failed to create channel");

    match channel {
        datalink::Channel::Ethernet(_, mut rx) => {
            loop {
                match rx.next() {
                    Ok(packet) => {
                        // Parse the Ethernet frame
                        let eth_packet = EthernetPacket::new(packet).unwrap();
                        match eth_packet.get_ethertype() {
                            EtherTypes::Ipv4 => {
                                // Parse the IPv4 packet
                                let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
                                let src_ip = ipv4_packet.get_source();

                                // Check if the source IP is blocked
                                if src_ip == blocked_ip {
                                    println!("Blocked packet from {}", src_ip);
                                    continue; // Drop this packet
                                }

                                // Process TCP packets
                                if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                                    println!(
                                        "Allowed TCP packet from {}:{}",
                                        src_ip,
                                        tcp_packet.get_source()
                                    );
                                }
                            }
                            _ => {}
                        }
                    }
                    Err(e) => eprintln!("Error reading packet: {}", e),
                }
            }
        }
        _ => eprintln!("Unsupported channel type"),
    }
}
