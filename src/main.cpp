#include <iostream>
#include "pcap_reader.h"
#include "packet_parser.h"

using namespace PacketAnalyzer;

int main() {

    PcapReader reader;

    if (!reader.open("data/test_dpi.pcap")) {
        std::cerr << "Failed to open PCAP file\n";
        return 1;
    }

    RawPacket raw;
    ParsedPacket parsed;

    int count = 0;

    while (reader.readNextPacket(raw)) {

        count++;

        if (!PacketParser::parse(raw, parsed))
            continue;

        std::cout << "==============================\n";
        std::cout << "Packet #" << count << "\n";
        std::cout << "==============================\n";

        std::cout << "Source MAC      : "
                  << parsed.src_mac << "\n";

        std::cout << "Destination MAC : "
                  << parsed.dest_mac << "\n";

        if(parsed.has_ip)
        {
            std::cout << "Source IP       : "
                      << parsed.src_ip << "\n";

            std::cout << "Destination IP  : "
                      << parsed.dest_ip << "\n";

            std::cout << "Protocol        : "
                      << PacketParser::protocolToString(parsed.protocol)
                      << "\n";
        }

        if(parsed.has_tcp)
        {
            std::cout << "Source Port     : "
                      << parsed.src_port << "\n";

            std::cout << "Destination Port: "
                      << parsed.dest_port << "\n";

            std::cout << "TCP Flags       : "
                      << PacketParser::tcpFlagsToString(parsed.tcp_flags)
                      << "\n";
        }

        if(parsed.has_udp)
        {
            std::cout << "Source Port     : "
                      << parsed.src_port << "\n";

            std::cout << "Destination Port: "
                      << parsed.dest_port << "\n";
        }

        std::cout << "Payload Length  : "
                  << parsed.payload_length
                  << " bytes\n\n";

        if(count == 5)
            break;
    }

    reader.close();
}