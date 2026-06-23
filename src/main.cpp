#include <iostream>
#include "pcap_reader.h"

using namespace PacketAnalyzer;

int main() {
    PcapReader reader;

    if (!reader.open("data/test_dpi.pcap")) {
        std::cerr << "Failed to open PCAP file\n";
        return 1;
    }

    RawPacket packet;
    int count = 0;

    while (reader.readNextPacket(packet)) {
        count++;

        std::cout << "Packet #" << count << '\n';
        std::cout << "Timestamp: "
                  << packet.header.ts_sec
                  << "."
                  << packet.header.ts_usec
                  << '\n';

        std::cout << "Length: "
                  << packet.header.incl_len
                  << " bytes\n\n";
    }

    reader.close();

    std::cout << "Total packets: "
              << count
              << std::endl;

    return 0;
}