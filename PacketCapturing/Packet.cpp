#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <netinet/ip.h>  // For IP header
#include <netinet/udp.h> // For UDP header (optional)
#include <netinet/tcp.h> // For TCP header (optional)
#include <netdb.h>  // For gethostbyaddr()
#include <arpa/inet.h>  // For inet_ntoa()

// Define a function to resolve the hostname from an IP address -> DNS lookup 
std::string resolve_hostname(const char *ip_address) {
    struct in_addr ip_addr;
    inet_aton(ip_address, &ip_addr);

    struct hostent *host = gethostbyaddr(&ip_addr, sizeof(ip_addr), AF_INET);
    if (host != nullptr) {
        return std::string(host->h_name);
    } else {
        return "Unknown";
    }
}

// Callback function to handle captured packets
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Print the length of the captured packet
    std::cout << "Captured a packet with length: " << pkthdr->len << std::endl;

    // Ethernet header length
    const int ETH_HEADER_LEN = 14;

    // Check if the packet is long enough for an IP header
    if (pkthdr->len > ETH_HEADER_LEN) {
        // Point to the IP header
        const struct ip *ip_header = (struct ip *)(packet + ETH_HEADER_LEN);

        std::string src_ip = inet_ntoa(ip_header->ip_src);
        std::string dst_ip = inet_ntoa(ip_header->ip_dst);

        std::cout << "Source IP: " << src_ip << " (" << resolve_hostname(src_ip.c_str()) << ")" << std::endl;
        std::cout << "Destination IP: " << dst_ip << " (" << resolve_hostname(dst_ip.c_str()) << ")" << std::endl;

        // Print source and destination IP addresses
        std::cout << "Source IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
        std::cout << "Destination IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;

        // Optional: Print protocol (e.g., TCP, UDP)
        std::cout << "Protocol: " << (int)ip_header->ip_p << std::endl;
        
        // Optional: Process TCP or UDP headers if needed
        if (ip_header->ip_p == IPPROTO_TCP) {
            const struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETH_HEADER_LEN + (ip_header->ip_hl * 4));
            std::cout << "Source Port: " << ntohs(tcp_header->th_sport) << std::endl;
            std::cout << "Destination Port: " << ntohs(tcp_header->th_dport) << std::endl;
            std::cout << "- - - - - - - - - - - - - - - - - - - - -" << std::endl;
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            const struct udphdr *udp_header = (struct udphdr *)(packet + ETH_HEADER_LEN + (ip_header->ip_hl * 4));
            std::cout << "Source Port: " << ntohs(udp_header->uh_sport) << std::endl;
            std::cout << "Destination Port: " << ntohs(udp_header->uh_dport) << std::endl;
            std::cout << "- - - - - - - - - - - - - - - - - - - - -" << std::endl;
        }
        
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];  // Buffer to hold error messages from libpcap functions
    pcap_if_t *alldevs, *dev;  // Pointers to store the list of network devices and individual device
    pcap_t *handle;  // Handle for the packet capture session
    int i = 0;  // Counter for device enumeration

    // Find all network devices available for packet capture
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }

    // Enumerate and print all found devices
    for (dev = alldevs; dev; dev = dev->next) {
        std::cout << ++i << ". " << dev->name << " - " << (dev->description ? dev->description : "No description available") << std::endl;
    }

    // Check if no devices were found
    if (i == 0) {
        std::cerr << "No devices found!" << std::endl;
        return 1;
    }

    // Choose the first device from the list
    dev = alldevs;
    std::cout << "Using device: " << dev->name << std::endl;

    // Open the selected device for packet capture
    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return 1;
    }

    // Define a filter expression (e.g., "ip" to capture only IP packets)
    // const std::string filter_exp = "ip";  // Example filter expression
    // struct bpf_program fp;  // Compiled filter program
    // if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
    //     std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
    //     return 1;
    // }

    // Set the filter for the packet capture session
    // if (pcap_setfilter(handle, &fp) == -1) {
    //     std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
    //     return 1;
    // }

    // Start capturing packets indefinitely
    pcap_loop(handle, -1, packet_handler, nullptr);

    // Close the packet capture session
    pcap_close(handle);

    // Free the list of network devices
    pcap_freealldevs(alldevs);

    return 0;
}
