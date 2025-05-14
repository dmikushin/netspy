/*
 * netspy.cpp.in - A preloadable library for logging network traffic to PCAP files
 * 
 * Usage: LD_PRELOAD=/path/to/libnetspy.so your_program
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include <pcap.h>
#include <stdarg.h>
#include <random>
#include <netinet/ip6.h>

#include "network_interceptor.hpp"

// Implementation of NetworkInterceptor class methods

NetworkInterceptor& NetworkInterceptor::getInstance() {
    static NetworkInterceptor instance;
    return instance;
}

NetworkInterceptor::NetworkInterceptor() {
    initialize();
}

NetworkInterceptor::~NetworkInterceptor() {
    cleanup();
}

void NetworkInterceptor::initialize() {
    char pcap_filename[256];
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Initialize socket tracking
    m_socketInfo = {};
    
    // Create PCAP filename based on executable name and PID
    snprintf(pcap_filename, sizeof(pcap_filename), "%s_%d.pcap", 
             program_invocation_short_name, getpid());
    
    m_pcapFilename = pcap_filename;
    
    // Initialize pcap
    m_pcapHandle = pcap_open_dead(DLT_RAW, MAX_PACKET_SIZE);
    if (!m_pcapHandle) {
        fprintf(stderr, "NetSpy: Failed to initialize pcap: %s\n", errbuf);
        return;
    }
    
    m_pcapDumper = pcap_dump_open(m_pcapHandle, m_pcapFilename.c_str());
    if (!m_pcapDumper) {
        fprintf(stderr, "NetSpy: Failed to open pcap dump file: %s\n", 
                pcap_geterr(m_pcapHandle));
        pcap_close(m_pcapHandle);
        m_pcapHandle = nullptr;
        return;
    }
    
    debug("Network traffic logging initialized. Output: %s\n", m_pcapFilename.c_str());
    
    // Load original functions
    loadOriginalFunctions();
}

void NetworkInterceptor::cleanup() {
    if (m_pcapDumper) {
        pcap_dump_close(m_pcapDumper);
        m_pcapDumper = nullptr;
    }
    
    if (m_pcapHandle) {
        pcap_close(m_pcapHandle);
        m_pcapHandle = nullptr;
    }
    
    debug("Network traffic logging complete.\n");
}

void NetworkInterceptor::updateSocketInfo(int sockfd, const struct sockaddr* addr, bool isLocal) {
    if (sockfd < 0 || sockfd >= MAX_SOCKETS || !addr)
        return;
    
    std::lock_guard<std::mutex> lock(m_socketMutex);
    
    if (isLocal) {
        memcpy(&m_socketInfo[sockfd].localAddr, addr, sizeof(struct sockaddr_storage));
    } else {
        memcpy(&m_socketInfo[sockfd].remoteAddr, addr, sizeof(struct sockaddr_storage));
        m_socketInfo[sockfd].isConnected = true;
    }
}

// NOTE: Caller must hold m_socketMutex before calling this function to avoid deadlock.
void NetworkInterceptor::getSocketAddresses(int sockfd, struct sockaddr_storage* local, struct sockaddr_storage* remote) {
    if (sockfd < 0 || sockfd >= MAX_SOCKETS)
        return;
    // No locking here! Caller must hold m_socketMutex.
    if (local)
        memcpy(local, &m_socketInfo[sockfd].localAddr, sizeof(struct sockaddr_storage));
    if (remote)
        memcpy(remote, &m_socketInfo[sockfd].remoteAddr, sizeof(struct sockaddr_storage));
}

int NetworkInterceptor::generatePacket(unsigned char* buffer, size_t bufferSize, 
                                    const struct sockaddr_storage* srcAddr, 
                                    const struct sockaddr_storage* dstAddr,
                                    const void* data, size_t dataLen, int protocol) {
    if (!buffer || bufferSize < sizeof(struct ip) + 
        (protocol == IPPROTO_TCP ? sizeof(struct tcphdr) : sizeof(struct udphdr)) + dataLen)
        return -1;

    if (srcAddr->ss_family == AF_INET && dstAddr->ss_family == AF_INET) {
        // IPv4 handling (existing code)
        struct ip* ipHeader = (struct ip*)buffer;
        struct tcphdr* tcpHeader;
        struct udphdr* udpHeader;
        int headerLen = 0;
        memset(ipHeader, 0, sizeof(struct ip));
        ipHeader->ip_v = 4;
        ipHeader->ip_hl = sizeof(struct ip) >> 2;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 0xFFFF);
        ipHeader->ip_id = htons(dis(gen));
        ipHeader->ip_ttl = 64;
        ipHeader->ip_p = protocol;
        ipHeader->ip_src.s_addr = ((struct sockaddr_in*)srcAddr)->sin_addr.s_addr;
        ipHeader->ip_dst.s_addr = ((struct sockaddr_in*)dstAddr)->sin_addr.s_addr;
        headerLen += sizeof(struct ip);
        if (protocol == IPPROTO_TCP) {
            tcpHeader = (struct tcphdr*)(buffer + headerLen);
            memset(tcpHeader, 0, sizeof(struct tcphdr));
            tcpHeader->th_sport = ((struct sockaddr_in*)srcAddr)->sin_port;
            tcpHeader->th_dport = ((struct sockaddr_in*)dstAddr)->sin_port;
            tcpHeader->th_seq = htonl(dis(gen));
            tcpHeader->th_off = sizeof(struct tcphdr) >> 2;
            tcpHeader->th_flags = TH_PUSH | TH_ACK;
            tcpHeader->th_win = htons(65535);
            headerLen += sizeof(struct tcphdr);
        } else if (protocol == IPPROTO_UDP) {
            udpHeader = (struct udphdr*)(buffer + headerLen);
            memset(udpHeader, 0, sizeof(struct udphdr));
            udpHeader->uh_sport = ((struct sockaddr_in*)srcAddr)->sin_port;
            udpHeader->uh_dport = ((struct sockaddr_in*)dstAddr)->sin_port;
            udpHeader->uh_ulen = htons(sizeof(struct udphdr) + dataLen);
            headerLen += sizeof(struct udphdr);
        } else {
            return -1;  // Unsupported protocol
        }
        if (data && dataLen > 0) {
            memcpy(buffer + headerLen, data, dataLen);
            headerLen += dataLen;
        }
        ipHeader->ip_len = htons(headerLen);
        return headerLen;
    } else if (srcAddr->ss_family == AF_INET6 && dstAddr->ss_family == AF_INET6) {
        // IPv6 handling
        struct ip6_hdr* ip6Header = (struct ip6_hdr*)buffer;
        struct tcphdr* tcpHeader;
        struct udphdr* udpHeader;
        int headerLen = 0;
        memset(ip6Header, 0, sizeof(struct ip6_hdr));
        ip6Header->ip6_flow = htonl((6 << 28) | (0 << 20) | 0); // version, traffic class, flow label
        ip6Header->ip6_plen = htons((protocol == IPPROTO_TCP ? sizeof(struct tcphdr) : sizeof(struct udphdr)) + dataLen);
        ip6Header->ip6_nxt = protocol;
        ip6Header->ip6_hops = 64;
        ip6Header->ip6_src = ((struct sockaddr_in6*)srcAddr)->sin6_addr;
        ip6Header->ip6_dst = ((struct sockaddr_in6*)dstAddr)->sin6_addr;
        headerLen += sizeof(struct ip6_hdr);
        if (protocol == IPPROTO_TCP) {
            tcpHeader = (struct tcphdr*)(buffer + headerLen);
            memset(tcpHeader, 0, sizeof(struct tcphdr));
            tcpHeader->th_sport = ((struct sockaddr_in6*)srcAddr)->sin6_port;
            tcpHeader->th_dport = ((struct sockaddr_in6*)dstAddr)->sin6_port;
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 0xFFFF);
            tcpHeader->th_seq = htonl(dis(gen));
            tcpHeader->th_off = sizeof(struct tcphdr) >> 2;
            tcpHeader->th_flags = TH_PUSH | TH_ACK;
            tcpHeader->th_win = htons(65535);
            headerLen += sizeof(struct tcphdr);
        } else if (protocol == IPPROTO_UDP) {
            udpHeader = (struct udphdr*)(buffer + headerLen);
            memset(udpHeader, 0, sizeof(struct udphdr));
            udpHeader->uh_sport = ((struct sockaddr_in6*)srcAddr)->sin6_port;
            udpHeader->uh_dport = ((struct sockaddr_in6*)dstAddr)->sin6_port;
            udpHeader->uh_ulen = htons(sizeof(struct udphdr) + dataLen);
            headerLen += sizeof(struct udphdr);
        } else {
            return -1; // Unsupported protocol
        }
        if (data && dataLen > 0) {
            memcpy(buffer + headerLen, data, dataLen);
            headerLen += dataLen;
        }
        return headerLen;
    } else {
        // Unsupported or mismatched address families
        return -1;
    }
}

void NetworkInterceptor::logPacketToPcap(const struct sockaddr_storage* srcAddr, 
                                      const struct sockaddr_storage* dstAddr,
                                      const void* data, size_t dataLen, int protocol) {
    struct pcap_pkthdr pcapHdr;
    unsigned char packetBuffer[MAX_PACKET_SIZE];
    int packetLen;
    
    if (!m_pcapDumper)
        return;
    
    // Generate a pseudo packet
    packetLen = generatePacket(packetBuffer, sizeof(packetBuffer), 
                              srcAddr, dstAddr, data, dataLen, protocol);
    
    if (packetLen <= 0)
        return;
    
    // Set up pcap header
    gettimeofday(&pcapHdr.ts, nullptr);
    pcapHdr.caplen = packetLen;
    pcapHdr.len = packetLen;
    
    // Write to PCAP file
    std::lock_guard<std::mutex> lock(m_pcapMutex);
    pcap_dump((u_char*)m_pcapDumper, &pcapHdr, packetBuffer);
    pcap_dump_flush(m_pcapDumper);
}

// NOTE: Caller must hold m_socketMutex before calling this function to avoid deadlock.
void NetworkInterceptor::logNetworkActivity(int sockfd, const void* data, size_t dataLen, bool isOutgoing) {
    struct sockaddr_storage localAddr, remoteAddr;
    struct sockaddr_storage *srcAddr, *dstAddr;
    int protocol;
    
    if (sockfd < 0 || sockfd >= MAX_SOCKETS || !data || dataLen == 0)
        return;
    
    // Get socket addresses
    memset(&localAddr, 0, sizeof(localAddr));
    memset(&remoteAddr, 0, sizeof(remoteAddr));
    getSocketAddresses(sockfd, &localAddr, &remoteAddr);
    
    // Skip if we don't have both addresses
    if (localAddr.ss_family == 0 || remoteAddr.ss_family == 0) {
        // For non-connected sockets (UDP), try to get local address
        if (localAddr.ss_family == 0) {
            socklen_t addrlen = sizeof(localAddr);
            getsockname(sockfd, (struct sockaddr*)&localAddr, &addrlen);
        }
        
        // If still no local address, skip logging
        if (localAddr.ss_family == 0)
            return;
    }
    
    // Set source and destination based on direction
    if (isOutgoing) {
        srcAddr = &localAddr;
        dstAddr = &remoteAddr;
    } else {
        srcAddr = &remoteAddr;
        dstAddr = &localAddr;
    }
    
    // Determine protocol based on socket type
    protocol = (m_socketInfo[sockfd].type == SOCK_DGRAM) ? IPPROTO_UDP : IPPROTO_TCP;
    
    // Log to PCAP
    logPacketToPcap(srcAddr, dstAddr, data, dataLen, protocol);
}

void NetworkInterceptor::debug(const char* format, ...) {
    if (!DEBUG_ENABLED)
        return;
    
    va_list args;
    va_start(args, format);
    
    fprintf(stderr, "NetSpy: ");
    vfprintf(stderr, format, args);
    
    va_end(args);
}

// Constructor function
extern "C" void __attribute__((constructor)) netspy_init() {
    NetworkInterceptor::getInstance();
}

// Destructor function
extern "C" void __attribute__((destructor)) netspy_cleanup() {
    NetworkInterceptor::getInstance().cleanup();
}

// Include generated function implementations
#include "generated_bindings_impl.hpp"
