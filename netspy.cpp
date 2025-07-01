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
#include <algorithm>
#include <pthread.h>
#include <fcntl.h>

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
    // Initialize socket tracking
    m_socketInfo = {};
    
    // Check for PCAP-over-IP environment variable
    const char* pcapOverIPPort = getenv("NETSPY_PCAP_OVER_IP_PORT");
    if (pcapOverIPPort) {
        int port = atoi(pcapOverIPPort);
        if (port <= 0) {
            port = DEFAULT_PCAP_OVER_IP_PORT;
        }
        m_usePcapOverIP = true;
        initPcapOverIP();
    } else {
        initPcapFile();
    }
    
    // Load original functions
    loadOriginalFunctions();
}

void NetworkInterceptor::initPcapFile() {
    char pcap_filename[256];
    char errbuf[PCAP_ERRBUF_SIZE];
    
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
}

void NetworkInterceptor::initPcapOverIP() {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Initialize pcap handle for packet generation
    m_pcapHandle = pcap_open_dead(DLT_RAW, MAX_PACKET_SIZE);
    if (!m_pcapHandle) {
        fprintf(stderr, "NetSpy: Failed to initialize pcap: %s\n", errbuf);
        return;
    }
    
    // Get port from environment or use default
    int port = DEFAULT_PCAP_OVER_IP_PORT;
    const char* portStr = getenv("NETSPY_PCAP_OVER_IP_PORT");
    if (portStr) {
        int envPort = atoi(portStr);
        if (envPort > 0 && envPort < 65536) {
            port = envPort;
        }
    }
    
    // Create server socket
    m_pcapServerSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_pcapServerSocket < 0) {
        fprintf(stderr, "NetSpy: Failed to create PCAP-over-IP server socket: %s\n", strerror(errno));
        return;
    }
    
    // Allow socket reuse
    int opt = 1;
    if (setsockopt(m_pcapServerSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        fprintf(stderr, "NetSpy: Failed to set socket options: %s\n", strerror(errno));
        close(m_pcapServerSocket);
        m_pcapServerSocket = -1;
        return;
    }
    
    // Bind to port
    struct sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);
    
    if (bind(m_pcapServerSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        fprintf(stderr, "NetSpy: Failed to bind PCAP-over-IP server to port %d: %s\n", port, strerror(errno));
        close(m_pcapServerSocket);
        m_pcapServerSocket = -1;
        return;
    }
    
    // Listen for connections
    if (listen(m_pcapServerSocket, 5) < 0) {
        fprintf(stderr, "NetSpy: Failed to listen on PCAP-over-IP server: %s\n", strerror(errno));
        close(m_pcapServerSocket);
        m_pcapServerSocket = -1;
        return;
    }
    
    // Start server thread
    if (pthread_create(&m_serverThread, nullptr, pcapServerThread, this) != 0) {
        fprintf(stderr, "NetSpy: Failed to create PCAP-over-IP server thread: %s\n", strerror(errno));
        close(m_pcapServerSocket);
        m_pcapServerSocket = -1;
        return;
    }
    
    debug("PCAP-over-IP server listening on port %d\n", port);
}

void* NetworkInterceptor::pcapServerThread(void* arg) {
    NetworkInterceptor* self = static_cast<NetworkInterceptor*>(arg);
    
    // Set socket to non-blocking for periodic checks
    int flags = fcntl(self->m_pcapServerSocket, F_GETFL, 0);
    fcntl(self->m_pcapServerSocket, F_SETFL, flags | O_NONBLOCK);
    
    while (self->m_pcapServerSocket >= 0) {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        
        int clientSocket = accept(self->m_pcapServerSocket, (struct sockaddr*)&clientAddr, &clientLen);
        if (clientSocket < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No pending connections, sleep briefly and check again
                usleep(100000);  // 100ms
                continue;
            } else if (errno == EINTR || errno == EBADF) {
                // Socket closed or interrupted, exit gracefully
                break;
            } else {
                self->debug("Failed to accept PCAP-over-IP client: %s\n", strerror(errno));
                usleep(100000);  // 100ms
                continue;
            }
        }
        
        self->debug("PCAP-over-IP client connected from %s:%d\n", 
                    inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
        
        // Add client to list
        {
            std::lock_guard<std::mutex> lock(self->m_clientMutex);
            self->m_clientSockets.push_back(clientSocket);
        }
        
        // Send PCAP file header to new client
        struct pcap_file_header header;
        header.magic = 0xa1b2c3d4;
        header.version_major = 2;
        header.version_minor = 4;
        header.thiszone = 0;
        header.sigfigs = 0;
        header.snaplen = MAX_PACKET_SIZE;
        header.linktype = DLT_RAW;
        
        if (send(clientSocket, &header, sizeof(header), MSG_NOSIGNAL) < 0) {
            self->debug("Failed to send PCAP header to client: %s\n", strerror(errno));
            close(clientSocket);
            std::lock_guard<std::mutex> lock(self->m_clientMutex);
            self->m_clientSockets.erase(
                std::remove(self->m_clientSockets.begin(), self->m_clientSockets.end(), clientSocket),
                self->m_clientSockets.end());
        }
    }
    
    return nullptr;
}

void NetworkInterceptor::sendPcapPacket(const struct pcap_pkthdr* header, const unsigned char* packet) {
    std::lock_guard<std::mutex> lock(m_clientMutex);
    
    // Send to all connected clients
    auto it = m_clientSockets.begin();
    while (it != m_clientSockets.end()) {
        int clientSocket = *it;
        
        // Send packet header
        if (send(clientSocket, header, sizeof(*header), MSG_NOSIGNAL) < 0 ||
            send(clientSocket, packet, header->caplen, MSG_NOSIGNAL) < 0) {
            debug("Failed to send packet to PCAP-over-IP client: %s\n", strerror(errno));
            close(clientSocket);
            it = m_clientSockets.erase(it);
        } else {
            ++it;
        }
    }
}

void NetworkInterceptor::cleanup() {
    if (m_usePcapOverIP) {
        // Close all client connections first
        {
            std::lock_guard<std::mutex> lock(m_clientMutex);
            for (int clientSocket : m_clientSockets) {
                close(clientSocket);
            }
            m_clientSockets.clear();
        }
        
        // Close server socket to interrupt accept()
        if (m_pcapServerSocket >= 0) {
            int serverSocket = m_pcapServerSocket;
            m_pcapServerSocket = -1;  // Signal thread to exit
            close(serverSocket);
        }
        
        // Give thread time to exit gracefully
        usleep(500000);  // 500ms
        
        // Join the thread - it should exit quickly now that socket is closed
        pthread_join(m_serverThread, nullptr);
    }
    
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
    
    if (!m_pcapHandle)
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
    
    if (m_usePcapOverIP) {
        // Send to connected clients
        sendPcapPacket(&pcapHdr, packetBuffer);
    } else if (m_pcapDumper) {
        // Write to PCAP file
        std::lock_guard<std::mutex> lock(m_pcapMutex);
        pcap_dump((u_char*)m_pcapDumper, &pcapHdr, packetBuffer);
        pcap_dump_flush(m_pcapDumper);
    }
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
