/*
 * network_interceptor.hpp - NetworkInterceptor class definition
 */

#pragma once

#include <mutex>
#include <array>
#include <string>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>

// Configuration
constexpr int MAX_SOCKETS = 4096;
constexpr int MAX_PACKET_SIZE = 65535;
constexpr bool DEBUG_ENABLED = true;
constexpr int DEFAULT_PCAP_OVER_IP_PORT = 57012;

// Socket tracking information
struct SocketInfo {
    int domain = 0;                    // Socket domain (AF_INET, etc.)
    int type = 0;                      // Socket type (SOCK_STREAM, SOCK_DGRAM, etc.)
    int protocol = 0;                  // Socket protocol
    bool isConnected = false;          // Whether the socket is connected
    struct sockaddr_storage localAddr = {};   // Local address
    struct sockaddr_storage remoteAddr = {};  // Remote address
};

class NetworkInterceptor {
public:
    static NetworkInterceptor& getInstance();
    
    // Initialization and cleanup
    void initialize();
    void cleanup();
    
    // Helper methods
    void updateSocketInfo(int sockfd, const struct sockaddr* addr, bool isLocal);
    // NOTE: Caller must hold m_socketMutex before calling this function to avoid deadlock.
    void getSocketAddresses(int sockfd, struct sockaddr_storage* local, struct sockaddr_storage* remote);
    int generatePacket(unsigned char* buffer, size_t bufferSize, 
                     const struct sockaddr_storage* srcAddr, 
                     const struct sockaddr_storage* dstAddr,
                     const void* data, size_t dataLen, int protocol);
    void logPacketToPcap(const struct sockaddr_storage* srcAddr, 
                        const struct sockaddr_storage* dstAddr,
                        const void* data, size_t dataLen, int protocol);
    void logNetworkActivity(int sockfd, const void* data, size_t dataLen, bool isOutgoing);
    void debug(const char* format, ...);
    
    // Include generated function headers
    #include "generated_bindings_header.hpp"
    
private:
    NetworkInterceptor();
    ~NetworkInterceptor();
    
    NetworkInterceptor(const NetworkInterceptor&) = delete;
    NetworkInterceptor& operator=(const NetworkInterceptor&) = delete;
    
    void initPcapFile();
    void initPcapOverIP();
    void sendPcapPacket(const struct pcap_pkthdr* header, const unsigned char* packet);
    static void* pcapServerThread(void* arg);
    
    std::mutex m_pcapMutex;
    std::mutex m_socketMutex;
    std::mutex m_clientMutex;
    
    pcap_dumper_t* m_pcapDumper = nullptr;
    pcap_t* m_pcapHandle = nullptr;
    
    std::array<SocketInfo, MAX_SOCKETS> m_socketInfo;
    std::string m_pcapFilename;
    
    // PCAP-over-IP support
    bool m_usePcapOverIP = false;
    int m_pcapServerSocket = -1;
    std::vector<int> m_clientSockets;
    pthread_t m_serverThread;
};
