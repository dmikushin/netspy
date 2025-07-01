/*
 * network_interceptor.hpp - NetworkInterceptor class definition
 */

#pragma once

#include <mutex>
#include <array>
#include <string>
#include <pcap.h>
#include <netinet/in.h>
#include <sys/socket.h>

// Configuration
constexpr int MAX_SOCKETS = 4096;
constexpr int MAX_PACKET_SIZE = 65535;
constexpr bool DEBUG_ENABLED = true;

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
    
    std::mutex m_pcapMutex;
    std::mutex m_socketMutex;
    
    pcap_dumper_t* m_pcapDumper = nullptr;
    pcap_t* m_pcapHandle = nullptr;
    
    std::array<SocketInfo, MAX_SOCKETS> m_socketInfo;
    std::string m_pcapFilename;
};
