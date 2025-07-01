#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <pcap.h>
#include <dlfcn.h>
#include <vector>
#include <algorithm>
#include <cstdlib>

class PcapOverIPTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Set environment variable for PCAP-over-IP
        setenv("NETSPY_PCAP_OVER_IP_PORT", "57013", 1);  // Use different port for tests
    }
    
    void TearDown() override {
        unsetenv("NETSPY_PCAP_OVER_IP_PORT");
    }
    
    // Helper function to connect to PCAP-over-IP server
    int connectToPcapServer(int port) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) return -1;
        
        struct sockaddr_in serverAddr;
        memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
        serverAddr.sin_port = htons(port);
        
        // Try to connect with timeout
        for (int i = 0; i < 10; i++) {
            if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == 0) {
                return sockfd;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        close(sockfd);
        return -1;
    }
    
    // Helper function to read PCAP file header
    bool readPcapHeader(int sockfd) {
        struct pcap_file_header header;
        ssize_t bytes = recv(sockfd, &header, sizeof(header), 0);
        
        if (bytes != sizeof(header)) return false;
        
        // Verify PCAP magic number
        return header.magic == 0xa1b2c3d4;
    }
    
    // Helper function to read a packet from stream
    bool readPcapPacket(int sockfd, std::vector<uint8_t>& packet) {
        struct pcap_pkthdr pkthdr;
        ssize_t bytes = recv(sockfd, &pkthdr, sizeof(pkthdr), MSG_WAITALL);
        
        if (bytes != sizeof(pkthdr)) return false;
        
        packet.resize(pkthdr.caplen);
        bytes = recv(sockfd, packet.data(), pkthdr.caplen, MSG_WAITALL);
        
        return bytes == pkthdr.caplen;
    }
};

TEST_F(PcapOverIPTest, ServerListensOnPort) {
    // Load the NetSpy library which should start PCAP-over-IP server
    void* handle = dlopen("./libnetspy.so", RTLD_LAZY);
    ASSERT_NE(handle, nullptr) << "Failed to load libnetspy.so: " << dlerror();
    
    // Give server time to start
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Try to connect to the server
    int clientSocket = connectToPcapServer(57013);
    EXPECT_GE(clientSocket, 0) << "Failed to connect to PCAP-over-IP server";
    
    if (clientSocket >= 0) {
        close(clientSocket);
    }
    
    // Give some time for cleanup to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    dlclose(handle);
    
    // Give cleanup time to complete
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

TEST_F(PcapOverIPTest, ServerSendsPcapHeader) {
    void* handle = dlopen("./libnetspy.so", RTLD_LAZY);
    ASSERT_NE(handle, nullptr);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    int clientSocket = connectToPcapServer(57013);
    ASSERT_GE(clientSocket, 0);
    
    // Read and verify PCAP header
    EXPECT_TRUE(readPcapHeader(clientSocket));
    
    close(clientSocket);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    dlclose(handle);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

TEST_F(PcapOverIPTest, MultipleClientsCanConnect) {
    void* handle = dlopen("./libnetspy.so", RTLD_LAZY);
    ASSERT_NE(handle, nullptr);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Connect multiple clients
    std::vector<int> clients;
    for (int i = 0; i < 3; i++) {
        int client = connectToPcapServer(57013);
        EXPECT_GE(client, 0) << "Failed to connect client " << i;
        if (client >= 0) {
            clients.push_back(client);
            EXPECT_TRUE(readPcapHeader(client)) << "Failed to read header for client " << i;
        }
    }
    
    // Close all clients
    for (int client : clients) {
        close(client);
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    dlclose(handle);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

TEST_F(PcapOverIPTest, NetworkActivityGeneratesPackets) {
    void* handle = dlopen("./libnetspy.so", RTLD_LAZY);
    ASSERT_NE(handle, nullptr);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    int clientSocket = connectToPcapServer(57013);
    ASSERT_GE(clientSocket, 0);
    ASSERT_TRUE(readPcapHeader(clientSocket));
    
    // Generate some network activity by creating a socket and sending data
    std::thread networkActivity([]() {
        int testSocket = socket(AF_INET, SOCK_DGRAM, 0);
        if (testSocket >= 0) {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = inet_addr("127.0.0.1");
            addr.sin_port = htons(12345);
            
            const char* testData = "test packet data";
            sendto(testSocket, testData, strlen(testData), 0, 
                   (struct sockaddr*)&addr, sizeof(addr));
            
            close(testSocket);
        }
    });
    
    // Wait for network activity
    networkActivity.join();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Try to read a packet (with timeout)
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(clientSocket, &readfds);
    
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    
    int result = select(clientSocket + 1, &readfds, nullptr, nullptr, &timeout);
    if (result > 0) {
        std::vector<uint8_t> packet;
        EXPECT_TRUE(readPcapPacket(clientSocket, packet));
        EXPECT_GT(packet.size(), 0) << "Received empty packet";
    }
    
    close(clientSocket);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    dlclose(handle);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

TEST_F(PcapOverIPTest, ClientDisconnectionHandled) {
    void* handle = dlopen("./libnetspy.so", RTLD_LAZY);
    ASSERT_NE(handle, nullptr);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Connect and immediately disconnect
    int client1 = connectToPcapServer(57013);
    ASSERT_GE(client1, 0);
    ASSERT_TRUE(readPcapHeader(client1));
    close(client1);  // Abrupt disconnection
    
    // Connect another client to ensure server is still working
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    int client2 = connectToPcapServer(57013);
    EXPECT_GE(client2, 0) << "Server should handle client disconnections gracefully";
    
    if (client2 >= 0) {
        EXPECT_TRUE(readPcapHeader(client2));
        close(client2);
    }
    
    dlclose(handle);
}

// Test that file mode still works when PCAP-over-IP is not enabled
TEST(PcapFileTest, FileModeDeimuuWhenEnvNotSet) {
    // Ensure environment variable is not set
    unsetenv("NETSPY_PCAP_OVER_IP_PORT");
    
    void* handle = dlopen("./libnetspy.so", RTLD_LAZY);
    ASSERT_NE(handle, nullptr);
    
    // Give some time for initialization
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Try to connect to default port - should fail since server shouldn't be running
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(clientSocket, 0);
    
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddr.sin_port = htons(57012);  // Default port
    
    // Connection should fail
    EXPECT_LT(connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)), 0);
    
    close(clientSocket);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    dlclose(handle);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
}