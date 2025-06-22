#include <gtest/gtest.h>
#include <regex>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>

// Test helper to capture stderr output
class StderrCapture {
public:
    StderrCapture() {
        // Save original stderr
        original_stderr_ = dup(STDERR_FILENO);
        
        // Create a pipe
        if (pipe(pipe_fd_) != 0) {
            throw std::runtime_error("Failed to create pipe");
        }
        
        // Make read end non-blocking
        int flags = fcntl(pipe_fd_[0], F_GETFL, 0);
        fcntl(pipe_fd_[0], F_SETFL, flags | O_NONBLOCK);
        
        // Redirect stderr to pipe
        dup2(pipe_fd_[1], STDERR_FILENO);
    }
    
    ~StderrCapture() {
        // Restore original stderr
        dup2(original_stderr_, STDERR_FILENO);
        close(original_stderr_);
        close(pipe_fd_[0]);
        close(pipe_fd_[1]);
    }
    
    std::string GetOutput() {
        // Close write end to signal EOF
        close(pipe_fd_[1]);
        pipe_fd_[1] = -1;
        
        // Read from pipe
        std::string result;
        char buffer[1024];
        ssize_t bytes_read;
        
        while ((bytes_read = read(pipe_fd_[0], buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes_read] = '\0';
            result += buffer;
        }
        
        return result;
    }
    
private:
    int original_stderr_;
    int pipe_fd_[2];
};

// Mock NetworkInterceptor for testing
class TestableNetworkInterceptor {
public:
    static bool TestRegexFilter(const std::string& filter, const std::string& message) {
        // Set environment variable
        if (filter.empty()) {
            unsetenv("NETSPY_LOG_FILTER");
        } else {
            setenv("NETSPY_LOG_FILTER", filter.c_str(), 1);
        }
        
        // Test regex matching logic
        const char* filterEnv = getenv("NETSPY_LOG_FILTER");
        if (filterEnv && strlen(filterEnv) > 0) {
            try {
                std::regex logFilter(filterEnv);
                return std::regex_search(message, logFilter);
            } catch (const std::regex_error& e) {
                return false; // Invalid regex
            }
        }
        
        // No filter means message should be logged
        return true;
    }
};

// Test fixture
class RegexFilterTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Clear any existing filter
        unsetenv("NETSPY_LOG_FILTER");
    }
    
    void TearDown() override {
        // Clean up
        unsetenv("NETSPY_LOG_FILTER");
    }
};

// Test cases
TEST_F(RegexFilterTest, NoFilterLogsAll) {
    EXPECT_TRUE(TestableNetworkInterceptor::TestRegexFilter("", "socket(2, 1, 0) = 3"));
    EXPECT_TRUE(TestableNetworkInterceptor::TestRegexFilter("", "bind(3, 0.0.0.0:8080) = 0"));
    EXPECT_TRUE(TestableNetworkInterceptor::TestRegexFilter("", "connect(3, 127.0.0.1:80) = 0"));
}

TEST_F(RegexFilterTest, SocketOnlyFilter) {
    const std::string filter = "socket\\(";
    
    EXPECT_TRUE(TestableNetworkInterceptor::TestRegexFilter(filter, "socket(2, 1, 0) = 3"));
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter(filter, "bind(3, 0.0.0.0:8080) = 0"));
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter(filter, "connect(3, 127.0.0.1:80) = 0"));
}

TEST_F(RegexFilterTest, PortFilter) {
    const std::string filter = ":8080";
    
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter(filter, "socket(2, 1, 0) = 3"));
    EXPECT_TRUE(TestableNetworkInterceptor::TestRegexFilter(filter, "bind(3, 0.0.0.0:8080) = 0"));
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter(filter, "connect(3, 127.0.0.1:80) = 0"));
}

TEST_F(RegexFilterTest, MultipleOperationsFilter) {
    const std::string filter = "(socket|connect)\\(";
    
    EXPECT_TRUE(TestableNetworkInterceptor::TestRegexFilter(filter, "socket(2, 1, 0) = 3"));
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter(filter, "bind(3, 0.0.0.0:8080) = 0"));
    EXPECT_TRUE(TestableNetworkInterceptor::TestRegexFilter(filter, "connect(3, 127.0.0.1:80) = 0"));
}

TEST_F(RegexFilterTest, IPAddressFilter) {
    const std::string filter = "127\\.0\\.0\\.1";
    
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter(filter, "socket(2, 1, 0) = 3"));
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter(filter, "bind(3, 0.0.0.0:8080) = 0"));
    EXPECT_TRUE(TestableNetworkInterceptor::TestRegexFilter(filter, "connect(3, 127.0.0.1:80) = 0"));
}

TEST_F(RegexFilterTest, SocketTypeFilter) {
    const std::string filter = "socket\\([^,]+, 2,"; // SOCK_DGRAM
    
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter(filter, "socket(2, 1, 0) = 3"));
    EXPECT_TRUE(TestableNetworkInterceptor::TestRegexFilter(filter, "socket(2, 2, 0) = 4"));
}

TEST_F(RegexFilterTest, SuccessfulOperationsFilter) {
    const std::string filter = "= 0$";
    
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter(filter, "socket(2, 1, 0) = 3"));
    EXPECT_TRUE(TestableNetworkInterceptor::TestRegexFilter(filter, "bind(3, 0.0.0.0:8080) = 0"));
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter(filter, "connect(3, 127.0.0.1:80) = -1"));
}

TEST_F(RegexFilterTest, ErrorOperationsFilter) {
    const std::string filter = "= -1$";
    
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter(filter, "socket(2, 1, 0) = 3"));
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter(filter, "bind(3, 0.0.0.0:8080) = 0"));
    EXPECT_TRUE(TestableNetworkInterceptor::TestRegexFilter(filter, "connect(3, 127.0.0.1:80) = -1"));
}

TEST_F(RegexFilterTest, EmptyFilterDisablesLogging) {
    const std::string filter = "^$"; // Matches empty string only
    
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter(filter, "socket(2, 1, 0) = 3"));
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter(filter, "bind(3, 0.0.0.0:8080) = 0"));
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter(filter, "connect(3, 127.0.0.1:80) = 0"));
}

TEST_F(RegexFilterTest, InvalidRegexHandling) {
    const std::string filter = "[invalid"; // Invalid regex
    
    // Should return false for invalid regex
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter(filter, "socket(2, 1, 0) = 3"));
}

TEST_F(RegexFilterTest, ComplexRegexWithGroups) {
    const std::string filter = "bind\\(\\d+, ([0-9.]+):(80|443)\\)";
    
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter(filter, "socket(2, 1, 0) = 3"));
    EXPECT_TRUE(TestableNetworkInterceptor::TestRegexFilter(filter, "bind(3, 192.168.1.1:80) = 0"));
    EXPECT_TRUE(TestableNetworkInterceptor::TestRegexFilter(filter, "bind(3, 10.0.0.1:443) = 0"));
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter(filter, "bind(3, 0.0.0.0:8080) = 0"));
}

TEST_F(RegexFilterTest, CaseInsensitiveFilter) {
    const std::string filter = "[Ss][Oo][Cc][Kk][Ee][Tt]";
    
    EXPECT_TRUE(TestableNetworkInterceptor::TestRegexFilter(filter, "socket(2, 1, 0) = 3"));
    EXPECT_TRUE(TestableNetworkInterceptor::TestRegexFilter(filter, "SOCKET(2, 1, 0) = 3"));
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter(filter, "bind(3, 0.0.0.0:8080) = 0"));
}

// Test environment variable behavior
TEST_F(RegexFilterTest, EnvironmentVariablePersistence) {
    // Set filter
    setenv("NETSPY_LOG_FILTER", "socket\\(", 1);
    EXPECT_TRUE(TestableNetworkInterceptor::TestRegexFilter("socket\\(", "socket(2, 1, 0) = 3"));
    
    // Change filter
    setenv("NETSPY_LOG_FILTER", "bind\\(", 1);
    EXPECT_TRUE(TestableNetworkInterceptor::TestRegexFilter("bind\\(", "bind(3, 0.0.0.0:8080) = 0"));
    EXPECT_FALSE(TestableNetworkInterceptor::TestRegexFilter("bind\\(", "socket(2, 1, 0) = 3"));
}