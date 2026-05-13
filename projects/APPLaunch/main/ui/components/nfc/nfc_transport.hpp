#pragma once

#include "nfc_models.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <dirent.h>
#include <memory>
#include <string>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace nfc_app {

struct TransportEndpoint {
    TransportKind kind = TransportKind::Mock;
    std::string path;
    std::string label;
    int baud_rate = 115200;
};

class INfcTransport {
public:
    virtual ~INfcTransport() = default;
    virtual bool open(const TransportEndpoint &endpoint, std::string *error) = 0;
    virtual void close() = 0;
    virtual bool is_open() const = 0;
    virtual ssize_t write_bytes(const uint8_t *data, size_t size, std::string *error) = 0;
    virtual ssize_t read_bytes(uint8_t *buffer, size_t size, int timeout_ms, std::string *error) = 0;
    virtual TransportEndpoint endpoint() const = 0;
};

class MockTransport : public INfcTransport {
public:
    bool open(const TransportEndpoint &endpoint, std::string *error) override
    {
        endpoint_ = endpoint;
        open_ = true;
        if (error) error->clear();
        return true;
    }

    void close() override
    {
        open_ = false;
    }

    bool is_open() const override
    {
        return open_;
    }

    ssize_t write_bytes(const uint8_t *data, size_t size, std::string *error) override
    {
        (void)data;
        if (!open_) {
            if (error) *error = "mock transport not open";
            return -1;
        }
        if (error) error->clear();
        return static_cast<ssize_t>(size);
    }

    ssize_t read_bytes(uint8_t *buffer, size_t size, int timeout_ms, std::string *error) override
    {
        (void)buffer;
        (void)size;
        (void)timeout_ms;
        if (!open_) {
            if (error) *error = "mock transport not open";
            return -1;
        }
        if (error) error->clear();
        return 0;
    }

    TransportEndpoint endpoint() const override
    {
        return endpoint_;
    }

private:
    TransportEndpoint endpoint_;
    bool open_ = false;
};

class SerialTransport : public INfcTransport {
public:
    ~SerialTransport() override
    {
        close();
    }

    bool open(const TransportEndpoint &endpoint, std::string *error) override
    {
        close();
        endpoint_ = endpoint;

#ifdef _WIN32
        if (error) *error = "serial transport unsupported on Windows in v1";
        return false;
#else
        fd_ = ::open(endpoint.path.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (fd_ < 0) {
            if (error) *error = std::string("open failed: ") + std::strerror(errno);
            return false;
        }

        struct termios options;
        if (tcgetattr(fd_, &options) != 0) {
            if (error) *error = std::string("tcgetattr failed: ") + std::strerror(errno);
            close();
            return false;
        }

        cfmakeraw(&options);
        cfsetispeed(&options, baud_to_constant(endpoint.baud_rate));
        cfsetospeed(&options, baud_to_constant(endpoint.baud_rate));
        options.c_cflag |= (CLOCAL | CREAD);
        options.c_cflag &= ~CRTSCTS;
        options.c_cflag &= ~PARENB;
        options.c_cflag &= ~CSTOPB;
        options.c_cflag &= ~CSIZE;
        options.c_cflag |= CS8;
        options.c_cc[VMIN] = 0;
        options.c_cc[VTIME] = 0;

        if (tcsetattr(fd_, TCSANOW, &options) != 0) {
            if (error) *error = std::string("tcsetattr failed: ") + std::strerror(errno);
            close();
            return false;
        }

        if (error) error->clear();
        return true;
#endif
    }

    void close() override
    {
#ifndef _WIN32
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
#endif
    }

    bool is_open() const override
    {
#ifdef _WIN32
        return false;
#else
        return fd_ >= 0;
#endif
    }

    ssize_t write_bytes(const uint8_t *data, size_t size, std::string *error) override
    {
#ifdef _WIN32
        (void)data;
        (void)size;
        if (error) *error = "serial transport unsupported on Windows in v1";
        return -1;
#else
        if (fd_ < 0) {
            if (error) *error = "serial transport not open";
            return -1;
        }
        ssize_t written = ::write(fd_, data, size);
        if (written < 0 && error) *error = std::string("write failed: ") + std::strerror(errno);
        return written;
#endif
    }

    ssize_t read_bytes(uint8_t *buffer, size_t size, int timeout_ms, std::string *error) override
    {
#ifdef _WIN32
        (void)buffer;
        (void)size;
        (void)timeout_ms;
        if (error) *error = "serial transport unsupported on Windows in v1";
        return -1;
#else
        if (fd_ < 0) {
            if (error) *error = "serial transport not open";
            return -1;
        }

        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(fd_, &read_set);
        struct timeval timeout;
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;

        int ready = select(fd_ + 1, &read_set, nullptr, nullptr, &timeout);
        if (ready < 0) {
            if (error) *error = std::string("select failed: ") + std::strerror(errno);
            return -1;
        }
        if (ready == 0) return 0;

        ssize_t got = ::read(fd_, buffer, size);
        if (got < 0 && error) *error = std::string("read failed: ") + std::strerror(errno);
        return got;
#endif
    }

    TransportEndpoint endpoint() const override
    {
        return endpoint_;
    }

private:
#ifndef _WIN32
    static speed_t baud_to_constant(int baud)
    {
        switch (baud) {
        case 9600: return B9600;
        case 19200: return B19200;
        case 38400: return B38400;
        case 57600: return B57600;
        case 230400: return B230400;
        default: return B115200;
        }
    }
#endif

    TransportEndpoint endpoint_;
#ifndef _WIN32
    int fd_ = -1;
#endif
};

class NfcTransportFactory {
public:
    static std::vector<TransportEndpoint> enumerate_endpoints()
    {
        std::vector<TransportEndpoint> endpoints;
        endpoints.push_back({TransportKind::Mock, "mock://pn532killer", "Mock PN532Killer", 115200});

#ifndef _WIN32
        DIR *dir = opendir("/dev");
        if (!dir) return endpoints;

        struct dirent *entry = nullptr;
        while ((entry = readdir(dir)) != nullptr) {
            const std::string name(entry->d_name);
            TransportKind kind = TransportKind::Mock;
            bool matched = false;

            if (starts_with(name, "ttyUSB") || starts_with(name, "ttyACM") ||
                starts_with(name, "cu.usbmodem") || starts_with(name, "cu.usbserial")) {
                kind = TransportKind::UsbSerial;
                matched = true;
            } else if (starts_with(name, "ttyS") || starts_with(name, "ttyAMA") ||
                       starts_with(name, "serial") || starts_with(name, "ttyTHS")) {
                kind = TransportKind::UartSerial;
                matched = true;
            }

            if (!matched) continue;

            TransportEndpoint endpoint;
            endpoint.kind = kind;
            endpoint.path = std::string("/dev/") + name;
            endpoint.label = std::string(to_string(kind)) + " " + name;
            endpoint.baud_rate = 115200;
            endpoints.push_back(endpoint);
        }
        closedir(dir);

        std::sort(endpoints.begin() + 1, endpoints.end(), [](const TransportEndpoint &lhs, const TransportEndpoint &rhs) {
            return lhs.path < rhs.path;
        });
#endif
        return endpoints;
    }

    static std::unique_ptr<INfcTransport> create(const TransportEndpoint &endpoint)
    {
        if (endpoint.kind == TransportKind::Mock) {
            return std::unique_ptr<INfcTransport>(new MockTransport());
        }
        return std::unique_ptr<INfcTransport>(new SerialTransport());
    }

private:
    static bool starts_with(const std::string &value, const std::string &prefix)
    {
        return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
    }
};

} // namespace nfc_app