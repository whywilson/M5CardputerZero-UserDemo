#pragma once

#include "nfc_models.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <dirent.h>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/ioctl.h>
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
        // Open with O_NONBLOCK so open() doesn't hang waiting for DCD/carrier
        // (CH340 and similar USB-serial chips never assert DCD).
        // After open we clear O_NONBLOCK via fcntl so that write() blocks until
        // bytes are fully queued in the kernel tty buffer.
        fd_ = ::open(endpoint.path.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (fd_ < 0) {
            if (error) *error = std::string("open failed: ") + std::strerror(errno);
            return false;
        }
        // Clear O_NONBLOCK so subsequent write()s are reliable
        int flags = fcntl(fd_, F_GETFL, 0);
        if (flags >= 0) fcntl(fd_, F_SETFL, flags & ~O_NONBLOCK);

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
        options.c_cc[VTIME] = 1; // 100 ms kernel-level timeout; matched to Python timeout=0.1
        options.c_cflag &= ~HUPCL; // don't lower DTR on close

        if (tcsetattr(fd_, TCSANOW, &options) != 0) {
            if (error) *error = std::string("tcsetattr failed: ") + std::strerror(errno);
            close();
            return false;
        }

        // DTR/RTS handling differs between device types on macOS:
        //
        // PN532Killer (CDC-ACM, /dev/cu.usbmodem*):
        //   Needs DTR=HIGH → DTR=LOW to boot into normal mode.
        //   If DTR stays HIGH, the USB bridge stays in a firmware-update mode
        //   and ignores all PN532 commands.
        //
        // Plain PN532 (USB-serial adapter /dev/cu.usbserial*, e.g. CH340):
        //   DTR is often connected to nRST through a capacitor.
        //   Keeping DTR=HIGH lets the chip run; pulling LOW holds it in reset.
        //   Python pyserial uses DTR=HIGH (default) and works for both cases.
        //
        // Detect by port name:
        //   macOS CDC-ACM: cu.usbmodem*
        //   Linux CDC-ACM: ttyACM*
        // Both need the DTR pulse; plain PN532 / CH340 (ttyUSB*, cu.usbserial*, etc.) keep DTR HIGH.
        const bool is_cdc_acm = endpoint.path.find("usbmodem") != std::string::npos
                             || endpoint.path.find("ttyACM")   != std::string::npos;
        if (is_cdc_acm) {
            // PN532Killer: pulse HIGH → LOW, then stay LOW
            int bits = TIOCM_DTR | TIOCM_RTS;
            ioctl(fd_, TIOCMBIS, &bits);  // HIGH
            usleep(100000);               // 100 ms hold
            ioctl(fd_, TIOCMBIC, &bits);  // LOW
            usleep(10000);                // 10 ms settle
        } else {
            // Plain PN532 / CH340: set DTR=HIGH and keep it
            int bits = TIOCM_DTR | TIOCM_RTS;
            ioctl(fd_, TIOCMBIS, &bits);
            usleep(50000);                // 50 ms: let chip stabilise
        }

        // Only flush RX stale bytes; do NOT flush TX.
        tcflush(fd_, TCIFLUSH);

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
        // Do NOT call tcdrain() – it is not called by pyserial and may stall on
        // some CH340 driver revisions on macOS.
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

        // Use select() + read() rather than VTIME-based blocking read.
        // On macOS with the WCH CH340 USB-serial driver, VTIME-based blocking
        // reads do NOT reliably trigger USB IN polling; select() does.
        // This matches pyserial's internal implementation (serialposix.py).
        size_t got = 0;
        auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(timeout_ms);
        while (got < size) {
            auto remaining_us = std::chrono::duration_cast<std::chrono::microseconds>(
                                    deadline - std::chrono::steady_clock::now()).count();
            if (remaining_us <= 0) break;
            struct timeval tv;
            tv.tv_sec  = (long)(remaining_us / 1000000);
            tv.tv_usec = (long)(remaining_us % 1000000);
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(fd_, &rfds);
            int r = ::select(fd_ + 1, &rfds, nullptr, nullptr, &tv);
            if (r < 0) {
                if (errno == EINTR) continue;
                if (error) *error = std::string("select failed: ") + std::strerror(errno);
                return -1;
            }
            if (r == 0) break; // timeout
            if (!FD_ISSET(fd_, &rfds)) break;
            ssize_t n = ::read(fd_, buffer + got, 1); // read 1 byte (like pyserial)
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (error) *error = std::string("read failed: ") + std::strerror(errno);
                return -1;
            }
            if (n == 0) break;
            got += (size_t)n;
            // After receiving at least 1 byte, drain any immediately available bytes
            // (avoids extra round-trips when multiple bytes are buffered).
            while (got < size) {
                struct timeval tv2 = {0, 0}; // non-blocking
                fd_set rfds2; FD_ZERO(&rfds2); FD_SET(fd_, &rfds2);
                if (::select(fd_ + 1, &rfds2, nullptr, nullptr, &tv2) <= 0) break;
                if (!FD_ISSET(fd_, &rfds2)) break;
                ssize_t m = ::read(fd_, buffer + got, size - got);
                if (m <= 0) break;
                got += (size_t)m;
            }
            break; // return as soon as we have data
        }
        if (error) error->clear();
        return (ssize_t)got;
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

#ifndef _WIN32
        DIR *dir = opendir("/dev");
        if (!dir) {
            endpoints.push_back({TransportKind::I2cBus, "i2c://1", "I2C (dev/i2c-1)", 0});
            return endpoints;
        }

        struct dirent *entry = nullptr;
        while ((entry = readdir(dir)) != nullptr) {
            const std::string name(entry->d_name);
            TransportKind kind = TransportKind::I2cBus;
            bool matched = false;

            if (starts_with(name, "ttyUSB") || starts_with(name, "ttyACM") ||
                starts_with(name, "cu.usbmodem") || starts_with(name, "cu.usbserial") ||
                starts_with(name, "cu.wchusbserial") || starts_with(name, "cu.SLAB_USBtoUART") ||
                starts_with(name, "cu.usbserial-")) {
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
            // Try to read USB product name for a friendlier label
            std::string product = read_usb_product_name(name);
            if (!product.empty())
                endpoint.label = std::string(to_string(kind)) + " " + product + " (" + name + ")";
            else
                endpoint.label = std::string(to_string(kind)) + " " + name;
            endpoint.baud_rate = 115200;
            endpoints.push_back(endpoint);
        }
        closedir(dir);

        std::sort(endpoints.begin(), endpoints.end(), [](const TransportEndpoint &lhs, const TransportEndpoint &rhs) {
            return lhs.path < rhs.path;
        });

        // On macOS a single USB device can appear under both an Apple-native name
        // (cu.usbmodem*, cu.usbserial-*) and a WCH-driver name (cu.wchusbserial*).
        // Connecting to the first entry locks the port exclusively, making the
        // duplicate entry always fail. Remove WCH entries whose USB serial-number
        // suffix matches an already-present non-WCH entry.
        {
            std::set<std::string> non_wch_suffixes;
            for (size_t i = 0; i < endpoints.size(); ++i) {
                const std::string devname = endpoints[i].path.substr(5); // strip /dev/
                if (!starts_with(devname, "cu.wchusbserial"))
                    non_wch_suffixes.insert(usb_serial_suffix(devname));
            }
            auto it = endpoints.begin();
            while (it != endpoints.end()) {
                const std::string devname = it->path.substr(5);
                if (starts_with(devname, "cu.wchusbserial") &&
                    non_wch_suffixes.count(usb_serial_suffix(devname))) {
                    it = endpoints.erase(it);
                } else {
                    ++it;
                }
            }
        }
#endif
        // I2C placeholder (not yet implemented)
        endpoints.push_back({TransportKind::I2cBus, "i2c://1", "I2C (dev/i2c-1)", 0});
        return endpoints;
    }

    static std::unique_ptr<INfcTransport> create(const TransportEndpoint &endpoint)
    {
        if (endpoint.kind == TransportKind::I2cBus) {
            return std::unique_ptr<INfcTransport>(new MockTransport());
        }
        return std::unique_ptr<INfcTransport>(new SerialTransport());
    }

private:
    static bool starts_with(const std::string &value, const std::string &prefix)
    {
        return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
    }

    // Extract the USB serial-number suffix by stripping known driver-specific
    // prefixes. Longest prefixes are checked first to avoid ambiguity.
    static std::string usb_serial_suffix(const std::string &name)
    {
        static const char *kPrefixes[] = {
            "cu.wchusbserial", "cu.SLAB_USBtoUART",
            "cu.usbserial-", "cu.usbserial", "cu.usbmodem",
            "ttyUSB", "ttyACM", nullptr
        };
        for (const char **p = kPrefixes; *p; ++p) {
            const size_t plen = std::strlen(*p);
            if (name.size() > plen && name.compare(0, plen, *p) == 0)
                return name.substr(plen);
        }
        return name;
    }

    // Read USB product name from sysfs (Linux) or IOKit (macOS).
    // Returns empty string if unavailable.
    static std::string read_usb_product_name(const std::string &devname)
    {
#if defined(__linux__)
        // sysfs path: /sys/class/tty/<dev>/device/../../product
        // The tty device node -> device (usb interface) -> device (usb device) -> product
        static const char *SUFFIXES[] = {"/device/../../product", "/device/../product", nullptr};
        for (const char **s = SUFFIXES; *s; ++s) {
            const std::string path = std::string("/sys/class/tty/") + devname + *s;
            FILE *f = fopen(path.c_str(), "r");
            if (!f) continue;
            char buf[128] = {};
            if (fgets(buf, sizeof(buf), f)) {
                fclose(f);
                // Strip trailing whitespace/newline
                size_t len = strlen(buf);
                while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' || buf[len - 1] == ' '))
                    buf[--len] = '\0';
                if (len > 0) return std::string(buf);
            }
            fclose(f);
        }
#elif defined(__APPLE__)
        // On macOS: run ioreg to extract USB product name matching this serial port device.
        // We look for the IOCalloutDevice property matching /dev/<devname>.
        std::string cmd = std::string("ioreg -l -n IOUSBHostDevice 2>/dev/null | grep -A20 '\"IOCalloutDevice\" = \"/dev/") + devname + "\"' | grep '\"USB Product Name\"' | head -1";
        FILE *f = popen(cmd.c_str(), "r");
        if (f) {
            char buf[256] = {};
            if (fgets(buf, sizeof(buf), f)) {
                pclose(f);
                // Parse: "USB Product Name" = "PN532Killer-UART"
                const char *q = strchr(buf, '"');
                if (q) { q = strchr(q + 1, '"'); }
                if (q) { q = strchr(q + 1, '"'); }
                if (q) { q = strchr(q + 1, '"'); }  // now at opening quote of value
                if (q) {
                    q++; // skip opening "
                    const char *e = strchr(q, '"');
                    if (e && e > q) return std::string(q, e);
                }
            } else {
                pclose(f);
            }
        }
        // Fallback: map known VID/PID via ioreg USB serial number embedded in devname
        // cu.usbmodem<serial> where serial="00000001" → suffix "00000001"
        {
            const std::string suffix = usb_serial_suffix(devname);
            if (!suffix.empty()) {
                std::string cmd2 = std::string("ioreg -l 2>/dev/null | grep -B10 '\"USB Serial Number\" = \"") + suffix + "\"' | grep '\"USB Product Name\"' | tail -1";
                FILE *f2 = popen(cmd2.c_str(), "r");
                if (f2) {
                    char buf2[256] = {};
                    if (fgets(buf2, sizeof(buf2), f2)) {
                        pclose(f2);
                        const char *q = strchr(buf2, '"');
                        if (q) { q = strchr(q + 1, '"'); }
                        if (q) { q = strchr(q + 1, '"'); }
                        if (q) { q = strchr(q + 1, '"'); }
                        if (q) {
                            q++;
                            const char *e = strchr(q, '"');
                            if (e && e > q) return std::string(q, e);
                        }
                    } else {
                        pclose(f2);
                    }
                }
            }
        }
#endif
        return {};
    }
};

} // namespace nfc_app