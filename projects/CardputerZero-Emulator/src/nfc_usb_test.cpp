// nfc_usb_test.cpp  –  Automated USB-serial / PN532 / PN532Killer connectivity test
//
// Usage:
//   ./nfc-usb-test [/dev/cu.wchusbserial000000011] [--verbose]
//
// Steps:
//   1. Open serial port
//   2. Send HSU wakeup preamble
//   3. GetFirmwareVersion → identify chip
//   4. checkPn532Killer (0xAA) → PN532 or PN532Killer?
//   5. SetWorkMode (PN532Killer) / SAMConfiguration (PN532)
//   6. InListPassiveTarget – poll for a card for up to SCAN_TIMEOUT_S seconds

#include "ui/components/nfc/nfc_protocol.hpp"
#include "ui/components/nfc/nfc_transport.hpp"
#include "ui/components/nfc/nfc_models.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

// POSIX for direct raw diagnostics
#ifndef _WIN32
#include <termios.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#endif

// ── ANSI colours ──────────────────────────────────────────────────────────────
#define GRN "\033[32m"
#define RED "\033[31m"
#define YEL "\033[33m"
#define CYN "\033[36m"
#define DIM "\033[2m"
#define RST "\033[0m"

static constexpr int SCAN_TIMEOUT_S = 10;   // seconds to wait for a card
static constexpr int SCAN_POLL_MS   = 400;  // ms between InListPassiveTarget retries

static bool g_verbose = false;

// ── helpers ───────────────────────────────────────────────────────────────────
static void pass(const char *step, const std::string &info = "")
{
    std::cout << GRN "[PASS] " RST << step;
    if (!info.empty()) std::cout << "  →  " CYN << info << RST;
    std::cout << "\n";
}

static void fail(const char *step, const std::string &reason = "")
{
    std::cout << RED "[FAIL] " RST << step;
    if (!reason.empty()) std::cout << "  →  " << reason;
    std::cout << "\n";
}

static void info_line(const char *msg)
{
    std::cout << YEL "[INFO] " RST << msg << "\n";
}

static void hex_dump(const char *label, const uint8_t *data, size_t len)
{
    if (!g_verbose) return;
    std::cout << DIM "       " << label << " (" << len << "B): ";
    for (size_t i = 0; i < len; ++i) {
        char buf[4];
        std::snprintf(buf, sizeof(buf), "%02X ", data[i]);
        std::cout << buf;
    }
    std::cout << RST "\n";
}

// Raw diagnostic read – sends wakeup + GetFirmwareVersion and dumps raw bytes.
// Uses sleep-based reads (not select) to rule out select() quirks on macOS CH340.
static void raw_probe(const std::string &port)
{
#ifndef _WIN32
    std::cout << DIM "\n--- raw probe on " << port << " ---\n" RST;
    int fd = ::open(port.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) { std::cout << DIM "    open failed: " << strerror(errno) << RST "\n"; return; }
    // Clear O_NONBLOCK after open
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);

    struct termios t;
    tcgetattr(fd, &t);
    cfmakeraw(&t);
    cfsetispeed(&t, B115200);
    cfsetospeed(&t, B115200);
    t.c_cflag |= (CLOCAL | CREAD | CS8);
    t.c_cflag &= ~(CRTSCTS | PARENB | CSTOPB | HUPCL);
    // Use VTIME blocking read (match pyserial timeout=0.1 → VTIME=1)
    // VMIN=0, VTIME=N means: return when N*100ms elapsed with no data, or when data arrives.
    t.c_cc[VMIN] = 0; t.c_cc[VTIME] = 4; // 400ms kernel-level timeout
    tcsetattr(fd, TCSANOW, &t);
    // DTR/RTS HIGH→LOW pulse: TIOCMBIS (raise) → 100ms → TIOCMBIC (lower)
    // pyserial asserts HIGH in Serial() constructor, user code lowers with dtr=False.
    // PN532Killer needs this pulse to boot. Without it the device ignores commands.
    { int b = TIOCM_DTR | TIOCM_RTS; ioctl(fd, TIOCMBIS, &b); } // raise HIGH
    usleep(100000);
    { int b = TIOCM_DTR | TIOCM_RTS; ioctl(fd, TIOCMBIC, &b); } // lower to LOW
    tcflush(fd, TCIFLUSH);
    usleep(10000); // 10ms: match pyserial timing (wakeup sent ~5-10ms after dtr=False)

    // Print modem status (DTR/RTS/CTS/DSR/DCD)
    auto print_modem = [&](const char *label) {
        int mstat = 0;
        ioctl(fd, TIOCMGET, &mstat);
        printf(DIM "    [%s modem: DTR=%d RTS=%d CTS=%d DSR=%d DCD=%d]\n" RST, label,
               !!(mstat & TIOCM_DTR), !!(mstat & TIOCM_RTS),
               !!(mstat & TIOCM_CTS), !!(mstat & TIOCM_DSR),
               !!(mstat & TIOCM_CAR));
    };

    // Helper: write command, poll FIONREAD at multiple timestamps, then collect
    auto txrx = [&](const char *name, const uint8_t *tx, size_t txn) -> size_t {
        ssize_t wr = ::write(fd, tx, txn);
        int outq = 0; ioctl(fd, TIOCOUTQ, &outq);
        hex_dump((std::string("TX ") + name).c_str(), tx, txn);
        if (wr != (ssize_t)txn)
            printf("    [write returned %zd, expected %zu errno=%d]\n", wr, txn, errno);
        else
            printf(DIM "    [write OK %zd B, TIOCOUTQ=%d]\n" RST, wr, outq);

        static uint8_t rx[256];
        size_t total = 0;

        // Poll FIONREAD at multiple checkpoints (0, 10, 50, 100, 200, 500ms)
        const int checkpoints[] = { 0, 10, 50, 100, 200, 300, 500 };
        int prev_ms = 0;
        for (int cp : checkpoints) {
            int delay = cp - prev_ms;
            if (delay > 0) usleep(delay * 1000);
            prev_ms = cp;

            int avail = 0;
            ioctl(fd, FIONREAD, &avail);
            if (avail > 0) {
                // drain all available now
                ssize_t got = ::read(fd, rx + total, std::min((int)(sizeof(rx) - total), avail));
                if (got > 0) total += (size_t)got;
                printf(DIM "    [t=%dms FIONREAD=%d, read %zd, total=%zu]\n" RST,
                       cp, avail, got, total);
            } else {
                printf(DIM "    [t=%dms FIONREAD=0]\n" RST, cp);
            }
        }
        if (total > 0) hex_dump((std::string("RX ") + name).c_str(), rx, total);
        else std::cout << DIM "    RX " << name << ": (none after 500ms)\n" RST;
        return total;
    };

    // Test A: GetFirmwareVersion directly (no wakeup, no SAMConfig)
    {
        print_modem("Test-A start");
        const uint8_t gfv[] = {0x00, 0x00, 0xFF, 0x02, 0xFE, 0xD4, 0x02, 0x2A, 0x00};
        printf(DIM "\n[Test A] GFV only (no wakeup, no SAMConfig):\n" RST);
        txrx("GFV-direct", gfv, sizeof(gfv));
    }

    // Test B: fresh reopen + IMMEDIATE wakeup→SAMConfig→GFV (match Python timing)
    // Python sends wakeup ~5ms after dtr=False, so we reopen and write immediately.
    {
        ::close(fd);
        usleep(50000); // 50ms gap before reopen
        fd = ::open(port.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (fd < 0) { printf("    [Test B reopen failed: %s]\n", strerror(errno)); goto done; }
        fl = fcntl(fd, F_GETFL, 0);
        if (fl >= 0) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
        tcgetattr(fd, &t); cfmakeraw(&t);
        cfsetispeed(&t, B115200); cfsetospeed(&t, B115200);
        t.c_cflag |= (CLOCAL | CREAD | CS8);
        t.c_cflag &= ~(CRTSCTS | PARENB | CSTOPB | HUPCL);
        t.c_cc[VMIN] = 0; t.c_cc[VTIME] = 4;
        tcsetattr(fd, TCSANOW, &t);
        { int b = TIOCM_DTR | TIOCM_RTS; ioctl(fd, TIOCMBIS, &b); }
        print_modem("Test-B DTR=HIGH");
        usleep(100000); // 100ms HIGH
        { int b = TIOCM_DTR | TIOCM_RTS; ioctl(fd, TIOCMBIC, &b); } // DTR=LOW
        // NO extra sleep: send wakeup immediately (matches Python ~5ms after dtr=False)
        print_modem("Test-B DTR=LOW");
        tcflush(fd, TCIFLUSH);

        const uint8_t wake[] = {0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        printf(DIM "\n[Test B] Immediate after DTR=LOW: wakeup → SAMConfig → GFV:\n" RST);
        txrx("wakeup", wake, sizeof(wake));

        const uint8_t sam[] = {0x00, 0x00, 0xFF, 0x03, 0xFD, 0xD4, 0x14, 0x01, 0x17, 0x00};
        txrx("SAMConfig", sam, sizeof(sam));

        const uint8_t gfv[] = {0x00, 0x00, 0xFF, 0x02, 0xFE, 0xD4, 0x02, 0x2A, 0x00};
        txrx("GFV", gfv, sizeof(gfv));
    }
done:
    if (fd >= 0) ::close(fd);
    std::cout << DIM "--- end raw probe ---\n\n" RST;
#endif
}

// ── select()-based read for raw fd (bypasses VTIME quirks on macOS WCH driver) ─
// Returns bytes read into buf within max_ms milliseconds.
// Uses repeated select()+read(1) like pyserial internally does.
static size_t select_read(int fd, uint8_t *buf, size_t want, int max_ms)
{
#ifndef _WIN32
    size_t got = 0;
    auto deadline = std::chrono::steady_clock::now()
                    + std::chrono::milliseconds(max_ms);
    while (got < want && std::chrono::steady_clock::now() < deadline) {
        auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(
                             deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) break;
        struct timeval tv;
        tv.tv_sec  = (long)(remaining / 1000000);
        tv.tv_usec = (long)(remaining % 1000000);
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        int r = ::select(fd + 1, &rfds, nullptr, nullptr, &tv);
        if (r > 0 && FD_ISSET(fd, &rfds)) {
            ssize_t n = ::read(fd, buf + got, 1);
            if (n > 0) got += (size_t)n;
        }
    }
    return got;
#else
    return 0;
#endif
}

// ── main ──────────────────────────────────────────────────────────────────────
int main(int argc, char **argv)
{
    std::string port = "/dev/cu.wchusbserial000000011";
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--verbose" || std::string(argv[i]) == "-v") {
            g_verbose = true;
        } else {
            port = argv[i];
        }
    }

    std::cout << "\n=== NFC USB Automated Test ===\n";
    std::cout << "Port: " << port;
    if (g_verbose) std::cout << "  [verbose]";
    std::cout << "\n\n";

    // ── Step 1: open serial port ──────────────────────────────────────────────
    nfc_app::TransportEndpoint ep;
    ep.kind      = nfc_app::TransportKind::UsbSerial;
    ep.path      = port;
    ep.label     = "USB test";
    ep.baud_rate = 115200;

    auto transport = nfc_app::NfcTransportFactory::create(ep);
    std::string err;
    if (!transport->open(ep, &err)) {
        fail("Step 1: Open serial port", err);
        return 1;
    }
    pass("Step 1: Open serial port", port);

    nfc_app::Pn532KillerClient client(transport.get());

    // ── Steps 2-5: detect_device() – wakeup + SAMConfig + 0xAA probe + FW ver ─
    // This exercises the same code path as the real application, including the
    // drain fix added after probe_pn532killer() in detect_device().
    info_line("Step 2-5: detect_device() – wakeup / SAMConfig / 0xAA probe / FW ver");
    std::string firmware_str;
    const auto kind = client.detect_device(&firmware_str, &err);
    if (kind == nfc_app::DeviceKind::Unknown) {
        fail("Step 2-5: detect_device", err);
        if (g_verbose) {
            transport->close();
            raw_probe(port);
        } else {
            std::cout << "       (re-run with --verbose to see raw RX bytes)\n";
            transport->close();
        }
        return 1;
    }
    {
        std::string label = firmware_str + "  [" + std::string(nfc_app::to_string(kind)) + "]";
        pass("Step 2-5: detect_device", label);
    }

    // ── Step 6: scan for Mifare Classic card ──────────────────────────────────
    std::cout << "\n" YEL "[INFO]" RST " Step 6: Waiting for Mifare Classic card ("
              << SCAN_TIMEOUT_S << "s timeout) – place card on reader…\n";

    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::seconds(SCAN_TIMEOUT_S);

    nfc_app::TagInfo tag;
    bool card_found = false;
    int attempts = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        ++attempts;
        tag = nfc_app::TagInfo{};
        if (client.in_list_passive_target_iso14443a(&tag, &err)) {
            card_found = true;
            break;
        }
        if (attempts == 1) {
            std::cout << "       (waiting: " << err << ")\n";
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(SCAN_POLL_MS));
    }

    if (!card_found) {
        fail("Step 6: Card scan timeout", std::to_string(attempts) + " attempts, last error: " + err);
        transport->close();
        std::cout << "\n=== Test complete (card not found) ===\n\n";
        return 2;
    }

    pass("Step 6: Card detected");
    std::cout << "       Type:     " << tag.tag_type << "\n";
    std::cout << "       UID:      " << tag.uid << "\n";
    std::cout << "       Protocol: " << nfc_app::to_string(tag.protocol) << "\n";
    for (const auto &kv : tag.identity_fields) {
        std::cout << "       " << kv.first << ": " << kv.second << "\n";
    }

    const bool is_mfc = tag.tag_type.find("Mifare Classic") != std::string::npos;

    // ── Step 7: Gen1A magic card detection ────────────────────────────────────
    std::cout << "\n" YEL "[INFO]" RST " Step 7: Probing Gen1A magic card unlock…\n";
    const bool is_gen1a = client.is_gen1a(&err);
    if (is_gen1a) {
        pass("Step 7: Gen1A unlocked – magic card confirmed");
    } else {
        // Not Gen1A – could be standard Mifare Classic with key auth required,
        // or a non-magic card.  Not a test failure.
        std::cout << YEL "[SKIP]" RST " Step 7: Not Gen1A"
                  << (err.empty() ? "" : " – " + err) << "\n";
        if (!is_mfc) {
            std::cout << "       (not Mifare Classic, Gen1A n/a)\n";
        }
    }

    // ── Step 8: Gen1A full dump (64 blocks) ───────────────────────────────────
    if (is_gen1a) {
        std::cout << "\n" YEL "[INFO]" RST " Step 8: Reading all 64 blocks (Gen1A dump)…\n";
        std::vector<std::vector<uint8_t>> blocks;
        std::vector<std::string> log;
        bool dump_ok = client.read_gen1a_full(&blocks, &log, &err,
            [](const std::string &line) {
                // Stream each line as it arrives
                if (line.size() >= 2 && line[0] == 'E' && line[1] == 'R') {
                    std::cout << "  " RED << line << RST "\n";
                } else if (line.size() >= 2 && line[0] == 'O' && line[1] == 'K') {
                    std::cout << "  " GRN << line << RST "\n";
                } else if (line.size() >= 2 && line[0] == '>') {
                    std::cout << "  " YEL << line << RST "\n";
                } else {
                    std::cout << "  " << line << "\n";
                }
                std::cout.flush();
            });

        if (dump_ok) {
            pass("Step 8: Gen1A full dump complete");
        } else {
            fail("Step 8: Gen1A dump failed", err);
        }
    } else {
        std::cout << YEL "[SKIP]" RST " Step 8: Gen1A dump skipped (not Gen1A)\n";
    }

    transport->close();
    std::cout << "\n=== Test complete ===\n\n";
    return (card_found && (!is_gen1a || true)) ? 0 : 2;
}
