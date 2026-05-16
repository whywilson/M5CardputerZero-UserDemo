#pragma once

// Linux ioctl-based I2C implementation of the GroveNFC register protocol.
// Ported from /Users/wilson/Github/GroveNFC/src/GroveNFC.cpp (register protocol only).
// Does NOT depend on Arduino / M5UnitUnified.

#include "nfc_models.hpp"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h>
#ifndef I2C_SLAVE
#define I2C_SLAVE 0x0703
#endif
#endif

#include <chrono>
#include <thread>

namespace nfc_app {

// GroveNFC register addresses (from GroveNFC.h)
namespace i2c_reg {
    static constexpr uint16_t HW_VER      = 0x0000;
    static constexpr uint16_t FW_VER      = 0x0002;
    static constexpr uint16_t SET_MODE    = 0x0004;
    static constexpr uint16_t SET_TAGADDR = 0x0006;
    static constexpr uint16_t SET_RFCFG   = 0x0008;
    static constexpr uint16_t SET_FWI     = 0x000A;
    static constexpr uint16_t SET_TXCRCE  = 0x000C;
    static constexpr uint16_t SET_RXCRCE  = 0x000E;
    static constexpr uint16_t NFC_STATUS  = 0x0010;
    static constexpr uint16_t RX_LEN      = 0x0012;
    static constexpr uint16_t MISC_RFON   = 0x0020;
    static constexpr uint16_t MISC_TXLAST = 0x0021;
    static constexpr uint16_t MISC_THRU   = 0x0022;
    static constexpr uint16_t MISC_EGT    = 0x0023;
    static constexpr uint16_t MISC_SLOT   = 0x0024;
    static constexpr uint16_t MISC_EPWR   = 0x0029;
    static constexpr uint16_t DATA        = 0x0100;
    static constexpr uint16_t EPROM       = 0x1000;
}

// Mode register constants
namespace i2c_mode {
    static constexpr uint16_t DEFAULT    = 0x0000;
    static constexpr uint16_t READER     = 0x0100;
    static constexpr uint16_t TAG_NONE   = 0x0000;
    static constexpr uint16_t TAG_NTAG213 = 0x0001;
    static constexpr uint16_t TAG_NTAG215 = 0x0002;
    static constexpr uint16_t TAG_NTAG216 = 0x0003;
    static constexpr uint16_t TAG_MFC1K  = 0x0004;
    static constexpr uint16_t TAG_CHINA2 = 0x0020;
    static constexpr uint16_t TAG_ISO15  = 0x000C;
}

// RF config constants
namespace i2c_rfcfg {
    static constexpr uint16_t R14A = 0x0100;
    static constexpr uint16_t T14A = 0x0001;
    static constexpr uint16_t R14B = 0x0500;
    static constexpr uint16_t T14B = 0x0005;
    static constexpr uint16_t R212 = 0x0900;
    static constexpr uint16_t T212 = 0x0009;
    static constexpr uint16_t R15  = 0x0B00;
    static constexpr uint16_t T15  = 0x000B;
}

// Status bits
static constexpr uint16_t STATUS_RECV_DONE    = 0x0001;
static constexpr uint16_t STATUS_RECV_TIMEOUT = 0x4000;
static constexpr uint16_t STATUS_RECV_CRCERR  = 0x2000;
static constexpr uint16_t STATUS_RECV_BITERR  = 0x1000;

// Tag address constants (slot base addresses in EEPROM)
static constexpr uint16_t TAG_ADDR_NTAG213 = 0x0000;
static constexpr uint16_t TAG_ADDR_NTAG215 = 0x1000;
static constexpr uint16_t TAG_ADDR_NTAG216 = 0x2000;
static constexpr uint16_t TAG_ADDR_MFC1K   = 0x3000;
static constexpr uint16_t TAG_ADDR_ISO15   = 0x7000;
static constexpr uint16_t TAG_ADDR_14B     = 0x0000;

// I2C addresses
static constexpr uint8_t I2C_ADDR_GROVENFC = 0x48;
static constexpr uint8_t I2C_ADDR_NFCUNIT  = 0x50;

// ─────────────────────────────────────────────────────────────────────────────
// CardInfo — simplified card read result (corresponds to grove_nfc::CardInfo)
// ─────────────────────────────────────────────────────────────────────────────
struct I2cCardInfo {
    bool        valid    = false;
    std::string protocol;   // "MFC1K","MFC4K","NTAG213","NTAG215","NTAG216",
                            // "MFUL","DESFire","ISO14443A","ISO14443B",
                            // "ISO15693","FeliCa","None"
    std::string uid;        // uppercase hex, e.g. "04:AB:CD:EF"
    std::string detail;     // human-readable card details
};

// ─────────────────────────────────────────────────────────────────────────────
// I2cGroveNfcDevice
// ─────────────────────────────────────────────────────────────────────────────
class I2cGroveNfcDevice {
public:
    I2cGroveNfcDevice() = default;
    ~I2cGroveNfcDevice() { close(); }

    // Open the I2C bus at bus_path (e.g. "/dev/i2c-1") and address addr.
    bool open(const std::string &bus_path, uint8_t addr, std::string *error = nullptr)
    {
#ifdef _WIN32
        if (error) *error = "I2C not supported on Windows";
        return false;
#else
        close();
        addr_ = addr;
        bus_path_ = bus_path;

        fd_ = ::open(bus_path.c_str(), O_RDWR);
        if (fd_ < 0) {
            if (error) *error = std::string("open ") + bus_path + ": " + std::strerror(errno);
            return false;
        }
        if (::ioctl(fd_, I2C_SLAVE, (long)addr) < 0) {
            if (error) *error = std::string("ioctl I2C_SLAVE 0x") + hex8(addr) + ": " + std::strerror(errno);
            ::close(fd_);
            fd_ = -1;
            return false;
        }
        // Probe: try to read firmware version register — if it fails the device isn't there.
        uint16_t fw = readSysReg(i2c_reg::FW_VER);
        if (fw == 0 && errno != 0) {
            // Attempt a raw 1-byte read as ping (same as GroveNFC::ping)
            uint8_t dummy = 0;
            if (::read(fd_, &dummy, 1) < 0) {
                if (error) *error = std::string("probe 0x") + hex8(addr) + " on " + bus_path + ": no device";
                ::close(fd_);
                fd_ = -1;
                return false;
            }
        }
        if (error) error->clear();
        return true;
#endif
    }

    void close()
    {
#ifndef _WIN32
        if (fd_ >= 0) {
            stopRF();
            ::close(fd_);
            fd_ = -1;
        }
#endif
    }

    bool is_open() const { return fd_ >= 0; }
    bool is_nfc_unit() const { return addr_ == I2C_ADDR_NFCUNIT; }
    uint8_t addr() const { return addr_; }
    const std::string &bus_path() const { return bus_path_; }

    DeviceKind device_kind() const {
        if (addr_ == I2C_ADDR_NFCUNIT) return DeviceKind::NFCUnit;
        if (addr_ == I2C_ADDR_GROVENFC) return DeviceKind::GroveNFC;
        return DeviceKind::Unknown;
    }

    // ── Card reading ───────────────────────────────────────────────────────────

    // Try to read any card type (ISO14443A > ISO14443B > ISO15693 > FeliCa).
    // Returns true if a card was found.
    bool readCard(I2cCardInfo &card)
    {
        if (is_nfc_unit()) {
            // NFC Unit: use same register protocol path (ST25R3916 shares the same I2C register map
            // exposed by the GroveNFC firmware bridge). Try ISO14443A only; if it fails, fall through.
            if (readISO14A(card)) return true;
        }

        if (readISO14B(card)) return true;
        if (readISO14A(card)) return true;
        if (readISO15(card)) return true;
        if (readFelica(card)) return true;

        card.valid = false;
        card.protocol = "None";
        card.uid = "";
        card.detail = "No card";
        return false;
    }

    // ── Emulation (GroveNFC 0x48 only, NFC Unit returns false) ───────────────

    bool startEmulationNtag213()
    {
        if (is_nfc_unit()) return false;
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(5);
        writeSysReg(i2c_reg::SET_TAGADDR, TAG_ADDR_NTAG213);
        delay_ms(5);
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NTAG213);
    }

    bool startEmulationNtag215()
    {
        if (is_nfc_unit()) return false;
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(5);
        writeSysReg(i2c_reg::SET_TAGADDR, TAG_ADDR_NTAG215);
        delay_ms(5);
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NTAG215);
    }

    bool startEmulationNtag216()
    {
        if (is_nfc_unit()) return false;
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(5);
        writeSysReg(i2c_reg::SET_TAGADDR, TAG_ADDR_NTAG216);
        delay_ms(5);
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NTAG216);
    }

    bool startEmulationMifare1K()
    {
        if (is_nfc_unit()) return false;
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(5);
        writeSysReg(i2c_reg::SET_TAGADDR, TAG_ADDR_MFC1K);
        delay_ms(5);
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_MFC1K);
    }

    bool startEmulationISO15()
    {
        if (is_nfc_unit()) return false;
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(5);
        writeSysReg(i2c_reg::SET_TAGADDR, TAG_ADDR_ISO15);
        delay_ms(5);
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_ISO15);
    }

    bool startEmulationChinaII()
    {
        if (is_nfc_unit()) return false;
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(5);
        writeSysReg(i2c_reg::SET_TAGADDR, TAG_ADDR_14B);
        delay_ms(5);
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_CHINA2);
    }

    bool stopEmulation()
    {
        if (is_nfc_unit()) return false;
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
    }

    // ── Slot selection (GroveNFC 0x48 only) ──────────────────────────────────

    bool setSlot(uint8_t slot_index)
    {
        if (is_nfc_unit()) return false;
        return writeMiscReg(i2c_reg::MISC_SLOT, slot_index);
    }

    // ── Low-level register I/O (public for diagnostics) ──────────────────────

    bool writeSysReg(uint16_t reg, uint16_t value)
    {
#ifndef _WIN32
        if (fd_ < 0) return false;
        // Address: big-endian. Value: little-endian (same as GroveNFC Arduino driver).
        uint8_t buf[4] = {
            (uint8_t)(reg >> 8),
            (uint8_t)(reg & 0xFF),
            (uint8_t)(value & 0xFF),
            (uint8_t)(value >> 8)
        };
        return ::write(fd_, buf, 4) == 4;
#else
        return false;
#endif
    }

    bool writeMiscReg(uint16_t reg, uint8_t value)
    {
#ifndef _WIN32
        if (fd_ < 0) return false;
        uint8_t buf[3] = {
            (uint8_t)(reg >> 8),
            (uint8_t)(reg & 0xFF),
            value
        };
        return ::write(fd_, buf, 3) == 3;
#else
        return false;
#endif
    }

    uint16_t readSysReg(uint16_t reg)
    {
#ifndef _WIN32
        if (fd_ < 0) return 0;
        uint8_t reg_buf[2] = {(uint8_t)(reg >> 8), (uint8_t)(reg & 0xFF)};
        if (::write(fd_, reg_buf, 2) != 2) return 0;
        uint8_t rx[2] = {0, 0};
        if (::read(fd_, rx, 2) != 2) return 0;
        return (uint16_t(rx[1]) << 8) | rx[0]; // little-endian
#else
        return 0;
#endif
    }

    bool writeData(uint16_t reg, const uint8_t *data, uint16_t len)
    {
#ifndef _WIN32
        if (fd_ < 0) return false;
        std::vector<uint8_t> buf(2u + len);
        buf[0] = (uint8_t)(reg >> 8);
        buf[1] = (uint8_t)(reg & 0xFF);
        if (len > 0) std::memcpy(buf.data() + 2, data, len);
        return ::write(fd_, buf.data(), (size_t)(2 + len)) == (ssize_t)(2 + len);
#else
        return false;
#endif
    }

    bool readData(uint16_t reg, uint8_t *data, uint16_t len)
    {
#ifndef _WIN32
        if (fd_ < 0) return false;
        uint8_t reg_buf[2] = {(uint8_t)(reg >> 8), (uint8_t)(reg & 0xFF)};
        if (::write(fd_, reg_buf, 2) != 2) return false;
        if (len == 0) return true;
        return ::read(fd_, data, len) == (ssize_t)len;
#else
        return false;
#endif
    }

private:
    int      fd_   = -1;
    uint8_t  addr_ = 0;
    std::string bus_path_;

    // Arduino delay() → usleep
    static void delay_ms(int ms)
    {
        if (ms > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }

    // Hex helpers
    static std::string hex8(uint8_t v) {
        char buf[3]; std::snprintf(buf, sizeof(buf), "%02X", v); return buf;
    }
    static std::string bytes_to_hex(const uint8_t *data, size_t len, bool reverse = false) {
        std::string out;
        out.reserve(len * 3);
        for (size_t i = 0; i < len; ++i) {
            if (i) out += ':';
            const uint8_t b = reverse ? data[len - 1 - i] : data[i];
            char buf[3]; std::snprintf(buf, sizeof(buf), "%02X", b); out += buf;
        }
        return out;
    }

    void stopRF()
    {
        if (fd_ < 0) return;
        writeMiscReg(i2c_reg::MISC_RFON, 0x00);
    }

    bool recover()
    {
        if (fd_ < 0) return false;
        stopRF();
        delay_ms(2);
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(3);
        writeSysReg(i2c_reg::SET_FWI, 0x0000);
        writeSysReg(i2c_reg::SET_TXCRCE, 0x0000);
        writeSysReg(i2c_reg::SET_RXCRCE, 0x0000);
        writeMiscReg(i2c_reg::MISC_TXLAST, 0x00);
        writeMiscReg(i2c_reg::MISC_THRU, 0x00);
        writeMiscReg(i2c_reg::MISC_EGT, 0x06);
        writeMiscReg(i2c_reg::MISC_SLOT, 0x00);
        return true;
    }

    // txrx: send NFC command, wait for response via status polling.
    // Mirrors GroveNFC::txrx() exactly (no millis() / delay() needed here).
    bool txrx(const uint8_t *cmd, uint8_t cmd_len,
              uint8_t *out, uint16_t &out_len, uint16_t wait_ms)
    {
        if (!writeData(i2c_reg::DATA, cmd, cmd_len)) return false;

        const auto start = std::chrono::steady_clock::now();
        uint16_t status = 0;
        while (true) {
            status = readSysReg(i2c_reg::NFC_STATUS);
            if ((status & STATUS_RECV_DONE) ||
                (status & (STATUS_RECV_TIMEOUT | STATUS_RECV_CRCERR | STATUS_RECV_BITERR)))
                break;
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed_ms >= wait_ms) break;
            delay_ms(2);
        }

        if (!(status & STATUS_RECV_DONE)) {
            stopRF();
            delay_ms(2);
            return false;
        }

        const uint16_t rx_len = readSysReg(i2c_reg::RX_LEN);
        if (rx_len == 0 || rx_len > out_len) {
            stopRF();
            delay_ms(2);
            return false;
        }
        if (!readData(i2c_reg::DATA, out, rx_len)) {
            stopRF();
            delay_ms(2);
            return false;
        }
        out_len = rx_len;
        return true;
    }

    bool selectReaderCommon()
    {
        stopRF();
        if (!writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE)) return false;
        delay_ms(5);
        if (!writeSysReg(i2c_reg::SET_MODE, i2c_mode::READER | i2c_mode::TAG_NONE)) return false;
        writeMiscReg(i2c_reg::MISC_THRU, 0x00);
        writeMiscReg(i2c_reg::MISC_TXLAST, 0x00);
        return true;
    }

    // ── ISO14443A ─────────────────────────────────────────────────────────────
    bool readISO14A(I2cCardInfo &card)
    {
        if (!selectReaderCommon()) return false;
        writeSysReg(i2c_reg::SET_RFCFG, i2c_rfcfg::R14A | i2c_rfcfg::T14A);
        writeSysReg(i2c_reg::SET_FWI, 0x0009);
        writeSysReg(i2c_reg::SET_TXCRCE, 0x0000);
        writeSysReg(i2c_reg::SET_RXCRCE, 0x0000);
        writeMiscReg(i2c_reg::MISC_TXLAST, 0x07); // 7-bit last byte for REQA
        writeMiscReg(i2c_reg::MISC_RFON, 0x01);
        delay_ms(5);

        uint8_t rx[64] = {0};
        uint16_t rx_len = sizeof(rx);
        const uint8_t reqa[] = {0x52};
        if (!txrx(reqa, 1, rx, rx_len, 10)) return false;

        writeMiscReg(i2c_reg::MISC_TXLAST, 0x00);

        // Anticollision CL1
        const uint8_t anticol1[] = {0x93, 0x20};
        rx_len = sizeof(rx);
        if (!txrx(anticol1, 2, rx, rx_len, 10) || rx_len < 5) return false;
        uint8_t uid1[4] = {rx[0], rx[1], rx[2], rx[3]};
        uint8_t bcc1 = rx[4];

        writeSysReg(i2c_reg::SET_TXCRCE, 0x0001);
        writeSysReg(i2c_reg::SET_RXCRCE, 0x0001);

        // SELECT CL1
        uint8_t sel1[] = {0x93, 0x70, uid1[0], uid1[1], uid1[2], uid1[3], bcc1};
        rx_len = sizeof(rx);
        if (!txrx(sel1, 7, rx, rx_len, 10)) return false;
        uint8_t sak = rx[0];

        uint8_t uid_buf[7];
        size_t uid_len;
        const bool cascade = (uid1[0] == 0x88);

        if (!cascade) {
            std::memcpy(uid_buf, uid1, 4);
            uid_len = 4;
        } else {
            writeSysReg(i2c_reg::SET_TXCRCE, 0x0000);
            writeSysReg(i2c_reg::SET_RXCRCE, 0x0000);
            const uint8_t anticol2[] = {0x95, 0x20};
            rx_len = sizeof(rx);
            if (!txrx(anticol2, 2, rx, rx_len, 10) || rx_len < 5) return false;
            uint8_t uid2[4] = {rx[0], rx[1], rx[2], rx[3]};
            uint8_t bcc2 = rx[4];

            writeSysReg(i2c_reg::SET_TXCRCE, 0x0001);
            writeSysReg(i2c_reg::SET_RXCRCE, 0x0001);
            uint8_t sel2[] = {0x95, 0x70, uid2[0], uid2[1], uid2[2], uid2[3], bcc2};
            rx_len = sizeof(rx);
            if (!txrx(sel2, 7, rx, rx_len, 10)) return false;
            sak = rx[0];

            uid_buf[0] = uid1[1]; uid_buf[1] = uid1[2]; uid_buf[2] = uid1[3];
            uid_buf[3] = uid2[0]; uid_buf[4] = uid2[1]; uid_buf[5] = uid2[2]; uid_buf[6] = uid2[3];
            uid_len = 7;
        }

        card.uid = bytes_to_hex(uid_buf, uid_len);
        card.valid = true;

        // Identify by SAK
        if (sak == 0x08) {
            card.protocol = "MFC1K";
            card.detail = "MIFARE Classic 1K (SAK:08)";
        } else if (sak == 0x18) {
            card.protocol = "MFC4K";
            card.detail = "MIFARE Classic 4K (SAK:18)";
        } else if (sak == 0x09) {
            card.protocol = "MFCMini";
            card.detail = "MIFARE Classic Mini (SAK:09)";
        } else if (sak == 0x10) {
            card.protocol = "MFPlus2K";
            card.detail = "MIFARE Plus 2K (SAK:10)";
        } else if (sak == 0x11) {
            card.protocol = "MFPlus4K";
            card.detail = "MIFARE Plus 4K (SAK:11)";
        } else if (sak == 0x20 || sak == 0x28) {
            card.protocol = "DESFire";
            char buf[32]; std::snprintf(buf, sizeof(buf), "DESFire/JCOP (SAK:%02X)", sak);
            card.detail = buf;
        } else if (sak == 0x00) {
            // NTAG / Ultralight: use GET_VERSION to distinguish
            writeSysReg(i2c_reg::SET_TXCRCE, 0x0000);
            writeSysReg(i2c_reg::SET_RXCRCE, 0x0000);
            uint8_t get_ver[] = {0x60};
            rx_len = sizeof(rx);
            if (txrx(get_ver, 1, rx, rx_len, 15) && rx_len >= 8) {
                const uint8_t ic_type    = rx[2]; // 0x03=UL, 0x04=NTAG
                const uint8_t storage_sz = rx[6];
                if (ic_type == 0x04) {
                    if      (storage_sz == 0x0F) { card.protocol = "NTAG213"; card.detail = "NTAG213 144B (SAK:00)"; }
                    else if (storage_sz == 0x11) { card.protocol = "NTAG215"; card.detail = "NTAG215 504B (SAK:00)"; }
                    else if (storage_sz == 0x13) { card.protocol = "NTAG216"; card.detail = "NTAG216 888B (SAK:00)"; }
                    else                         { card.protocol = "NTAG";    card.detail = "NTAG (SAK:00)"; }
                } else {
                    card.protocol = "MFUL";
                    card.detail = "MIFARE Ultralight (SAK:00)";
                }
            } else {
                card.protocol = "MFUL";
                card.detail = "MIFARE Ultralight/NTAG (SAK:00)";
            }
        } else {
            card.protocol = "ISO14443A";
            char buf[32]; std::snprintf(buf, sizeof(buf), "ISO14443A (SAK:%02X)", sak);
            card.detail = buf;
        }
        return true;
    }

    // ── ISO14443B ─────────────────────────────────────────────────────────────
    bool readISO14B(I2cCardInfo &card)
    {
        auto runOnce = [&]() -> bool {
            stopRF();
            if (!writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE)) return false;
            delay_ms(10);
            if (!writeSysReg(i2c_reg::SET_MODE, i2c_mode::READER | i2c_mode::TAG_NONE)) return false;
            writeSysReg(i2c_reg::SET_TAGADDR, 0x0000);
            writeMiscReg(i2c_reg::MISC_THRU, 0x00);
            writeMiscReg(i2c_reg::MISC_TXLAST, 0x00);
            writeSysReg(i2c_reg::SET_RFCFG, i2c_rfcfg::R14B | i2c_rfcfg::T14B);
            writeSysReg(i2c_reg::SET_FWI, 0x0000);
            writeSysReg(i2c_reg::SET_TXCRCE, 0x0002);
            writeSysReg(i2c_reg::SET_RXCRCE, 0x0002);
            writeMiscReg(i2c_reg::MISC_EGT, 0x06);
            writeMiscReg(i2c_reg::MISC_RFON, 0x01);
            delay_ms(10);

            uint8_t rx[128] = {0};
            uint16_t rx_len = 0;

            // Clear status, then send REQB
            writeSysReg(i2c_reg::NFC_STATUS, 0x0000);
            const uint8_t reqb[] = {0x05, 0x00, 0x00};
            if (!writeData(i2c_reg::DATA, reqb, 3)) return false;
            delay_ms(10);

            // Poll for RECV_DONE
            uint16_t status = 0;
            for (int i = 0; i < 20; ++i) {
                status = readSysReg(i2c_reg::NFC_STATUS);
                if (status & STATUS_RECV_DONE) break;
                if (status & (STATUS_RECV_TIMEOUT | STATUS_RECV_CRCERR | STATUS_RECV_BITERR)) break;
                delay_ms(2);
            }
            if (!(status & STATUS_RECV_DONE)) { stopRF(); return false; }

            rx_len = readSysReg(i2c_reg::RX_LEN);
            if (rx_len == 0 || rx_len > sizeof(rx)) { stopRF(); return false; }
            if (!readData(i2c_reg::DATA, rx, rx_len)) { stopRF(); return false; }

            // ATTRIB
            writeSysReg(i2c_reg::NFC_STATUS, 0x0000);
            const uint8_t attrib[] = {0x1D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x08};
            if (!writeData(i2c_reg::DATA, attrib, 9)) return false;
            delay_ms(10);
            for (int i = 0; i < 20; ++i) {
                status = readSysReg(i2c_reg::NFC_STATUS);
                if (status & STATUS_RECV_DONE) break;
                if (status & (STATUS_RECV_TIMEOUT | STATUS_RECV_CRCERR | STATUS_RECV_BITERR)) break;
                delay_ms(2);
            }
            if (!(status & STATUS_RECV_DONE)) { stopRF(); return false; }
            rx_len = readSysReg(i2c_reg::RX_LEN);
            if (rx_len == 0 || rx_len > sizeof(rx)) { stopRF(); return false; }
            if (!readData(i2c_reg::DATA, rx, rx_len)) { stopRF(); return false; }

            uint8_t uid_buf[16] = {0};
            size_t uid_len = (rx_len > sizeof(uid_buf)) ? sizeof(uid_buf) : rx_len;
            std::memcpy(uid_buf, rx, uid_len);

            // GET UID
            writeSysReg(i2c_reg::NFC_STATUS, 0x0000);
            const uint8_t getuid[] = {0x00, 0x36, 0x00, 0x00, 0x08};
            if (writeData(i2c_reg::DATA, getuid, 5)) {
                delay_ms(10);
                for (int i = 0; i < 20; ++i) {
                    status = readSysReg(i2c_reg::NFC_STATUS);
                    if (status & STATUS_RECV_DONE) break;
                    if (status & (STATUS_RECV_TIMEOUT | STATUS_RECV_CRCERR | STATUS_RECV_BITERR)) break;
                    delay_ms(2);
                }
                if ((status & STATUS_RECV_DONE)) {
                    uint16_t rlen2 = readSysReg(i2c_reg::RX_LEN);
                    if (rlen2 > 0 && rlen2 <= sizeof(uid_buf)) {
                        if (readData(i2c_reg::DATA, uid_buf, rlen2))
                            uid_len = rlen2;
                    }
                }
            }

            stopRF();
            if (uid_len == 0) return false;

            card.protocol = "ISO14443B";
            card.uid = bytes_to_hex(uid_buf, uid_len);
            card.detail = "ISO14443B";
            card.valid = true;
            return true;
        };

        if (runOnce()) return true;
        recover();
        delay_ms(20);
        return runOnce();
    }

    // ── ISO15693 ──────────────────────────────────────────────────────────────
    bool readISO15(I2cCardInfo &card)
    {
        if (!selectReaderCommon()) return false;
        writeSysReg(i2c_reg::SET_RFCFG, i2c_rfcfg::R15 | i2c_rfcfg::T15);
        writeSysReg(i2c_reg::SET_TXCRCE, 0x0008);
        writeSysReg(i2c_reg::SET_RXCRCE, 0x0008);
        writeMiscReg(i2c_reg::MISC_TXLAST, 0x00);
        writeMiscReg(i2c_reg::MISC_RFON, 0x01);
        delay_ms(5);

        uint8_t rx[64] = {0};
        uint16_t rx_len = sizeof(rx);
        const uint8_t inv[] = {0x26, 0x01, 0x00};
        if (!txrx(inv, 3, rx, rx_len, 15) || rx_len < 10) {
            writeMiscReg(i2c_reg::MISC_RFON, 0x01);
            delay_ms(4);
            rx_len = sizeof(rx);
            if (!txrx(inv, 3, rx, rx_len, 100) || rx_len < 10) return false;
        }

        card.protocol = "ISO15693";
        card.uid = bytes_to_hex(&rx[2], 8, /*reverse=*/true);
        card.valid = true;
        card.detail = "ISO15693 Inventory";
        return true;
    }

    // ── FeliCa ────────────────────────────────────────────────────────────────
    bool readFelica(I2cCardInfo &card)
    {
        if (!selectReaderCommon()) return false;
        writeSysReg(i2c_reg::SET_RFCFG, i2c_rfcfg::R212 | i2c_rfcfg::T212);
        writeMiscReg(i2c_reg::MISC_SLOT, 0x00);
        writeSysReg(i2c_reg::SET_TXCRCE, 0x0004);
        writeSysReg(i2c_reg::SET_RXCRCE, 0x0004);
        writeMiscReg(i2c_reg::MISC_RFON, 0x01);
        delay_ms(5);

        uint8_t rx[64] = {0};
        uint16_t rx_len = sizeof(rx);
        const uint8_t polling[] = {0x06, 0x00, 0xFF, 0xFF, 0x00, 0x00};
        if (!txrx(polling, 6, rx, rx_len, 15) || rx_len < 10) return false;

        card.protocol = "FeliCa";
        card.uid = bytes_to_hex(&rx[2], 8);
        card.valid = true;
        char buf[48];
        std::snprintf(buf, sizeof(buf), "FeliCa IDm:%s", card.uid.c_str());
        card.detail = buf;
        return true;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Helper: translate I2cCardInfo.protocol → ProtocolKind + tag_type string
// ─────────────────────────────────────────────────────────────────────────────
inline ProtocolKind i2c_protocol_to_kind(const std::string &proto)
{
    if (proto == "MFC1K" || proto == "MFC4K" || proto == "MFCMini") return ProtocolKind::MifareClassic;
    if (proto == "ISO14443B") return ProtocolKind::Iso14443B;
    if (proto == "ISO15693")  return ProtocolKind::Iso15693;
    return ProtocolKind::Iso14443A;
}

inline std::string i2c_protocol_to_tag_type(const std::string &proto)
{
    if (proto == "MFC1K")    return "MIFARE Classic 1K";
    if (proto == "MFC4K")    return "MIFARE Classic 4K";
    if (proto == "MFCMini")  return "MIFARE Classic Mini";
    if (proto == "MFPlus2K") return "MIFARE Plus 2K";
    if (proto == "MFPlus4K") return "MIFARE Plus 4K";
    if (proto == "DESFire")  return "MIFARE DESFire";
    if (proto == "NTAG213")  return "NTAG213";
    if (proto == "NTAG215")  return "NTAG215";
    if (proto == "NTAG216")  return "NTAG216";
    if (proto == "NTAG")     return "NTAG";
    if (proto == "MFUL")     return "MIFARE Ultralight";
    if (proto == "ISO14443A") return "ISO14443A";
    if (proto == "ISO14443B") return "ISO14443B";
    if (proto == "ISO15693")  return "ISO15693";
    if (proto == "FeliCa")    return "FeliCa";
    return proto;
}

} // namespace nfc_app
