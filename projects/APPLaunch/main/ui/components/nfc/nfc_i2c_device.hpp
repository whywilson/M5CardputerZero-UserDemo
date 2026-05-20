#pragma once

// Linux ioctl-based I2C implementation of the GroveNFC register protocol.
// Ported from /Users/wilson/Github/GroveNFC/src/GroveNFC.cpp (register protocol only).
// Does NOT depend on Arduino / M5UnitUnified.

#include "nfc_models.hpp"
#include "nfc_hex_logger.hpp"

#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <array>
#include <bitset>
#include <random>
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
    std::string atqa_hex;   // uppercase hex, e.g. "0004"
    std::string sak_hex;    // uppercase hex, e.g. "08"
    std::string magic_type; // "Gen1A" / "Gen3" / "Gen4" / ""
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
        card.magic_type.clear();
        card.atqa_hex.clear();
        card.sak_hex.clear();

        if (is_nfc_unit()) {
            // M5 NFC Unit (ST25R3916B at 0x50) uses a completely different I2C
            // register protocol from GroveNFC (Nuvoton MCU at 0x48).
            // Use the dedicated ST25R3916B driver path.
            return readCardNFCUnit(card);
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

    // Dump card content as hex lines based on protocol + UID from last scan.
    bool dumpCard(ProtocolKind protocol,
                  const std::string &uid_hint,
                  const std::string &tag_type,
                  const std::vector<std::string> *mfc_key_hex,
                  std::string *magic_type,
                  std::vector<std::string> &out_lines,
                  std::string *error = nullptr)
    {
        out_lines.clear();
        if (magic_type) magic_type->clear();
        if (!is_open()) {
            if (error) *error = "I2C device not open";
            return false;
        }

        if (!is_nfc_unit()) {
            if (error) *error = "I2C dump currently supports NFC Unit only";
            return false;
        }

        switch (protocol) {
        case ProtocolKind::Iso15693:
            return dumpNFCUnitISO15693(uid_hint, out_lines, error);
        case ProtocolKind::Iso14443A:
            return dumpNFCUnitMFU(uid_hint, out_lines, error);
        case ProtocolKind::MifareClassic:
            return dumpNFCUnitMFC(uid_hint, tag_type, mfc_key_hex, magic_type, out_lines, error);
        default:
            if (error) *error = "Unsupported protocol for I2C dump";
            return false;
        }
    }

    // ── Emulation (GroveNFC 0x48 only, NFC Unit returns false) ───────────────

    bool startEmulationNtag213()
    {
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(5);
        writeSysReg(i2c_reg::SET_TAGADDR, TAG_ADDR_NTAG213);
        delay_ms(5);
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NTAG213);
    }

    bool startEmulationNtag215()
    {
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(5);
        writeSysReg(i2c_reg::SET_TAGADDR, TAG_ADDR_NTAG215);
        delay_ms(5);
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NTAG215);
    }

    bool startEmulationNtag216()
    {
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(5);
        writeSysReg(i2c_reg::SET_TAGADDR, TAG_ADDR_NTAG216);
        delay_ms(5);
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NTAG216);
    }

    bool startEmulationMifare1K()
    {
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(5);
        writeSysReg(i2c_reg::SET_TAGADDR, TAG_ADDR_MFC1K);
        delay_ms(5);
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_MFC1K);
    }

    bool startEmulationISO15()
    {
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(5);
        writeSysReg(i2c_reg::SET_TAGADDR, TAG_ADDR_ISO15);
        delay_ms(5);
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_ISO15);
    }

    bool startEmulationChinaII()
    {
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(5);
        writeSysReg(i2c_reg::SET_TAGADDR, TAG_ADDR_14B);
        delay_ms(5);
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_CHINA2);
    }

    bool stopEmulation()
    {
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
    }

    // ── Slot selection (GroveNFC / NFC Unit) ─────────────────────────────────

    bool setSlot(uint8_t slot_index)
    {
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
        // Use I2C_RDWR (repeated-start) so no STOP is issued between the
        // register address write and the data read. GroveNFC M090 clears its
        // receive buffer on a STOP, so a plain write()+read() sequence returns
        // stale / zero data for volatile registers (STATUS, RX_LEN, DATA).
        uint8_t reg_buf[2] = {(uint8_t)(reg >> 8), (uint8_t)(reg & 0xFF)};
        uint8_t rx[2] = {0, 0};
        struct i2c_msg msgs[2] = {
            {addr_, 0,        2, (__u8*)reg_buf},
            {addr_, I2C_M_RD, 2, (__u8*)rx}
        };
        struct i2c_rdwr_ioctl_data data = {msgs, 2};
        if (::ioctl(fd_, I2C_RDWR, &data) < 0) return 0;
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
        if (len == 0) return true;
        uint8_t reg_buf[2] = {(uint8_t)(reg >> 8), (uint8_t)(reg & 0xFF)};
        struct i2c_msg msgs[2] = {
            {addr_, 0,        2,   (__u8*)reg_buf},
            {addr_, I2C_M_RD, len, (__u8*)data}
        };
        struct i2c_rdwr_ioctl_data ioctl_data = {msgs, 2};
        return ::ioctl(fd_, I2C_RDWR, &ioctl_data) >= 0;
#else
        return false;
#endif
    }

private:
    int      fd_   = -1;
    uint8_t  addr_ = 0;
    std::string bus_path_;

    // ── ST25R3916B I2C protocol helpers (M5 NFC Unit at 0x50) ────────────────
    //
    // The ST25R3916B I2C command-byte encoding:
    //   0x00-0x3F  Space-A register (addr in [5:0]); write = [addr][data], read
    //              via I2C_RDWR repeated-start [addr] → read [data]
    //   0x40-0x7F  Space-B register (addr in [5:0]); same R/W pattern
    //   0x80       FIFO access; write = [0x80][data…], read via repeated-start
    //   0xC0-0xFF  Direct command (single write byte, no data)
    //
    // Key registers:
    //   0x02 OP_CONTROL: bit7=en(osc), bit6=rx_en, bit3=tx_en(RF field)
    //   0x03 MODE:       bits[6:3]=0x1 → ISO14443A initiator
    //   0x04 BIT_RATE:   0x00 = 106kbps TX+RX
    //   0x05 ISO14443A_NFC: bit0=antcl (anticollision enable)
    //   0x1A IRQ_MAIN:   bit4=rxe(end-of-receive), bit3=txe, bit2=col(collision)
    //   0x1E FIFO_STATUS1: RX FIFO byte count (lower 8 bits)
    //   0x22/0x23 NUM_TX_BYTES: TX byte count + incomplete-bits

    bool st25r_write_reg(uint8_t reg, uint8_t val)
    {
#ifndef _WIN32
        uint8_t buf[2] = {(uint8_t)(reg & 0x3F), val};
        return ::write(fd_, buf, 2) == 2;
#else
        return false;
#endif
    }

    bool st25r_read_reg(uint8_t reg, uint8_t &val)
    {
#ifndef _WIN32
        uint8_t rb = (reg & 0x3F) | 0x40;  // bit6=1 indicates register read in ST25R3916B I2C protocol
        uint8_t data = 0;
        struct i2c_msg msgs[2] = {
            {addr_, 0,        1, (__u8*)&rb},
            {addr_, I2C_M_RD, 1, (__u8*)&data}
        };
        struct i2c_rdwr_ioctl_data d = {msgs, 2};
        if (::ioctl(fd_, I2C_RDWR, &d) < 0) return false;
        val = data;
        return true;
#else
        return false;
#endif
    }

    bool st25r_cmd(uint8_t cmd)
    {
#ifndef _WIN32
        return ::write(fd_, &cmd, 1) == 1;
#else
        return false;
#endif
    }

    bool st25r_fifo_write(const uint8_t *data, uint8_t len)
    {
#ifndef _WIN32
        std::vector<uint8_t> buf;
        buf.push_back(0x80);
        buf.insert(buf.end(), data, data + len);
        return ::write(fd_, buf.data(), buf.size()) == (ssize_t)buf.size();
#else
        return false;
#endif
    }

    bool st25r_fifo_read(uint8_t *data, uint8_t len)
    {
#ifndef _WIN32
        // OP_READ_FIFO = 0x9F (NOT 0x80! 0x80 = OP_LOAD_FIFO, 0xC0 = OP_DIRECT_COMMAND)
        uint8_t op = 0x9F;
        struct i2c_msg msgs[2] = {
            {addr_, 0,        1,   (__u8*)&op},
            {addr_, I2C_M_RD, len, (__u8*)data}
        };
        struct i2c_rdwr_ioctl_data d = {msgs, 2};
        return ::ioctl(fd_, I2C_RDWR, &d) >= 0;
#else
        return false;
#endif
    }

    // Set NUM_TX_BYTES registers (0x22-0x23).
    // Format: 16-bit big-endian value = (bytes_count << 3) | last_bits
    // CMD_TRANSMIT_WITH_CRC (0xC4) appends CRC automatically; do NOT include CRC in count.
    // CMD_TRANSMIT_WITHOUT_CRC (0xC5) transmits exactly bytes_count bytes.
    void st25r_set_ntx(uint16_t bytes_count, uint8_t last_bits = 0)
    {
        uint16_t v = ((bytes_count & 0x1FF) << 3) | (last_bits & 0x07);
        st25r_write_reg(0x22, (uint8_t)((v >> 8) & 0xFF));
        st25r_write_reg(0x23, (uint8_t)(v & 0xFF));
    }

    // Poll IRQ_MAIN (0x1A) until `mask` bits are set or `timeout_ms` expires.
    // Returns the IRQ_MAIN byte (0 on timeout).
    uint8_t st25r_wait_irq(uint8_t mask, int timeout_ms)
    {
        // No sleep between polls: ISO14443A card responses start within ~302µs
        // after TX ends. With delay_ms(1) the RECEIVE command would arrive after
        // the card is already done. Tight I2C polling (~200µs/read) is needed.
        auto start = std::chrono::steady_clock::now();
        while (true) {
            uint8_t irq = 0;
            st25r_read_reg(0x1A, irq);
            if (irq & mask) return irq;
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed >= timeout_ms) return 0;
            // No sleep — tight polling required for NFC timing
        }
    }

    // ── ISO15693 / NFC-V helpers ──────────────────────────────────────────────

    // Write a Space-B register via the ST25R3916B I2C protocol.
    // Space-B access: [0xFB, reg&0x3F, value]
    bool st25r_write_spaceb(uint8_t reg, uint8_t val)
    {
#ifndef _WIN32
        uint8_t buf[3] = {0xFB, (uint8_t)(reg & 0x3F), val};
        return ::write(fd_, buf, 3) == 3;
#else
        return false;
#endif
    }

    // ISO15693 CRC-16 (poly=0x8408 reflected 0x1021, init=0xFFFF, xor-out=0xFFFF)
    static uint16_t crc16_iso15693(const uint8_t *data, size_t len)
    {
        uint16_t crc = 0xFFFF;
        for (size_t i = 0; i < len; i++) {
            uint8_t b = data[i];
            for (int j = 0; j < 8; j++) {
                uint8_t mix = (uint8_t)((crc ^ b) & 1);
                crc >>= 1;
                if (mix) crc ^= 0x8408;
                b >>= 1;
            }
        }
        return crc ^ 0xFFFF;
    }

    // Encode data bytes with ISO15693 1-of-4 PPM (SubCarrierStream TX).
    // Prepends SOF (0x21), appends CRC16 + EOF (0x04).
    // out must be at least 1 + (len+2)*4 + 1 bytes.
    // Returns encoded length.
    static uint8_t encode_nfcv_1of4(uint8_t *out, const uint8_t *data, uint8_t len)
    {
        static const uint8_t SYM4[4] = {0x02, 0x08, 0x20, 0x80};
        uint16_t crc = crc16_iso15693(data, len);
        // Build frame: data + CRC
        uint8_t frame[64];
        uint8_t flen = 0;
        for (uint8_t i = 0; i < len && flen < 60; i++) frame[flen++] = data[i];
        frame[flen++] = (uint8_t)(crc & 0xFF);
        frame[flen++] = (uint8_t)(crc >> 8);
        // Encode
        uint8_t pos = 0;
        out[pos++] = 0x21;  // SOF_1OF4
        for (uint8_t i = 0; i < flen; i++) {
            uint8_t b = frame[i];
            for (int j = 0; j < 4; j++) {
                out[pos++] = SYM4[b & 3];
                b >>= 2;
            }
        }
        out[pos++] = 0x04;  // EOF
        return pos;
    }

    // Decode Manchester-encoded ISO15693 response (SubCarrierStream RX).
    // buf/len = raw FIFO bytes; out must be >= 16 bytes; out_len = payload bytes (excl CRC).
    // Returns true on success (SOF ok, no collision, CRC matches).
    static bool decode_vicc_manchester(const uint8_t *buf, uint8_t len,
                                       uint8_t *out, uint8_t &out_len)
    {
        if (!buf || len == 0) return false;
        if ((buf[0] & 0x1F) != 0x17) return false;  // SOF check

        const uint32_t manBits     = (uint32_t)len * 8;
        const uint32_t maxPayBits  = (manBits > 5) ? ((manBits - 5) / 2) : 0;
        const uint32_t outBufLen   = (maxPayBits + 7) / 8;
        if (outBufLen == 0) return false;

        std::memset(out, 0, outBufLen < 32 ? outBufLen : 32);

        uint16_t mp = 5;   // Manchester bit position (after 5-bit SOF)
        uint16_t bp = 0;   // Payload bit position

        for (; mp < (uint16_t)(manBits - 2); mp += 2) {
            bool isEOF = false;
            uint8_t man = (buf[mp / 8] >> (mp % 8)) & 1;
            man |= (uint8_t)(((buf[(mp + 1) / 8] >> ((mp + 1) % 8)) & 1) << 1);

            if (man == 1) {
                bp++;
            } else if (man == 2) {
                uint16_t bpos = bp / 8;
                if (bpos < outBufLen && bpos < 32) out[bpos] |= (uint8_t)(1 << (bp % 8));
                bp++;
            }

            if ((bp % 8) == 0) {
                uint16_t byte_pos = (uint16_t)(mp / 8);
                if (byte_pos + 1 < len) {
                    if (((buf[byte_pos] & 0xE0) == 0xA0) && (buf[byte_pos + 1] == 0x03)) {
                        isEOF = true;
                    }
                }
            }

            if ((man == 0 || man == 3) && !isEOF) return false;  // Collision
            if (bp >= (uint16_t)(outBufLen * 8) || isEOF) break;
        }

        uint8_t out_bytes = (uint8_t)(bp / 8);
        if (out_bytes < 3) return false;  // Need flags+DSFID+UID minimum
        if ((bp % 8) != 0) return false;  // Bit boundary error

        // Verify CRC (last 2 bytes of decoded output)
        uint16_t crc_calc = crc16_iso15693(out, out_bytes - 2);
        uint16_t crc_rx   = ((uint16_t)out[out_bytes - 1] << 8) | out[out_bytes - 2];
        if (crc_calc != crc_rx) return false;

        out_len = out_bytes - 2;  // Strip CRC
        return true;
    }

    // Configure ST25R3916B for ISO15693 / NFC-V SubCarrierStream mode.
    // Mirrors GroveNFC UnitST25R3916::configure_nfc_v() exactly.
    // Includes CMD_NFC_INITIAL_FIELD_ON at end (no tx_en/rx_en set — critical).
    bool configure_nfcv()
    {
        // Stop all active operations before reconfiguring
        st25r_cmd(0xC2);   // CMD_STOP
        delay_ms(5);
        st25r_write_reg(0x02, 0x80);  // OP_CONTROL: osc only, field off
        delay_ms(5);
        // Space-A: Receiver config for 424kHz subcarrier demodulation
        st25r_write_reg(0x0B, 0x13);  // ReceiverConfig1: lp0|h80|z12k
        st25r_write_reg(0x0C, 0x2D);  // ReceiverConfig2: sqm_dyn|agc_en|agc_m|agc6_3
        st25r_write_reg(0x0D, 0x00);  // ReceiverConfig3
        st25r_write_reg(0x0E, 0x00);  // ReceiverConfig4
        // TX driver 40% modulation (required for ISO15693)
        st25r_write_reg(0x28, 0x70);
        // IOConfiguration1: MCU_CLK disabled, no LF clock
        st25r_write_reg(0x00, 0x07);
        // IOConfiguration2: enable AAT D/A (aat_en=0x20) — critical for RX sensitivity
        st25r_write_reg(0x01, 0x20);
        // OP_CONTROL: set en_fd_c1|en_fd_c0=0x03 (field detector auto-enable)
        // Do NOT set tx_en|rx_en here — GroveNFC explicitly avoids this for NFC-V
        st25r_write_reg(0x02, 0x80 | 0x03);
        // StreamModeDefinition: fc/32=424kHz subcarrier, num pulses=2
        st25r_write_reg(0x09, 0x38);
        // AuxiliaryDefinition
        st25r_write_reg(0x0A, 0x02);
        // Space-B: correlator and subcarrier configuration
        st25r_write_spaceb(0x05, 0x40);  // EMD_SUPPRESSION_CONFIGURATION
        st25r_write_spaceb(0x06, 0x14);  // SUBCARRIER_START_TIMER = 20
        st25r_write_spaceb(0x0B, 0x0C);  // P2P_RECEIVER_CONFIGURATION
        st25r_write_spaceb(0x0C, 0x13);  // CORRELATOR_CONFIGURATION_1: corr_s4|corr_s1|corr_s0
        st25r_write_spaceb(0x0D, 0x01);  // CORRELATOR_CONFIGURATION_2: 424kHz subcarrier stream
        st25r_write_spaceb(0x0E, 0x00);  // SQUELCH_TIMER
        st25r_write_spaceb(0x0F, 0x00);  // NFC_FIELD_ON_GUARD_TIMER
        st25r_write_spaceb(0x10, 0x10);  // AUXILIARY_MODULATION_SETTING
        st25r_write_spaceb(0x11, 0x7C);  // TX_DRIVER_TIMING
        st25r_write_spaceb(0x12, 0x80);  // RESISTIVE_AM_MODULATION
        // ModeDefinition = SubCarrierStream (0x70) — write LAST per GroveNFC
        st25r_write_reg(0x03, 0x70);
        // nfc_initial_field_on(): CMD + 5ms delay + explicitly set tx_en|rx_en.
        // GroveNFC modify_bit_register8(OP_CONTROL, set=tx_en|rx_en, clear=0x00)
        // sets BOTH tx_en and rx_en after CMD_NFC_INITIAL_FIELD_ON.
        // rx_en is required so the chip auto-switches to RX after CMD_TRANSMIT.
        st25r_cmd(0xC8);   // CMD_NFC_INITIAL_FIELD_ON (RFCA + field on; sets tx_en)
        delay_ms(5);
        {
            uint8_t op = 0;
            st25r_read_reg(0x02, op);
            st25r_write_reg(0x02, op | 0x40);  // Set rx_en (bit6), tx_en already set by cmd
        }
        return true;
    }

    // Restore ST25R3916B to ISO14443A mode after ISO15693 scan attempt.
    // Clears all registers changed by configure_nfcv() that are NOT reset
    // by the readCardNFCUnit() init sequence on the next call.
    void restore_iso14443a()
    {
        // Stop cleanly first
        st25r_cmd(0xC2);   // CMD_STOP
        delay_ms(5);
        // Restore IOConfiguration2: clear aat_en bit (reg 0x01, was set to 0x20)
        st25r_write_reg(0x01, 0x00);
        // Restore AUX_DEF (not set by readCardNFCUnit init, was changed to 0x02)
        st25r_write_reg(0x0A, 0x00);  // AUXILIARY_DEFINITION: reset to default
        // CRITICAL: Reset Space-B correlator to ISO14443A mode.
        // configure_nfcv() set CORRELATOR_CONFIGURATION_2=0x01 (424kHz subcarrier).
        // GroveNFC configure_nfc_a() explicitly calls writeCorrelatorConfiguration2(0x00)
        // before each ISO14443A scan — without this, the demodulator stays in NFC-V mode.
        st25r_write_spaceb(0x0B, 0x00);  // P2P_RECEIVER_CONFIGURATION: reset
        st25r_write_spaceb(0x0C, 0x00);  // CORRELATOR_CONFIGURATION_1: reset
        st25r_write_spaceb(0x0D, 0x00);  // CORRELATOR_CONFIGURATION_2: 0=ISO14443A (was 0x01=NFC-V)
        // OP_CONTROL: OSC only, field off (clears en_fd bits too)
        // readCardNFCUnit init will re-enable the field on next scan
        st25r_write_reg(0x02, 0x80);
    }

    // Compute ISO14443-3 CRC-A (for SELECT frames).
    static uint16_t crc_a(const uint8_t* data, uint8_t len) {
        uint16_t crc = 0x6363;
        for (int i = 0; i < len; i++) {
            uint8_t b = data[i] ^ (uint8_t)(crc & 0xFF);
            b ^= b << 4;
            crc = (crc >> 8) ^ ((uint16_t)b << 8) ^ ((uint16_t)b << 3) ^ ((uint16_t)b >> 4);
        }
        return crc;
    }

    static std::string normalize_uid_hex(const std::string &uid)
    {
        std::string out;
        out.reserve(uid.size());
        for (char ch : uid) {
            if (std::isxdigit(static_cast<unsigned char>(ch))) {
                out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
            }
        }
        return out;
    }

    static std::string hex_compact(const uint8_t *data, size_t len)
    {
        std::string out;
        out.reserve(len * 2);
        for (size_t i = 0; i < len; ++i) {
            char h[3];
            std::snprintf(h, sizeof(h), "%02X", data[i]);
            out += h;
        }
        return out;
    }

    class FibonacciLFSRRight32 {
    public:
        explicit FibonacciLFSRRight32(uint32_t seed) : state_(seed) {}

        bool step()
        {
            const bool out = (state_ & 0x1U) != 0;
            const bool fb = (((state_ >> 16) ^ (state_ >> 18) ^ (state_ >> 19) ^ (state_ >> 21)) & 0x1U) != 0;
            state_ = (state_ >> 1) | (static_cast<uint32_t>(fb) << 31);
            return out;
        }

        uint32_t next32()
        {
            uint32_t v = 0;
            for (uint32_t i = 0; i < 32; ++i) {
                v |= (static_cast<uint32_t>(step()) << i);
            }
            return v;
        }

    private:
        uint32_t state_ = 0;
    };

    class Crypto1Local {
    public:
        void init(uint64_t key48)
        {
            state_.reset();
            for (int i = 0; i < 48; ++i) {
                const int byte_index = i >> 3;
                const int bit_index = i & 0x07;
                const int reversed = (byte_index << 3) + (bit_index ^ 7);
                state_[i] = ((key48 >> reversed) & 1ULL) != 0;
            }
        }

        uint32_t inject(uint32_t uid, uint32_t nt, bool encrypted = false)
        {
            return step32(uid ^ nt, encrypted);
        }

        bool step_with(bool in, bool enc = false)
        {
            const bool z = filter();
            step();
            const bool ext = in ^ (enc ? z : false);
            state_[0] = state_[0] ^ ext;
            return z;
        }

        uint8_t step8(uint8_t in, bool enc = false)
        {
            uint8_t v = 0;
            for (uint_fast8_t i = 0; i < 8; ++i) {
                v |= static_cast<uint8_t>(step_with(((in >> i) & 1U) != 0, enc)) << i;
            }
            return v;
        }

        uint32_t step32(uint32_t in, bool enc = false)
        {
            uint32_t v = 0;
            for (uint32_t i = 0; i < 32; ++i) {
                const bool t = step_with(((in >> (i ^ 24U)) & 1U) != 0, enc);
                v |= static_cast<uint32_t>(t) << (24U ^ i);
            }
            return v;
        }

        static uint8_t oddparity8(uint8_t x)
        {
            return static_cast<uint8_t>(!__builtin_parity(x));
        }

        uint8_t encrypt_nr_ar(uint8_t out[8], uint32_t nr, uint32_t ar)
        {
            uint8_t parity = 0;
            for (uint_fast8_t i = 0; i < 4; ++i) {
                const uint8_t v = static_cast<uint8_t>((nr >> ((i ^ 0x03U) << 3)) & 0xFFU);
                out[i] = step8(v) ^ v;
                const uint8_t z = static_cast<uint8_t>(filter());
                parity |= static_cast<uint8_t>((z ^ oddparity8(v)) & 0x01U) << i;
            }
            for (uint_fast8_t pos = 4; pos < 8; ++pos) {
                const uint8_t i = static_cast<uint8_t>(pos - 4);
                const uint8_t v = static_cast<uint8_t>((ar >> (i << 3)) & 0xFFU);
                const uint8_t ks = step8(0x00);
                out[pos] = ks ^ v;
                const uint8_t z = static_cast<uint8_t>(filter());
                parity |= static_cast<uint8_t>((z ^ oddparity8(v)) & 0x01U) << pos;
            }
            return parity;
        }

        uint32_t encrypt_stream(uint8_t *out, const uint8_t *in, uint8_t len)
        {
            uint32_t parity = 0;
            for (uint_fast8_t i = 0; i < len; ++i) {
                const uint8_t ks = step8(0);
                out[i] = in[i] ^ ks;
                parity |= static_cast<uint32_t>((filter() ^ oddparity8(in[i])) & 1U) << i;
            }
            return parity;
        }

    private:
        bool step()
        {
            bool fb = false;
            fb ^= state_[4];
            fb ^= state_[5];
            fb ^= state_[6];
            fb ^= state_[8];
            fb ^= state_[12];
            fb ^= state_[18];
            fb ^= state_[20];
            fb ^= state_[22];
            fb ^= state_[23];
            fb ^= state_[28];
            fb ^= state_[30];
            fb ^= state_[32];
            fb ^= state_[33];
            fb ^= state_[35];
            fb ^= state_[37];
            fb ^= state_[38];
            fb ^= state_[42];
            fb ^= state_[47];

            state_ <<= 1;
            state_[0] = fb;
            return fb;
        }

        static bool fa(bool a, bool b, bool c, bool d)
        {
            return ((a || b) ^ (a && d)) ^ (c && ((a ^ b) || d));
        }

        static bool fb(bool a, bool b, bool c, bool d)
        {
            return ((a && b) || c) ^ ((a ^ b) && (c || d));
        }

        static bool fc(bool a, bool b, bool c, bool d, bool e)
        {
            return (a || ((b || e) && (d ^ e))) ^ ((a ^ (b && d)) && ((c ^ d) || (b && e)));
        }

        bool filter() const
        {
            const bool b5 = fb(state_[6], state_[4], state_[2], state_[0]);
            const bool a4 = fa(state_[14], state_[12], state_[10], state_[8]);
            const bool b3 = fb(state_[22], state_[20], state_[18], state_[16]);
            const bool b2 = fb(state_[30], state_[28], state_[26], state_[24]);
            const bool a1 = fa(state_[38], state_[36], state_[34], state_[32]);
            return fc(a1, b2, b3, a4, b5);
        }

        std::bitset<48> state_;
    };

    static uint32_t bswap32_local(uint32_t v)
    {
        return ((v & 0x000000FFU) << 24) |
               ((v & 0x0000FF00U) << 8) |
               ((v & 0x00FF0000U) >> 8) |
               ((v & 0xFF000000U) >> 24);
    }

    static void suc_23(uint32_t nt, uint32_t &suc2, uint32_t &suc3)
    {
        FibonacciLFSRRight32 lfsr(nt);
        lfsr.next32();
        lfsr.next32();
        suc2 = lfsr.next32();
        suc3 = lfsr.next32();
    }

    static uint64_t key_to64(const std::array<uint8_t, 6> &k)
    {
        uint64_t v = 0;
        v |= static_cast<uint64_t>(k[0]) << 40;
        v |= static_cast<uint64_t>(k[1]) << 32;
        v |= static_cast<uint64_t>(k[2]) << 24;
        v |= static_cast<uint64_t>(k[3]) << 16;
        v |= static_cast<uint64_t>(k[4]) << 8;
        v |= static_cast<uint64_t>(k[5]);
        return v;
    }

    static uint32_t array_to32(const uint8_t a[4])
    {
        return (static_cast<uint32_t>(a[0]) << 24) |
               (static_cast<uint32_t>(a[1]) << 16) |
               (static_cast<uint32_t>(a[2]) << 8) |
               (static_cast<uint32_t>(a[3]));
    }

    static void append_parity(uint8_t *out,
                              uint32_t out_len,
                              const uint8_t *in,
                              uint32_t in_len,
                              uint32_t parity)
    {
        if (!out || !in) return;
        const uint32_t required = (in_len * 9 + 7) >> 3;
        if (out_len < required) return;
        std::memset(out, 0, out_len);

        uint32_t bitpos = 0;
        for (uint32_t i = 0; i < in_len; ++i) {
            uint8_t v = in[i];
            for (int k = 0; k < 8; ++k) {
                const uint8_t b = static_cast<uint8_t>((v >> k) & 1U);
                if (b) out[bitpos >> 3] |= static_cast<uint8_t>(1U << (bitpos & 7));
                ++bitpos;
            }
            const uint8_t pb = static_cast<uint8_t>((parity >> i) & 1U);
            if (pb) out[bitpos >> 3] |= static_cast<uint8_t>(1U << (bitpos & 7));
            ++bitpos;
        }
    }

    static int mfc_sector_count_from_sak_tag(uint8_t sak, const std::string &tag_type)
    {
        if (sak == 0x18 || tag_type.find("4K") != std::string::npos) return 40;
        if (sak == 0x09 || tag_type.find("Mini") != std::string::npos) return 5;
        return 16;
    }

    static int mfc_sector_first_block(int sector)
    {
        return (sector < 32) ? (sector * 4) : (128 + (sector - 32) * 16);
    }

    static int mfc_sector_block_count(int sector)
    {
        return (sector < 32) ? 4 : 16;
    }

    static int mfc_sector_trailer_block(int sector)
    {
        return mfc_sector_first_block(sector) + mfc_sector_block_count(sector) - 1;
    }

    static bool parse_mfc_key_hex12(const std::string &raw, std::array<uint8_t, 6> &out)
    {
        std::string hex;
        hex.reserve(12);
        for (char c : raw) {
            if (std::isxdigit(static_cast<unsigned char>(c))) {
                hex.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
                if (hex.size() == 12) break;
            }
        }
        if (hex.size() != 12) return false;

        for (size_t i = 0; i < 6; ++i) {
            const std::string pair = hex.substr(i * 2, 2);
            out[i] = static_cast<uint8_t>(std::strtoul(pair.c_str(), nullptr, 16));
        }
        return true;
    }

    static void append_external_mfc_keys(std::vector<std::array<uint8_t, 6>> &keys,
                                         const std::vector<std::string> *external_hex)
    {
        if (!external_hex) return;
        for (const auto &line : *external_hex) {
            std::array<uint8_t, 6> parsed{};
            if (!parse_mfc_key_hex12(line, parsed)) continue;
            if (std::find(keys.begin(), keys.end(), parsed) == keys.end()) {
                keys.push_back(parsed);
            }
        }
    }

    bool st25r_wait_fifo(uint16_t need_bytes, int timeout_ms)
    {
        auto start = std::chrono::steady_clock::now();
        while (true) {
            uint8_t fifo = 0;
            if (st25r_read_reg(0x1E, fifo) && fifo >= need_bytes) return true;

            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed >= timeout_ms) return false;
        }
    }

    bool st25r_mfc_send_encrypted(Crypto1Local &crypto, const uint8_t *tx, uint8_t tx_len)
    {
        if (!tx || tx_len == 0 || tx_len > 32) return false;

        uint8_t plain[34] = {0};
        std::memcpy(plain, tx, tx_len);
        const uint16_t crc = crc_a(tx, tx_len);
        plain[tx_len] = static_cast<uint8_t>(crc & 0xFF);
        plain[tx_len + 1] = static_cast<uint8_t>((crc >> 8) & 0xFF);

        const uint8_t tx_with_crc = static_cast<uint8_t>(tx_len + 2);
        uint8_t enc[34] = {0};
        const uint32_t parity = crypto.encrypt_stream(enc, plain, tx_with_crc);

        const uint16_t total_bits = static_cast<uint16_t>(9U * tx_with_crc);
        const uint8_t stream_len = static_cast<uint8_t>((total_bits + 7U) >> 3);
        uint8_t bitstream[40] = {0};
        append_parity(bitstream, sizeof(bitstream), enc, tx_with_crc, parity);

        if (!st25r_write_reg(0x05, 0x80)) return false;  // no_tx_par

        st25r_cmd(0xDB);
        if (!st25r_fifo_write(bitstream, stream_len)) return false;
        st25r_set_ntx(static_cast<uint16_t>(total_bits >> 3), static_cast<uint8_t>(total_bits & 0x07));
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }
        st25r_cmd(0xC5);  // TRANSMIT_WITHOUT_CRC
        return true;
    }

    bool st25r_mfc_transceive_encrypted(Crypto1Local &crypto,
                                        uint8_t *rx,
                                        uint8_t &rx_len,
                                        const uint8_t *tx,
                                        uint8_t tx_len,
                                        int timeout_ms,
                                        bool include_crc,
                                        bool decrypt)
    {
        if (!rx || rx_len == 0 || !tx || tx_len == 0) return false;

        if (!st25r_set_aux_crc_mode(include_crc)) return false;
        if (!st25r_mfc_send_encrypted(crypto, tx, tx_len)) return false;

        const uint8_t expect = static_cast<uint8_t>(rx_len + (include_crc ? 2 : 0));
        if (!st25r_wait_fifo(expect, timeout_ms)) return false;

        uint8_t rbuf[40] = {0};
        uint8_t fifo_cnt = 0;
        if (!st25r_read_reg(0x1E, fifo_cnt) || fifo_cnt < expect) return false;
        if (!st25r_fifo_read(rbuf, expect)) return false;

        if (decrypt) {
            if (expect == 1) {
                const uint8_t ret = static_cast<uint8_t>(rbuf[0] & 0x0F);
                uint8_t res = 0;
                res |= static_cast<uint8_t>(crypto.step_with(0) ^ ((ret >> 0) & 1U)) << 0;
                res |= static_cast<uint8_t>(crypto.step_with(0) ^ ((ret >> 1) & 1U)) << 1;
                res |= static_cast<uint8_t>(crypto.step_with(0) ^ ((ret >> 2) & 1U)) << 2;
                res |= static_cast<uint8_t>(crypto.step_with(0) ^ ((ret >> 3) & 1U)) << 3;
                if (res != 0x0A) return false;
                rx[0] = res;
                rx_len = 1;
                return true;
            }

            for (uint8_t i = 0; i < expect; ++i) {
                rbuf[i] ^= crypto.step8(0);
            }
        }

        if (include_crc) {
            if (expect < 3) return false;
            const uint16_t crc_calc = crc_a(rbuf, rx_len);
            const uint16_t crc_rx = static_cast<uint16_t>(rbuf[expect - 2]) |
                                    (static_cast<uint16_t>(rbuf[expect - 1]) << 8);
            if (crc_calc != crc_rx) return false;
        }

        std::memcpy(rx, rbuf, rx_len);
        return true;
    }

    bool st25r_mfc_authenticate(uint8_t auth_cmd,
                                uint8_t block,
                                const std::array<uint8_t, 6> &key,
                                const std::vector<uint8_t> &uid,
                                Crypto1Local &crypto)
    {
        uint8_t rb_len = 8;
        uint8_t rb[8] = {0};
        const uint8_t auth_frame[2] = {auth_cmd, block};
        if (!st25r_nfca_transceive(auth_frame, 2, true, rb, rb_len, 40, 0x00, false, 0) || rb_len < 4) {
            return false;
        }

        if (uid.size() < 4) return false;
        std::this_thread::sleep_for(std::chrono::microseconds(90));

        uint8_t tail4[4] = {uid[uid.size() - 4], uid[uid.size() - 3], uid[uid.size() - 2], uid[uid.size() - 1]};
        const uint32_t u32 = array_to32(tail4);
        const uint32_t nt = array_to32(rb);

        uint32_t ar = 0;
        uint32_t suc3 = 0;
        suc_23(bswap32_local(nt), ar, suc3);

        static thread_local std::mt19937 rng(static_cast<uint32_t>(
            std::chrono::steady_clock::now().time_since_epoch().count()));
        const uint32_t nr = rng();

        crypto.init(key_to64(key));
        (void)crypto.inject(u32, nt, false);

        uint8_t ab[8] = {0};
        const uint8_t parity = crypto.encrypt_nr_ar(ab, nr, ar);
        uint8_t bitstream[9] = {0};
        append_parity(bitstream, sizeof(bitstream), ab, sizeof(ab), parity);

        st25r_cmd(0xD5);  // RESET_RX_GAIN
        if (!st25r_write_reg(0x05, 0x80)) return false;  // no_tx_par
        if (!st25r_set_aux_crc_mode(true)) return false; // no_crc_rx

        st25r_cmd(0xDB);
        if (!st25r_fifo_write(bitstream, sizeof(bitstream))) return false;
        st25r_set_ntx(sizeof(bitstream), 0);
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }
        st25r_cmd(0xC5);  // TRANSMIT_WITHOUT_CRC

        if (!st25r_wait_fifo(4, 50)) return false;
        uint8_t ba[4] = {0};
        if (!st25r_fifo_read(ba, sizeof(ba))) return false;

        uint8_t at2[4] = {0};
        for (int i = 0; i < 4; ++i) at2[i] = ba[i] ^ crypto.step8(0);
        const uint32_t at32 = static_cast<uint32_t>(at2[0]) |
                              (static_cast<uint32_t>(at2[1]) << 8) |
                              (static_cast<uint32_t>(at2[2]) << 16) |
                              (static_cast<uint32_t>(at2[3]) << 24);
        return at32 == suc3;
    }

    bool st25r_mfc_read_block(Crypto1Local &crypto, uint8_t block, std::array<uint8_t, 16> &out)
    {
        uint8_t rx_len = 16;
        uint8_t rx[16] = {0};
        const uint8_t cmd[2] = {0x30, block};
        if (!st25r_mfc_transceive_encrypted(crypto, rx, rx_len, cmd, sizeof(cmd), 40, true, true) || rx_len != 16) {
            return false;
        }
        std::copy(rx, rx + 16, out.begin());
        return true;
    }

    bool st25r_init_nfca_reader()
    {
        st25r_cmd(0xD6);              // ADJUST_REGULATORS
        delay_ms(5);
        st25r_write_reg(0x02, 0x80);  // OP_CONTROL: osc only
        delay_ms(10);
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }

        st25r_write_reg(0x03, 0x08);  // ISO14443A initiator
        st25r_write_reg(0x04, 0x00);  // 106kbps
        st25r_write_reg(0x05, 0x00);  // standard parity
        st25r_write_reg(0x09, 0x03);  // antenna drivers
        st25r_write_reg(0x26, 0x80);  // mask osc irq
        st25r_write_reg(0x0B, 0x08);
        st25r_write_reg(0x0C, 0x2D);
        st25r_write_reg(0x0D, 0xD8);
        st25r_write_reg(0x0E, 0x22);

        st25r_cmd(0xC8);              // NFC_INITIAL_FIELD_ON
        delay_ms(10);
        {
            uint8_t op = 0x80;
            st25r_read_reg(0x02, op);
            if (!st25r_write_reg(0x02, op | 0x48)) return false;  // tx_en|rx_en
        }
        delay_ms(5);
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }
        return true;
    }

    bool st25r_set_aux_crc_mode(bool no_crc_rx)
    {
        uint8_t aux = 0;
        if (!st25r_read_reg(0x0A, aux)) return false;
        if (no_crc_rx) aux |= 0x80;
        else aux &= static_cast<uint8_t>(~0x80);
        return st25r_write_reg(0x0A, aux);
    }

    bool st25r_nfca_transceive(const uint8_t *tx,
                               uint8_t tx_len,
                               bool with_crc,
                               uint8_t *rx,
                               uint8_t &rx_len,
                               int timeout_ms,
                               uint8_t iso14443a_settings = 0x00,
                               bool no_crc_rx = false,
                               uint8_t last_bits = 0)
    {
        if (!tx || tx_len == 0 || !rx || rx_len == 0) return false;
        if (!st25r_write_reg(0x05, iso14443a_settings)) return false;
        if (!st25r_set_aux_crc_mode(no_crc_rx)) return false;

        st25r_cmd(0xDB);  // CLEAR_FIFO
        if (!st25r_fifo_write(tx, tx_len)) return false;
        const uint16_t ntx_bytes = (last_bits == 0) ? tx_len : static_cast<uint16_t>(tx_len - 1);
        st25r_set_ntx(ntx_bytes, last_bits);
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }
        st25r_cmd(with_crc ? 0xC4 : 0xC5);

        const uint8_t irq = st25r_wait_irq(0x10 | 0x04, timeout_ms);
        if (!(irq & 0x10)) return false;

        uint8_t fifo_cnt = 0;
        if (!st25r_read_reg(0x1E, fifo_cnt) || fifo_cnt == 0) return false;
        const uint8_t to_read = std::min<uint8_t>(fifo_cnt, rx_len);
        if (!st25r_fifo_read(rx, to_read)) return false;
        if (fifo_cnt > to_read) {
            uint8_t sink[32] = {0};
            uint8_t rem = static_cast<uint8_t>(fifo_cnt - to_read);
            while (rem > 0) {
                const uint8_t n = std::min<uint8_t>(rem, sizeof(sink));
                st25r_fifo_read(sink, n);
                rem = static_cast<uint8_t>(rem - n);
            }
        }
        rx_len = to_read;
        return true;
    }

    bool st25r_nfca_transmit_only(const uint8_t *tx,
                                  uint8_t tx_len,
                                  bool with_crc,
                                  uint8_t iso14443a_settings = 0x00,
                                  uint8_t last_bits = 0,
                                  int timeout_ms = 20)
    {
        if (!tx || tx_len == 0) return false;
        if (!st25r_write_reg(0x05, iso14443a_settings)) return false;
        if (!st25r_set_aux_crc_mode(false)) return false;

        st25r_cmd(0xDB);  // CLEAR_FIFO
        if (!st25r_fifo_write(tx, tx_len)) return false;
        const uint16_t ntx_bytes = (last_bits == 0) ? tx_len : static_cast<uint16_t>(tx_len - 1);
        st25r_set_ntx(ntx_bytes, last_bits);
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }
        st25r_cmd(with_crc ? 0xC4 : 0xC5);

        const uint8_t irq = st25r_wait_irq(0x08 | 0x04, timeout_ms);
        return (irq & 0x08) != 0;
    }

    bool st25r_mfc_read_plain_block(uint8_t block, std::array<uint8_t, 16> &out)
    {
        uint8_t rx_len = 20;
        uint8_t rx[20] = {0};
        const uint8_t cmd[2] = {0x30, block};
        if (!st25r_nfca_transceive(cmd, 2, true, rx, rx_len, 40, 0x00, false, 0) || rx_len < 16) {
            return false;
        }
        std::copy(rx, rx + 16, out.begin());
        return true;
    }

    bool st25r_gen1a_backdoor_ack(uint8_t cmd, uint8_t tx_last_bits)
    {
        uint8_t rx_len = 4;
        uint8_t rx[4] = {0};
        if (!st25r_nfca_transceive(&cmd, 1, false, rx, rx_len, 30, 0x00, true, tx_last_bits) || rx_len < 1) {
            return false;
        }

        const uint8_t lo = static_cast<uint8_t>(rx[0] & 0x0F);
        const uint8_t hi = static_cast<uint8_t>((rx[0] >> 4) & 0x0F);
        return lo == 0x0A || hi == 0x0A;
    }

    bool st25r_is_gen1a_magic(const std::string &selected_uid)
    {
        auto run_unlock_probe = [&](bool send_halt) {
            for (int attempt = 0; attempt < 3; ++attempt) {
                std::vector<uint8_t> uid;
                uint8_t sak = 0;
                if (!st25r_nfca_select_uid(uid, sak)) continue;

                const std::string uid_hex = hex_compact(uid.data(), uid.size());
                if (!selected_uid.empty() && uid_hex != selected_uid) continue;

                if (send_halt) {
                    const uint8_t halt_no_crc[2] = {0x50, 0x00};
                    (void)st25r_nfca_transmit_only(halt_no_crc, 2, false, 0x00, 0, 25);
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }

                const bool ack1 = st25r_gen1a_backdoor_ack(0x40, 7);  // 7-bit frame
                std::this_thread::sleep_for(std::chrono::milliseconds(1));

                const bool ack2 = st25r_gen1a_backdoor_ack(0x43, 0);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));

                // Some cards/reader states do not expose 4-bit ACK reliably; keep legacy no-rx fallback.
                if (!ack1 && !ack2) {
                    const uint8_t unlock1 = 0x40;
                    (void)st25r_nfca_transmit_only(&unlock1, 1, false, 0x00, 7, 25);
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));

                    const uint8_t unlock2 = 0x43;
                    (void)st25r_nfca_transmit_only(&unlock2, 1, false, 0x00, 0, 25);
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }

                std::array<uint8_t, 16> block0{};
                if (st25r_mfc_read_plain_block(0, block0)) {
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
            return false;
        };

        // Try both styles for compatibility: with HALT pre-step and without HALT.
        if (run_unlock_probe(true)) return true;
        if (run_unlock_probe(false)) return true;

        return false;
    }

    bool st25r_is_gen3_magic(const std::string &selected_uid)
    {
        std::vector<uint8_t> uid;
        uint8_t sak = 0;
        if (!st25r_nfca_select_uid(uid, sak)) return false;

        const std::string uid_hex = hex_compact(uid.data(), uid.size());
        if (!selected_uid.empty() && uid_hex != selected_uid) return false;

        std::array<uint8_t, 16> block0{};
        return st25r_mfc_read_plain_block(0, block0);
    }

    bool st25r_is_gen4_magic(const std::string &selected_uid)
    {
        std::vector<uint8_t> uid;
        uint8_t sak = 0;
        if (!st25r_nfca_select_uid(uid, sak)) return false;

        const std::string uid_hex = hex_compact(uid.data(), uid.size());
        if (!selected_uid.empty() && uid_hex != selected_uid) return false;

        uint8_t cmd[8] = {0xCF, 0x00, 0x00, 0x00, 0x00, 0xC6, 0x00, 0x00};
        const uint16_t c = crc_a(cmd, 6);
        cmd[6] = static_cast<uint8_t>(c & 0xFF);
        cmd[7] = static_cast<uint8_t>((c >> 8) & 0xFF);

        uint8_t rx[32] = {0};
        uint8_t rx_len = sizeof(rx);
        // Command already contains CRC-A, so transmit without auto-CRC and accept raw RX.
        if (!st25r_nfca_transceive(cmd, sizeof(cmd), false, rx, rx_len, 60, 0x00, true, 0)) {
            return false;
        }
        return rx_len >= 4;
    }

    std::string st25r_detect_magic_type(const std::string &selected_uid)
    {
        // Probe twice to tolerate analog/RF timing variance on ST25R scans.
        for (int pass = 0; pass < 2; ++pass) {
            if (st25r_is_gen1a_magic(selected_uid)) return "Gen1A";
            // Some ST25R UID reads may differ during re-select; retry without UID pinning.
            if (!selected_uid.empty() && st25r_is_gen1a_magic("")) return "Gen1A";
            if (st25r_is_gen3_magic(selected_uid)) return "Gen3";
            if (!selected_uid.empty() && st25r_is_gen3_magic("")) return "Gen3";
            if (st25r_is_gen4_magic(selected_uid)) return "Gen4";
            if (!selected_uid.empty() && st25r_is_gen4_magic("")) return "Gen4";
        }
        return "";
    }

    bool st25r_nfca_select_uid(std::vector<uint8_t> &uid, uint8_t &sak)
    {
        uid.clear();
        sak = 0;
        if (!st25r_init_nfca_reader()) return false;

        // WUPA short frame
        st25r_cmd(0xDB);
        st25r_cmd(0xC7);
        const uint8_t irq = st25r_wait_irq(0x10 | 0x04, 25);
        if (!(irq & 0x10)) return false;
        uint8_t atqa_len = 0;
        uint8_t atqa[8] = {0};
        if (!st25r_read_reg(0x1E, atqa_len) || atqa_len < 2) return false;
        const uint8_t atqa_read = std::min<uint8_t>(atqa_len, sizeof(atqa));
        if (!st25r_fifo_read(atqa, atqa_read)) return false;
        if (atqa_len > atqa_read) {
            uint8_t sink[8] = {0};
            uint8_t rem = static_cast<uint8_t>(atqa_len - atqa_read);
            while (rem > 0) {
                const uint8_t n = std::min<uint8_t>(rem, sizeof(sink));
                st25r_fifo_read(sink, n);
                rem = static_cast<uint8_t>(rem - n);
            }
        }
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }

        // CL1 anticollision
        const uint8_t anticol1[2] = {0x93, 0x20};
        uint8_t cl1_len = 8;
        uint8_t cl1[8] = {0};
        if (!st25r_nfca_transceive(anticol1, 2, false, cl1, cl1_len, 50, 0x01, false, 0)) return false;
        if (cl1_len < 5) return false;

        const uint8_t sel1[7] = {0x93, 0x70, cl1[0], cl1[1], cl1[2], cl1[3], cl1[4]};
        uint8_t sak_len = 4;
        uint8_t sak_buf[4] = {0};
        if (!st25r_nfca_transceive(sel1, 7, true, sak_buf, sak_len, 50, 0x00, false, 0)) return false;
        if (sak_len < 1) return false;
        sak = sak_buf[0];

        const bool cascade = (cl1[0] == 0x88) && (sak & 0x04);
        if (!cascade) {
            uid.assign(cl1, cl1 + 4);
            return true;
        }

        const uint8_t anticol2[2] = {0x95, 0x20};
        uint8_t cl2_len = 8;
        uint8_t cl2[8] = {0};
        if (!st25r_nfca_transceive(anticol2, 2, false, cl2, cl2_len, 50, 0x01, false, 0)) return false;
        if (cl2_len < 5) return false;

        const uint8_t sel2[7] = {0x95, 0x70, cl2[0], cl2[1], cl2[2], cl2[3], cl2[4]};
        sak_len = 4;
        std::memset(sak_buf, 0, sizeof(sak_buf));
        if (!st25r_nfca_transceive(sel2, 7, true, sak_buf, sak_len, 50, 0x00, false, 0)) return false;
        if (sak_len < 1) return false;
        sak = sak_buf[0];

        uid = {cl1[1], cl1[2], cl1[3], cl2[0], cl2[1], cl2[2], cl2[3]};
        return true;
    }

    bool st25r_nfcv_transceive(const uint8_t *req,
                               uint8_t req_len,
                               uint8_t *decoded,
                               uint8_t &decoded_len,
                               int timeout_ms)
    {
        if (!req || req_len == 0 || !decoded) return false;

        uint8_t encoded[96] = {0};
        uint8_t enc_len = encode_nfcv_1of4(encoded, req, req_len);

        st25r_cmd(0xDB);
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }
        if (!st25r_fifo_write(encoded, enc_len)) return false;
        st25r_set_ntx(enc_len, 0);
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }
        st25r_cmd(0xC5);  // transmit without CRC (already in stream)

        uint8_t irq = st25r_wait_irq(0x08, 20);
        if (irq & 0x08) irq |= st25r_wait_irq(0x10 | 0x04, timeout_ms);
        if (!(irq & 0x10)) return false;

        uint8_t fifo_cnt = 0;
        if (!st25r_read_reg(0x1E, fifo_cnt) || fifo_cnt < 3) return false;
        uint8_t raw[96] = {0};
        const uint8_t to_read = std::min<uint8_t>(fifo_cnt, sizeof(raw));
        if (!st25r_fifo_read(raw, to_read)) return false;

        uint8_t out_len = 0;
        if (!decode_vicc_manchester(raw, to_read, decoded, out_len)) return false;
        decoded_len = out_len;
        return true;
    }

    bool dumpNFCUnitMFU(const std::string &uid_hint,
                        std::vector<std::string> &out_lines,
                        std::string *error)
    {
#ifndef _WIN32
        std::vector<uint8_t> uid;
        uint8_t sak = 0;
        if (!st25r_nfca_select_uid(uid, sak)) {
            if (error) *error = "NFCA select failed";
            st25r_write_reg(0x02, 0x80);
            return false;
        }

        const std::string selected_uid = hex_compact(uid.data(), uid.size());
        const std::string expect_uid = normalize_uid_hex(uid_hint);
        if (!expect_uid.empty() && expect_uid != selected_uid) {
            if (error) *error = "Card UID changed, rescan card";
            st25r_write_reg(0x02, 0x80);
            return false;
        }

        uint8_t ver_len = 24;
        uint8_t ver[24] = {0};
        uint16_t last_page = 63;
        {
            const uint8_t get_ver[1] = {0x60};
            if (st25r_nfca_transceive(get_ver, 1, true, ver, ver_len, 40, 0x00, false, 0) && ver_len >= 8) {
                const uint8_t storage_sz = ver[6];
                if      (storage_sz == 0x0F) last_page = 44;   // NTAG213
                else if (storage_sz == 0x11) last_page = 134;  // NTAG215
                else if (storage_sz == 0x13) last_page = 230;  // NTAG216
                else                         last_page = 63;
            }
        }

        out_lines.clear();
        for (uint16_t page = 0; page <= last_page; page = static_cast<uint16_t>(page + 4)) {
            uint8_t rx_len = 20;
            uint8_t rx[20] = {0};
            const uint8_t cmd[2] = {0x30, static_cast<uint8_t>(page & 0xFF)};
            if (!st25r_nfca_transceive(cmd, 2, true, rx, rx_len, 40, 0x00, false, 0) || rx_len < 16) {
                if (page == 0) {
                    if (error) *error = "MFU read failed";
                    st25r_write_reg(0x02, 0x80);
                    return false;
                }
                break;
            }

            for (uint8_t i = 0; i < 4; ++i) {
                const uint16_t p = static_cast<uint16_t>(page + i);
                if (p > last_page) break;
                char prefix[8];
                std::snprintf(prefix, sizeof(prefix), "%02u:", static_cast<unsigned>(p));
                out_lines.push_back(std::string(prefix) + hex_compact(rx + i * 4, 4));
            }
        }

        st25r_write_reg(0x02, 0x80);
        if (out_lines.empty()) {
            if (error) *error = "MFU dump empty";
            return false;
        }
        return true;
#else
        (void)uid_hint;
        (void)out_lines;
        if (error) *error = "Unsupported platform";
        return false;
#endif
    }

    bool dumpNFCUnitMFC(const std::string &uid_hint,
                        const std::string &tag_type,
                        const std::vector<std::string> *mfc_key_hex,
                        std::string *magic_type,
                        std::vector<std::string> &out_lines,
                        std::string *error)
    {
#ifndef _WIN32
        std::vector<uint8_t> uid;
        uint8_t sak = 0;
        if (!st25r_nfca_select_uid(uid, sak)) {
            if (error) *error = "MFC select failed";
            st25r_write_reg(0x02, 0x80);
            return false;
        }

        const std::string selected_uid = hex_compact(uid.data(), uid.size());
        const std::string expect_uid = normalize_uid_hex(uid_hint);
        if (!expect_uid.empty() && expect_uid != selected_uid) {
            if (error) *error = "Card UID changed, rescan card";
            st25r_write_reg(0x02, 0x80);
            return false;
        }

        const int sector_count = mfc_sector_count_from_sak_tag(sak, tag_type);
        const int block_count = (sector_count == 40) ? 256 : (sector_count == 5 ? 20 : 64);
        auto format_mfc_block_line = [&](int block, const std::array<uint8_t, 16> &data) {
            char prefix[8];
            std::snprintf(prefix, sizeof(prefix), "%02d:", block);
            return std::string(prefix) + hex_compact(data.data(), data.size());
        };

        const std::string detected_magic = st25r_detect_magic_type(selected_uid);
        if (magic_type) *magic_type = detected_magic;
        if (!detected_magic.empty()) {
            out_lines.assign(static_cast<size_t>(block_count), std::string());
            bool any_ok = false;
            for (int block = 0; block < block_count; ++block) {
                std::array<uint8_t, 16> data{};
                if (st25r_mfc_read_plain_block(static_cast<uint8_t>(block), data)) {
                    out_lines[static_cast<size_t>(block)] = format_mfc_block_line(block, data);
                    any_ok = true;
                }
            }
            if (any_ok) {
                st25r_write_reg(0x02, 0x80);
                return true;
            }
            if (detected_magic == "Gen1A") {
                st25r_write_reg(0x02, 0x80);
                if (error) *error = "Gen1A detected but read failed";
                return false;
            }
        }

        static const std::array<std::array<uint8_t, 6>, 9> common_keys = {{
            {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
            {{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5}},
            {{0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7}},
            {{0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5}},
            {{0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD}},
            {{0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A}},
            {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}},
            {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
            {{0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56}},
        }};
        std::vector<std::array<uint8_t, 6>> auth_keys(common_keys.begin(), common_keys.end());
        append_external_mfc_keys(auth_keys, mfc_key_hex);

        out_lines.assign(static_cast<size_t>(block_count), std::string());
        bool any_block_ok = false;
        bool any_auth_ok = false;
        int first_failed_sector = -1;

        for (int sector = 0; sector < sector_count; ++sector) {
            const int first_block = mfc_sector_first_block(sector);
            const int sector_blocks = mfc_sector_block_count(sector);
            const int trailer_block = mfc_sector_trailer_block(sector);

            std::vector<uint8_t> sector_uid;
            uint8_t sector_sak = 0;
            if (!st25r_nfca_select_uid(sector_uid, sector_sak)) {
                if (first_failed_sector < 0) first_failed_sector = sector;
                continue;
            }
            const std::string sector_uid_hex = hex_compact(sector_uid.data(), sector_uid.size());
            if (sector_uid_hex != selected_uid) {
                if (error) *error = "Card moved during MFC dump, please keep card still";
                st25r_write_reg(0x02, 0x80);
                return false;
            }

            Crypto1Local crypto;
            bool auth_ok = false;
            for (const auto &k : auth_keys) {
                if (st25r_mfc_authenticate(0x60, static_cast<uint8_t>(trailer_block), k, sector_uid, crypto) ||
                    st25r_mfc_authenticate(0x61, static_cast<uint8_t>(trailer_block), k, sector_uid, crypto)) {
                    auth_ok = true;
                    any_auth_ok = true;
                    break;
                }
            }

            if (!auth_ok) {
                if (first_failed_sector < 0) first_failed_sector = sector;
                continue;
            }

            for (int i = 0; i < sector_blocks; ++i) {
                const int block = first_block + i;
                std::array<uint8_t, 16> data{};
                if (st25r_mfc_read_block(crypto, static_cast<uint8_t>(block), data)) {
                    out_lines[static_cast<size_t>(block)] = format_mfc_block_line(block, data);
                    any_block_ok = true;
                }
            }
        }

        st25r_write_reg(0x02, 0x80);
        if (!any_block_ok) {
            if (error) {
                if (!any_auth_ok) {
                    if (first_failed_sector >= 0) {
                        char msg[96];
                        std::snprintf(msg, sizeof(msg), "MFC auth failed on sector %d (common keys exhausted)", first_failed_sector);
                        *error = msg;
                    } else {
                        *error = "MFC auth failed (common keys exhausted)";
                    }
                } else {
                    *error = "MFC read failed after auth";
                }
            }
            return false;
        }

        return true;
#else
        (void)uid_hint;
        (void)tag_type;
        (void)out_lines;
        if (error) *error = "Unsupported platform";
        return false;
#endif
    }

    bool dumpNFCUnitISO15693(const std::string &uid_hint,
                             std::vector<std::string> &out_lines,
                             std::string *error)
    {
#ifndef _WIN32
        if (!configure_nfcv()) {
            if (error) *error = "ISO15693 init failed";
            return false;
        }

        uint8_t inv_req[3] = {0x26, 0x01, 0x00};
        uint8_t inv_dec[48] = {0};
        uint8_t inv_len = 0;
        if (!st25r_nfcv_transceive(inv_req, 3, inv_dec, inv_len, 80) || inv_len < 10) {
            restore_iso14443a();
            if (error) *error = "ISO15693 inventory failed";
            return false;
        }

        std::array<uint8_t, 8> uid_lsb{};
        for (size_t i = 0; i < uid_lsb.size(); ++i) uid_lsb[i] = inv_dec[2 + i];

        std::string uid_msb;
        uid_msb.reserve(16);
        for (int i = 7; i >= 0; --i) {
            char h[3];
            std::snprintf(h, sizeof(h), "%02X", uid_lsb[static_cast<size_t>(i)]);
            uid_msb += h;
        }
        const std::string expect_uid = normalize_uid_hex(uid_hint);
        if (!expect_uid.empty() && expect_uid != uid_msb) {
            restore_iso14443a();
            if (error) *error = "Card UID changed, rescan card";
            return false;
        }

        uint16_t block_count = 32;
        uint8_t sys_req[10] = {0x22, 0x2B};
        for (size_t i = 0; i < uid_lsb.size(); ++i) sys_req[2 + i] = uid_lsb[i];
        uint8_t sys_dec[64] = {0};
        uint8_t sys_len = 0;
        if (st25r_nfcv_transceive(sys_req, sizeof(sys_req), sys_dec, sys_len, 100) &&
            sys_len >= 12 && (sys_dec[0] & 0x01) == 0) {
            const uint8_t info_flags = sys_dec[1];
            size_t idx = 2 + 8;  // info_flags + UID
            if (info_flags & 0x01) idx += 1;  // DSFID
            if (info_flags & 0x02) idx += 1;  // AFI
            if ((info_flags & 0x04) && idx + 1 < sys_len) {
                block_count = static_cast<uint16_t>(sys_dec[idx] + 1);
            }
        }

        block_count = std::min<uint16_t>(block_count, 256);
        out_lines.clear();
        for (uint16_t block = 0; block < block_count; ++block) {
            uint8_t req[11] = {0x22, 0x20};
            for (size_t i = 0; i < uid_lsb.size(); ++i) req[2 + i] = uid_lsb[i];
            req[10] = static_cast<uint8_t>(block & 0xFF);

            uint8_t dec[64] = {0};
            uint8_t dec_len = 0;
            if (!st25r_nfcv_transceive(req, sizeof(req), dec, dec_len, 80) || dec_len < 2) {
                if (block == 0) {
                    restore_iso14443a();
                    if (error) *error = "ISO15693 read block failed";
                    return false;
                }
                break;
            }
            if (dec[0] & 0x01) {
                if (block == 0) {
                    restore_iso14443a();
                    if (error) {
                        char msg[48];
                        std::snprintf(msg, sizeof(msg), "ISO15693 error 0x%02X", dec_len > 1 ? dec[1] : 0xFF);
                        *error = msg;
                    }
                    return false;
                }
                break;
            }

            char prefix[8];
            std::snprintf(prefix, sizeof(prefix), "%02u:", static_cast<unsigned>(block));
            out_lines.push_back(std::string(prefix) + hex_compact(dec + 1, dec_len - 1));
        }

        restore_iso14443a();
        if (out_lines.empty()) {
            if (error) *error = "ISO15693 dump empty";
            return false;
        }
        return true;
#else
        (void)uid_hint;
        (void)out_lines;
        if (error) *error = "Unsupported platform";
        return false;
#endif
    }

    // ── ST25R3916B ISO14443A card reader ─────────────────────────────────────
    // Implements WUPA → ATQA → SDD CL1/CL2 → SELECT → UID + SAK.
    // Returns true if a card was found.
    bool readCardNFCUnit(I2cCardInfo &card)
    {
#ifndef _WIN32
        if (fd_ < 0) return false;
        card.magic_type.clear();
        card.atqa_hex.clear();
        card.sak_hex.clear();

        auto &hexlog = NfcHexLog::get();

        // Init sequence per M5UnitNFC library reference (confirmed via hardware testing):
        // 1. Enable oscillator only, configure mode/bitrate/receiver.
        // 2. CMD_NFC_INITIAL_FIELD_ON (0xC8) = RF Collision Avoidance + field on.
        // 3. Set tx_en | rx_en in OP_CONTROL.
        hexlog.log_event("NFC-I2C", "Init: OSC only, mode/receiver config, CMD_NFC_INITIAL_FIELD_ON");
        st25r_cmd(0xD6);              // ADJUST_REGULATORS first
        delay_ms(5);
        st25r_write_reg(0x02, 0x80);  // OP_CONTROL: en (osc only, no TX yet)
        delay_ms(20);
        // Clear any pending IRQs
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }

        // ISO14443A initiator mode at 106 kbps.
        st25r_write_reg(0x03, 0x08);  // MODE: om_iso14443a
        st25r_write_reg(0x04, 0x00);  // BIT_RATE: 106kbps
        st25r_write_reg(0x05, 0x00);  // ISO14443A_NFC: no antcl, no no_rx_par (initial)
        st25r_write_reg(0x09, 0x03);  // TX1+TX2 antenna drivers
        st25r_write_reg(0x26, 0x80);  // IRQ_MASK: only mask osc IRQ
        // Receiver configuration (per M5UnitNFC stability settings):
        st25r_write_reg(0x0B, 0x08);  // ReceiverConfig1: z_600k
        st25r_write_reg(0x0C, 0x2D);  // ReceiverConfig2: agc settings
        st25r_write_reg(0x0D, 0xD8);  // ReceiverConfig3: stability
        st25r_write_reg(0x0E, 0x22);  // ReceiverConfig4: stability
        delay_ms(10);

        // CMD_NFC_INITIAL_FIELD_ON (0xC8): RFCA + enable RF field.
        st25r_cmd(0xC8);
        delay_ms(10);
        // Now set tx_en (bit3) | rx_en (bit6) in OP_CONTROL.
        {
            uint8_t op = 0x80;
            st25r_read_reg(0x02, op);
            if (!st25r_write_reg(0x02, op | 0x48)) {
                hexlog.log_event("NFC-I2C", "ERR: OP_CONTROL write failed");
                return false;
            }
        }
        delay_ms(20);
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }  // clear IRQs

        // Clear FIFO + IRQ status, then send WUPA (wakes IDLE and HALT cards).
        hexlog.log_event("NFC-I2C", "CMD CLEAR_FIFO (0xDB) then TRANSMIT_WUPA (0xC7)");
        st25r_cmd(0xDB);  // CLEAR_FIFO
        st25r_cmd(0xC7);  // TRANSMIT_WUPA (7-bit short frame, no CRC)

        // Wait for ATQA (end-of-receive IRQ_MAIN bit4=rxe).
        uint8_t irq = st25r_wait_irq(0x10 | 0x04, 25);
        {
            char irq_msg[40];
            std::snprintf(irq_msg, sizeof(irq_msg), "WUPA irq=0x%02X (rxe=%d col=%d)",
                          irq, !!(irq & 0x10), !!(irq & 0x04));
            hexlog.log_event("NFC-I2C", irq_msg);
        }
        if (!(irq & 0x10)) {
            hexlog.log_event("NFC-I2C", "WUPA: no rxe → try ISO15693 SubCarrierStream");
            // ── ISO15693 INVENTORY (SubCarrierStream mode) ────────────────
            // ST25R3916B has no native ISO15693 mode.  It uses SubCarrierStream
            // (MODE=0x70) with software 1-of-4 PPM TX and Manchester decode RX.
            // Reference: M5UnitNFC configure_nfc_v() + encode_VCD() + decode_VICC().

            configure_nfcv();  // includes CMD_NFC_INITIAL_FIELD_ON + 5ms delay

            // Encode INVENTORY frame: {0x26, 0x01, 0x00} + CRC16 → 1-of-4 PPM
            const uint8_t inv_raw[3] = {0x26, 0x01, 0x00};
            uint8_t encoded[32];
            uint8_t enc_len = encode_nfcv_1of4(encoded, inv_raw, 3);

            st25r_cmd(0xDB);  // CLEAR_FIFO
            { uint8_t dummy15 = 0; st25r_read_reg(0x1A, dummy15); }

            if (!st25r_fifo_write(encoded, enc_len)) {
                hexlog.log_event("NFC-I2C", "ISO15693: FIFO write failed");
                restore_iso14443a();
                return false;
            }
            // NUM_TX_BYTES: total encoded bytes (CRC already inside encoded stream)
            st25r_set_ntx(enc_len, 0);
            { uint8_t dummy15 = 0; st25r_read_reg(0x1A, dummy15); }
            st25r_cmd(0xC5);  // TRANSMIT_WITHOUT_CRC (CRC is inside PPM stream)

            // Wait for txe then rxe
            uint8_t irq15 = st25r_wait_irq(0x08, 20);
            if (irq15 & 0x08) {
                irq15 |= st25r_wait_irq(0x10 | 0x04, 50);
            }
            {
                char msg15[64];
                std::snprintf(msg15, sizeof(msg15), "ISO15693 irq=0x%02X (rxe=%d txe=%d)",
                              irq15, !!(irq15 & 0x10), !!(irq15 & 0x08));
                hexlog.log_event("NFC-I2C", msg15);
            }
            if (!(irq15 & 0x10)) {
                hexlog.log_event("NFC-I2C", "ISO15693: no response → no card");
                restore_iso14443a();
                return false;
            }

            // Read raw Manchester-encoded response from FIFO
            uint8_t fc15 = 0;
            st25r_read_reg(0x1E, fc15);
            {
                char msg15[48];
                std::snprintf(msg15, sizeof(msg15), "ISO15693 FIFO=%d bytes", fc15);
                hexlog.log_event("NFC-I2C", msg15);
            }
            if (fc15 < 8) {
                hexlog.log_event("NFC-I2C", "ISO15693: response too short");
                restore_iso14443a();
                return false;
            }
            uint8_t raw15[64] = {0};
            uint8_t to_read15 = (fc15 < 64) ? fc15 : 64;
            if (!st25r_fifo_read(raw15, to_read15)) {
                hexlog.log_event("NFC-I2C", "ISO15693: FIFO read failed");
                restore_iso14443a();
                return false;
            }

            // Decode Manchester stream → flags + DSFID + UID (8 bytes) [+ CRC stripped]
            uint8_t decoded[32] = {0};
            uint8_t dec_len = 0;
            if (!decode_vicc_manchester(raw15, to_read15, decoded, dec_len) || dec_len < 10) {
                char msg15[64];
                std::snprintf(msg15, sizeof(msg15),
                              "ISO15693: decode failed (fc=%d dec=%d sof=0x%02X)",
                              fc15, dec_len, raw15[0]);
                hexlog.log_event("NFC-I2C", msg15);
                restore_iso14443a();
                return false;
            }

            // decoded[0] = response flags, decoded[1] = DSFID, decoded[2..9] = UID LSB-first
            std::string uid15;
            uid15.reserve(16);
            for (int i = 9; i >= 2; --i) {
                char h[3];
                std::snprintf(h, sizeof(h), "%02X", decoded[i]);
                uid15 += h;
            }
            {
                char msg15[72];
                std::snprintf(msg15, sizeof(msg15),
                              "ISO15693 flags=0x%02X DSFID=0x%02X UID=%s",
                              decoded[0], decoded[1], uid15.c_str());
                hexlog.log_event("NFC-I2C", msg15);
            }
            card.uid      = uid15;
            card.protocol = "ISO15693";
            card.detail   = "ISO15693 Tag";
            card.valid    = true;
            card.atqa_hex.clear();
            card.sak_hex.clear();
            restore_iso14443a();
            return true;
        }

        // Read ATQA (2 bytes) from FIFO via OP_READ_FIFO (0x9F).
        uint8_t fifo_cnt = 0;
        st25r_read_reg(0x1E, fifo_cnt);
        if (fifo_cnt < 2) {
            hexlog.log_event("NFC-I2C", "ATQA: FIFO too short (<2 bytes)");
            st25r_write_reg(0x02, 0x80);
            return false;
        }
        uint8_t atqa[2] = {0, 0};
        if (!st25r_fifo_read(atqa, 2)) {
            hexlog.log_event("NFC-I2C", "ATQA: FIFO read failed");
            st25r_write_reg(0x02, 0x80);
            return false;
        }
        // Drain any extra FIFO bytes beyond the 2 ATQA bytes.
        if (fifo_cnt > 2) {
            uint8_t drain[8];
            st25r_fifo_read(drain, (uint8_t)(fifo_cnt - 2));
        }
        // Clear IRQ before next step.
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }
        {
            char atqa_msg[40];
            std::snprintf(atqa_msg, sizeof(atqa_msg), "ATQA=%02X%02X", atqa[0], atqa[1]);
            hexlog.log_event("NFC-I2C", atqa_msg);
        }
        {
            char atqa_hex[5];
            std::snprintf(atqa_hex, sizeof(atqa_hex), "%02X%02X", atqa[0], atqa[1]);
            card.atqa_hex = atqa_hex;
        }

        // ── Anticollision CL1 ────────────────────────────────────────────────
        // Set antcl (bit0) in ISO14443A_NFC reg for anticollision bit-framing.
        // no_rx_par (bit6=0x40) is intentionally NOT set here (parity checked).
        hexlog.log_event("NFC-I2C", "Anticol CL1: ISO14443A_NFC=0x01, sending 93 20");
        st25r_write_reg(0x05, 0x01);  // antcl only (NOT 0x81 - bit7 is not no_rx_par!)
        st25r_cmd(0xDB);
        const uint8_t anticol1[2] = {0x93, 0x20};
        if (!st25r_fifo_write(anticol1, 2)) {
            hexlog.log_event("NFC-I2C", "CL1: FIFO write failed");
            st25r_write_reg(0x02, 0x80);
            return false;
        }
        // NUM_TX_BYTES: 16-bit big-endian at 0x22-0x23, value = (bytes<<3)|last_bits
        // For 2 complete bytes: (2<<3)|0 = 0x0010 → 0x22=0x00, 0x23=0x10
        st25r_set_ntx(2);
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }  // clear IRQ
        st25r_cmd(0xC5);  // TRANSMIT_WITHOUT_CRC (transceive: auto-enables RX after TX)

        // CMD_TRANSMIT_WITHOUT_CRC is a transceive: no separate RECEIVE command needed.
        // Wait directly for rxe (bit4) or col (bit2). No txe-then-RECEIVE sequence!
        irq = st25r_wait_irq(0x10 | 0x04, 50);
        {
            char irq_msg[48];
            std::snprintf(irq_msg, sizeof(irq_msg), "CL1 irq=0x%02X (rxe=%d col=%d)",
                          irq, !!(irq & 0x10), !!(irq & 0x04));
            hexlog.log_event("NFC-I2C", irq_msg);
        }
        if (!(irq & (0x10 | 0x04))) {
            hexlog.log_event("NFC-I2C", "CL1: timeout, no rxe/col");
            st25r_write_reg(0x02, 0x80);
            return false;
        }
        st25r_read_reg(0x1E, fifo_cnt);
        {
            char fcnt_msg[40];
            std::snprintf(fcnt_msg, sizeof(fcnt_msg), "CL1 FIFO=%d bytes", fifo_cnt);
            hexlog.log_event("NFC-I2C", fcnt_msg);
        }
        if (fifo_cnt < 5) {
            hexlog.log_event("NFC-I2C", "CL1: FIFO too short (<5 bytes)");
            st25r_write_reg(0x02, 0x80);
            return false;
        }
        uint8_t cl1[5] = {0};
        if (!st25r_fifo_read(cl1, 5)) {
            hexlog.log_event("NFC-I2C", "CL1: FIFO read failed");
            st25r_write_reg(0x02, 0x80);
            return false;
        }
        {
            char cl1_msg[64];
            std::snprintf(cl1_msg, sizeof(cl1_msg), "CL1=%02X%02X%02X%02X%02X",
                          cl1[0], cl1[1], cl1[2], cl1[3], cl1[4]);
            hexlog.log_event("NFC-I2C", cl1_msg);
        }

        // ── SELECT CL1 ───────────────────────────────────────────────────────
        // CMD_TRANSMIT_WITH_CRC (0xC4) automatically appends 2-byte CRC-A.
        // Write only 7 data bytes to FIFO (NOT 9); chip adds CRC to make 9 bytes on air.
        hexlog.log_event("NFC-I2C", "SELECT CL1: ISO14443A_NFC=0x00, 7 bytes, cmd 0xC4 (auto-CRC)");
        st25r_write_reg(0x05, 0x00);  // clear antcl for SELECT (normal framing + parity)
        st25r_cmd(0xDB);
        {
            const uint8_t sel1[7] = {0x93, 0x70, cl1[0], cl1[1], cl1[2], cl1[3], cl1[4]};
            st25r_fifo_write(sel1, 7);
        }
        st25r_set_ntx(7);   // 7 data bytes; chip appends 2 CRC bytes automatically
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }  // clear IRQ
        st25r_cmd(0xC4);  // TRANSMIT_WITH_CRC: TX the 7 bytes + auto CRC, then RX

        irq = st25r_wait_irq(0x10 | 0x08, 50);
        uint8_t sak = 0;
        {
            char irq_msg[40];
            std::snprintf(irq_msg, sizeof(irq_msg), "SELECT CL1 irq=0x%02X (rxe=%d txe=%d)", irq, !!(irq & 0x10), !!(irq & 0x08));
            hexlog.log_event("NFC-I2C", irq_msg);
        }
        if (irq & 0x10) {
            st25r_read_reg(0x1E, fifo_cnt);
            if (fifo_cnt >= 1) {
                uint8_t sak_buf[3] = {0};
                // Read up to 3 bytes (SAK + optional CRC if no_crc_rx=1)
                uint8_t to_read = fifo_cnt < 3 ? fifo_cnt : 3;
                st25r_fifo_read(sak_buf, to_read);
                sak = sak_buf[0];
            }
        }
        {
            char sak_msg[32];
            std::snprintf(sak_msg, sizeof(sak_msg), "SAK=0x%02X cascade=%d", sak, !!(sak & 0x04) && cl1[0] == 0x88);
            hexlog.log_event("NFC-I2C", sak_msg);
        }
        {
            char sak_hex[3];
            std::snprintf(sak_hex, sizeof(sak_hex), "%02X", sak);
            card.sak_hex = sak_hex;
        }

        // UID cascade: if uid[0]==CT(0x88) AND SAK bit2 set → more levels.
        const bool cascade = (cl1[0] == 0x88) && (sak & 0x04);

        uint8_t uid_buf[10] = {0};
        size_t uid_len = 0;

        if (!cascade) {
            // 4-byte UID: cl1[0..3]
            std::memcpy(uid_buf, cl1, 4);
            uid_len = 4;
        } else {
            // 7-byte UID: CL1 part = cl1[1..3], CL2 part = cl2[0..3]
            uid_buf[0] = cl1[1];
            uid_buf[1] = cl1[2];
            uid_buf[2] = cl1[3];

            // Anticollision CL2
            st25r_write_reg(0x05, 0x01);  // antcl for CL2
            st25r_cmd(0xDB);
            const uint8_t anticol2[2] = {0x95, 0x20};
            if (st25r_fifo_write(anticol2, 2)) {
                st25r_set_ntx(2);
                { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }
                st25r_cmd(0xC5);  // transceive

                irq = st25r_wait_irq(0x10 | 0x04, 50);
                if (irq & (0x10 | 0x04)) {
                    st25r_read_reg(0x1E, fifo_cnt);
                    if (fifo_cnt >= 5) {
                        uint8_t cl2[5] = {0};
                        if (st25r_fifo_read(cl2, 5)) {
                            // SELECT CL2 - use CMD_TRANSMIT_WITH_CRC (0xC4), 7 bytes only
                            st25r_write_reg(0x05, 0x00);  // clear antcl
                            st25r_cmd(0xDB);
                            {
                                const uint8_t sel2[7] = {0x95, 0x70,
                                    cl2[0], cl2[1], cl2[2], cl2[3], cl2[4]};
                                st25r_fifo_write(sel2, 7);
                            }
                            st25r_set_ntx(7);
                            { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }
                            st25r_cmd(0xC4);  // TRANSMIT_WITH_CRC (auto-CRC)
                            irq = st25r_wait_irq(0x10 | 0x08, 50);
                            if (irq & 0x10) {
                                st25r_read_reg(0x1E, fifo_cnt);
                                if (fifo_cnt >= 1) {
                                    uint8_t s2[3] = {0};
                                    uint8_t to_read = fifo_cnt < 3 ? fifo_cnt : 3;
                                    st25r_fifo_read(s2, to_read);
                                    sak = s2[0];
                                }
                            }
                            uid_buf[3] = cl2[0];
                            uid_buf[4] = cl2[1];
                            uid_buf[5] = cl2[2];
                            uid_buf[6] = cl2[3];
                            uid_len = 7;
                        }
                    }
                }
            }
            if (uid_len == 0) {
                // Partial: return the 3 CL1 bytes we already have.
                uid_len = 3;
            }
        }

        // Turn off RF field (keep oscillator on for fast next poll).
        // TX_CTRL stays at 0x03; it's set before OP_CONTROL each scan so is always safe.
        st25r_write_reg(0x02, 0x80);

        if (uid_len == 0) return false;

        // Format UID (no colon separators, consistent with GroveNFC path).
        std::string uid_str;
        uid_str.reserve(uid_len * 2);
        for (size_t i = 0; i < uid_len; ++i) {
            char h[3];
            std::snprintf(h, sizeof(h), "%02X", uid_buf[i]);
            uid_str += h;
        }
        card.uid = uid_str;
        card.valid = true;
        {
            char done_msg[80];
            std::snprintf(done_msg, sizeof(done_msg), "Card found: UID=%s SAK=%02X proto=%s",
                          uid_str.c_str(), sak, card.protocol.c_str());
            hexlog.log_event("NFC-I2C", done_msg);
        }

        // Classify by SAK (same mapping as readISO14A).
        if (sak == 0x08) {
            card.protocol = "MFC1K";
            card.detail = "MIFARE Classic 1K (SAK:08)";
        } else if (sak == 0x18) {
            card.protocol = "MFC4K";
            card.detail = "MIFARE Classic 4K (SAK:18)";
        } else if (sak == 0x09) {
            card.protocol = "MFCMini";
            card.detail = "MIFARE Classic Mini (SAK:09)";
        } else if (sak == 0x10 || sak == 0x11) {
            card.protocol = "MFPlus";
            char buf[32]; std::snprintf(buf, sizeof(buf), "MIFARE Plus (SAK:%02X)", sak);
            card.detail = buf;
        } else if (sak == 0x20 || sak == 0x28) {
            card.protocol = "DESFire";
            char buf[32]; std::snprintf(buf, sizeof(buf), "DESFire/JCOP (SAK:%02X)", sak);
            card.detail = buf;
        } else if (sak == 0x00) {
            // NTAG / Ultralight
            card.protocol = "NTAG";
            card.detail = "NTAG/Ultralight (SAK:00)";
        } else {
            card.protocol = "ISO14443A";
            char buf[32]; std::snprintf(buf, sizeof(buf), "ISO14443A (SAK:%02X)", sak);
            card.detail = buf;
        }

        const bool magic_probe_candidate =
            (sak == 0x08 || sak == 0x09 || sak == 0x18 || sak == 0x00 ||
             card.protocol == "MFC1K" || card.protocol == "MFC4K" ||
             card.protocol == "MFCMini" || card.protocol == "ISO14443A" ||
             card.protocol == "NTAG");

        if (magic_probe_candidate) {
            card.magic_type = st25r_detect_magic_type(uid_str);
            if (!card.magic_type.empty()) {
                hexlog.log_event("NFC-I2C", (std::string("Magic detected: ") + card.magic_type).c_str());
            } else {
                hexlog.log_event("NFC-I2C", "Magic detect done: None");
            }
        }
        return true;
#else
        card.valid = false;
        card.protocol = "None";
        card.uid = "";
        card.detail = "No card";
        return false;
#endif
    }

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
