#pragma once

// Linux spidev-based driver for ST25R3916 NFC SPI HAT.
// Implements ISO14443A card detection (REQA → anti-collision → UID).
// Protocol reference: ST25R3916 datasheet, ST RFAL source (rfal_rfst25r3916.h).

#include "nfc_models.hpp"
#include "nfc_i2c_device.hpp"  // reuse I2cCardInfo

#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <string>
#include <vector>

#if defined(__linux__)
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>
#include <linux/gpio.h>
#endif

#include <chrono>
#include <thread>

namespace nfc_app {

// ─── ST25R3916 register addresses ────────────────────────────────────────────
namespace st25r_reg {
    static constexpr uint8_t IO_CONF1            = 0x00;
    static constexpr uint8_t IO_CONF2            = 0x01;
    static constexpr uint8_t OP_CONTROL          = 0x02;
    static constexpr uint8_t MODE               = 0x03;
    static constexpr uint8_t BIT_RATE           = 0x04;
    static constexpr uint8_t ISO14443A_NFC      = 0x05;
    static constexpr uint8_t ISO14443B_1        = 0x06;
    static constexpr uint8_t ISO14443B_2        = 0x07;
    static constexpr uint8_t STREAM_MODE        = 0x08;
    static constexpr uint8_t AUX                = 0x09;
    static constexpr uint8_t RX_CONF1           = 0x0A;
    static constexpr uint8_t RX_CONF2           = 0x0B;
    static constexpr uint8_t RX_CONF3           = 0x0C;
    static constexpr uint8_t RX_CONF4           = 0x0D;
    static constexpr uint8_t MASK_RX_TIMER      = 0x0E;
    static constexpr uint8_t NO_RESPONSE_TIMER1 = 0x0F;
    static constexpr uint8_t NO_RESPONSE_TIMER2 = 0x10;
    static constexpr uint8_t TIMER_EMV_CONTROL  = 0x11;
    static constexpr uint8_t GPT1               = 0x12;
    static constexpr uint8_t GPT2               = 0x13;
    static constexpr uint8_t PPON2              = 0x14;
    static constexpr uint8_t IRQ_MASK_MAIN      = 0x15;
    static constexpr uint8_t IRQ_MASK_TIMER_NFC = 0x16;
    static constexpr uint8_t IRQ_MASK_ERR_WUP   = 0x17;
    static constexpr uint8_t IRQ_MAIN           = 0x18;
    static constexpr uint8_t IRQ_TIMER_NFC      = 0x19;
    static constexpr uint8_t IRQ_ERR_WUP        = 0x1A;
    static constexpr uint8_t FIFO_STATUS1       = 0x1B;
    static constexpr uint8_t FIFO_STATUS2       = 0x1C;
    static constexpr uint8_t COLLISION_STATUS   = 0x1D;
    static constexpr uint8_t NUM_TX_BYTES1      = 0x1E;
    static constexpr uint8_t NUM_TX_BYTES2      = 0x1F;
    static constexpr uint8_t NFCIP1_BIT_RATE    = 0x20;
    static constexpr uint8_t AD_RESULT          = 0x21;
    static constexpr uint8_t ANT_TUNE_A         = 0x22;
    static constexpr uint8_t ANT_TUNE_B         = 0x23;
    static constexpr uint8_t TX_DRIVER          = 0x24;
    static constexpr uint8_t PT_MOD             = 0x25;
    static constexpr uint8_t RF_CONF_A          = 0x26;
    static constexpr uint8_t RF_CONF_B          = 0x27;
    static constexpr uint8_t FIELD_THRES_ACTV   = 0x30;
    static constexpr uint8_t FIELD_THRES_DEACTV = 0x31;
    static constexpr uint8_t REGULATOR_CONTROL  = 0x32;
    static constexpr uint8_t REGULATOR_RESULT   = 0x33;
    static constexpr uint8_t IC_IDENTITY        = 0x3F;
}

// ST25R3916 IC Identity values (bits 7:3 = 0x14 = 10100b → 0xA0 for rev0)
static constexpr uint8_t ST25R3916_IC_TYPE_MASK  = 0xF8;
static constexpr uint8_t ST25R3916_IC_TYPE_VALUE = 0xA0;  // 10100 << 3

// ST25R3916 direct command opcodes (sent as 0xC0 | cmd)
namespace st25r_cmd {
    static constexpr uint8_t SET_DEFAULT            = 0x01;
    static constexpr uint8_t CLEAR                  = 0x02;
    static constexpr uint8_t TRANSMIT_WITH_CRC      = 0x03;
    static constexpr uint8_t TRANSMIT_WITHOUT_CRC   = 0x04;
    static constexpr uint8_t TRANSMIT_REQA          = 0x05;
    static constexpr uint8_t TRANSMIT_WUPA          = 0x06;
    static constexpr uint8_t NFCA_INITIAL_RF_COLLISION_AVOID = 0x07;
    static constexpr uint8_t NFCA_RESP_RF_COLLISION_AVOID    = 0x08;
    static constexpr uint8_t GOTO_SENSE             = 0x0A;
    static constexpr uint8_t CLEAR_FIFO             = 0x0F;
    static constexpr uint8_t RF_TRANSMITTER_ON      = 0x1E;
    static constexpr uint8_t RF_TRANSMITTER_OFF     = 0x1F;
}

// SPI command byte encoding
static constexpr uint8_t ST25R_SPI_CMD_WRITE_REG  = 0x00; // bits[7:6]=00
static constexpr uint8_t ST25R_SPI_CMD_READ_REG   = 0x40; // bits[7:6]=01
static constexpr uint8_t ST25R_SPI_CMD_FIFO_WRITE = 0x80; // bits[7:6]=10
static constexpr uint8_t ST25R_SPI_CMD_FIFO_READ  = 0xBF; // special
static constexpr uint8_t ST25R_SPI_CMD_DIRECT     = 0xC0; // bits[7:6]=11

// ─────────────────────────────────────────────────────────────────────────────
// NfcSpiDevice — ST25R3916 SPI NFC HAT driver
// ─────────────────────────────────────────────────────────────────────────────
class NfcSpiDevice {
public:
    NfcSpiDevice() = default;
    ~NfcSpiDevice() { close(); }

    bool open(const std::string &spidev_path, std::string *error = nullptr)
    {
#if defined(__linux__)
        close();
        spidev_path_ = spidev_path;
        fd_ = ::open(spidev_path.c_str(), O_RDWR);
        if (fd_ < 0) {
            if (error) *error = std::string("open(") + spidev_path + "): " + std::strerror(errno);
            return false;
        }

        // SPI mode 0 (CPOL=0, CPHA=0)
        uint8_t mode = SPI_MODE_0;
        if (::ioctl(fd_, SPI_IOC_WR_MODE, &mode) < 0) {
            if (error) *error = "ioctl SPI_IOC_WR_MODE failed";
            ::close(fd_); fd_ = -1;
            return false;
        }

        // 8 bits per word
        uint8_t bits = 8;
        if (::ioctl(fd_, SPI_IOC_WR_BITS_PER_WORD, &bits) < 0) {
            if (error) *error = "ioctl SPI_IOC_WR_BITS_PER_WORD failed";
            ::close(fd_); fd_ = -1;
            return false;
        }

        // 4 MHz max
        uint32_t speed = 4000000;
        if (::ioctl(fd_, SPI_IOC_WR_MAX_SPEED_HZ, &speed) < 0) {
            if (error) *error = "ioctl SPI_IOC_WR_MAX_SPEED_HZ failed";
            ::close(fd_); fd_ = -1;
            return false;
        }

        // Probe: read IC_IDENTITY register
        uint8_t ic_id = 0;
        if (!read_reg(st25r_reg::IC_IDENTITY, &ic_id)) {
            if (error) *error = "SPI transfer failed (no response from ST25R)";
            ::close(fd_); fd_ = -1;
            return false;
        }

        // Check IC type bits (bits 7:3 should be 0x14 = 10100b)
        const uint8_t ic_type = ic_id & ST25R3916_IC_TYPE_MASK;
        if (ic_type != ST25R3916_IC_TYPE_VALUE) {
            if (error) {
                char buf[80];
                std::snprintf(buf, sizeof(buf),
                    "ST25R3916 not found (IC_IDENTITY=0x%02X, expected 0xA0..0xA7)", ic_id);
                *error = buf;
            }
            ::close(fd_); fd_ = -1;
            return false;
        }

        // Initialize chip
        init_chip();
        device_kind_ = DeviceKind::ST25RNFC;
        return true;
#else
        if (error) *error = "SPI not supported on this platform";
        return false;
#endif
    }

    void close()
    {
#if defined(__linux__)
        if (fd_ >= 0) {
            // Turn RF off before closing
            direct_cmd(st25r_cmd::RF_TRANSMITTER_OFF);
            ::close(fd_);
            fd_ = -1;
        }
#endif
        device_kind_ = DeviceKind::Unknown;
    }

    bool is_open() const { return fd_ >= 0; }
    DeviceKind device_kind() const { return device_kind_; }
    const std::string &path() const { return spidev_path_; }

    // Scan for one ISO14443A card. Returns false if no card present or error.
    bool readCard(I2cCardInfo *out)
    {
        if (!out || fd_ < 0) return false;
        out->valid = false;

#if defined(__linux__)
        // Clear IRQ flags
        direct_cmd(st25r_cmd::CLEAR);

        // Set up for ISO14443A 106 kbps
        write_reg(st25r_reg::MODE, 0x00);       // ISO14443A / NFC
        write_reg(st25r_reg::BIT_RATE, 0x00);   // 106 kbps TX/RX
        // Enable RF transmitter + receiver
        write_reg(st25r_reg::OP_CONTROL, 0xC0); // en=1, tx_en=1
        sleep_ms(5);

        // Enable RF field
        direct_cmd(st25r_cmd::RF_TRANSMITTER_ON);
        sleep_ms(6);

        // Send REQA
        uint8_t atqa[2] = {0, 0};
        if (!send_reqa(atqa)) {
            direct_cmd(st25r_cmd::RF_TRANSMITTER_OFF);
            return false;
        }

        // Anti-collision / UID read
        uint8_t uid[10] = {0};
        uint8_t uid_len = 0;
        if (!anti_collision_loop(uid, &uid_len)) {
            direct_cmd(st25r_cmd::RF_TRANSMITTER_OFF);
            return false;
        }

        // Determine SAK (single/double/triple size)
        uint8_t sak = last_sak_;

        // Build result
        std::string uid_str;
        for (uint8_t i = 0; i < uid_len; ++i) {
            if (i > 0) uid_str += ':';
            char hex[3];
            std::snprintf(hex, sizeof(hex), "%02X", uid[i]);
            uid_str += hex;
        }

        char atqa_str[5];
        std::snprintf(atqa_str, sizeof(atqa_str), "%02X%02X", atqa[0], atqa[1]);
        char sak_str[3];
        std::snprintf(sak_str, sizeof(sak_str), "%02X", sak);

        out->uid      = uid_str;
        out->atqa_hex = std::string(atqa_str);
        out->sak_hex  = std::string(sak_str);
        out->protocol = identify_protocol(atqa, sak);
        out->detail   = std::string("ST25R3916 ") + spidev_path_ +
                        " ATQA:" + atqa_str + " SAK:" + sak_str;
        out->valid    = true;

        direct_cmd(st25r_cmd::RF_TRANSMITTER_OFF);
        return true;
#else
        return false;
#endif
    }

private:
    int fd_ = -1;
    DeviceKind device_kind_ = DeviceKind::Unknown;
    std::string spidev_path_;
    uint8_t last_sak_ = 0x00;

    static void sleep_ms(int ms)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }

#if defined(__linux__)
    bool spi_transfer(const uint8_t *tx, uint8_t *rx, size_t len)
    {
        if (fd_ < 0 || !tx || !rx || len == 0) return false;
        struct spi_ioc_transfer tr{};
        tr.tx_buf = (unsigned long)tx;
        tr.rx_buf = (unsigned long)rx;
        tr.len    = static_cast<uint32_t>(len);
        tr.speed_hz = 4000000;
        tr.bits_per_word = 8;
        tr.delay_usecs = 0;
        return (::ioctl(fd_, SPI_IOC_MESSAGE(1), &tr) >= 0);
    }

    bool write_reg(uint8_t addr, uint8_t value)
    {
        uint8_t tx[2] = { static_cast<uint8_t>(ST25R_SPI_CMD_WRITE_REG | (addr & 0x3F)), value };
        uint8_t rx[2] = {0, 0};
        return spi_transfer(tx, rx, 2);
    }

    bool read_reg(uint8_t addr, uint8_t *value)
    {
        uint8_t tx[2] = { static_cast<uint8_t>(ST25R_SPI_CMD_READ_REG | (addr & 0x3F)), 0x00 };
        uint8_t rx[2] = {0, 0};
        if (!spi_transfer(tx, rx, 2)) return false;
        if (value) *value = rx[1];
        return true;
    }

    bool direct_cmd(uint8_t cmd)
    {
        uint8_t tx[1] = { static_cast<uint8_t>(ST25R_SPI_CMD_DIRECT | (cmd & 0x3F)) };
        uint8_t rx[1] = {0};
        return spi_transfer(tx, rx, 1);
    }

    bool write_fifo(const uint8_t *data, size_t len)
    {
        if (len == 0 || len > 96) return false;
        std::vector<uint8_t> tx(len + 1);
        std::vector<uint8_t> rx(len + 1);
        tx[0] = ST25R_SPI_CMD_FIFO_WRITE;
        std::memcpy(tx.data() + 1, data, len);
        return spi_transfer(tx.data(), rx.data(), len + 1);
    }

    bool read_fifo(uint8_t *data, size_t max_len, size_t *got_len)
    {
        // First check how many bytes are in FIFO
        uint8_t fs1 = 0, fs2 = 0;
        read_reg(st25r_reg::FIFO_STATUS1, &fs1);
        read_reg(st25r_reg::FIFO_STATUS2, &fs2);
        // FIFO_STATUS1[7:0] = fifo_b (number of complete bytes)
        // FIFO_STATUS2[2:0] = fifo_lb (number of bits in last incomplete byte)
        const size_t fifo_bytes = fs1;
        if (fifo_bytes == 0) { if (got_len) *got_len = 0; return true; }
        const size_t read_len = std::min(fifo_bytes, max_len);

        std::vector<uint8_t> tx(read_len + 1, 0);
        std::vector<uint8_t> rx(read_len + 1, 0);
        tx[0] = ST25R_SPI_CMD_FIFO_READ;
        if (!spi_transfer(tx.data(), rx.data(), read_len + 1)) return false;
        std::memcpy(data, rx.data() + 1, read_len);
        if (got_len) *got_len = read_len;
        return true;
    }

    bool wait_irq(uint8_t irq_mask, int timeout_ms)
    {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            uint8_t irq = 0;
            if (!read_reg(st25r_reg::IRQ_MAIN, &irq)) return false;
            if (irq & irq_mask) return true;
            sleep_ms(1);
        }
        return false;
    }

    void init_chip()
    {
        // Software reset
        direct_cmd(st25r_cmd::SET_DEFAULT);
        sleep_ms(2);

        // Disable all IRQ masks (we poll IRQ_MAIN register directly)
        write_reg(st25r_reg::IRQ_MASK_MAIN, 0xFF);
        write_reg(st25r_reg::IRQ_MASK_TIMER_NFC, 0xFF);
        write_reg(st25r_reg::IRQ_MASK_ERR_WUP, 0xFF);

        // No-response timer: ~86ms at 106kbps
        write_reg(st25r_reg::NO_RESPONSE_TIMER1, 0x00);
        write_reg(st25r_reg::NO_RESPONSE_TIMER2, 0x64);

        // Enable regulator
        write_reg(st25r_reg::REGULATOR_CONTROL, 0x10);
        sleep_ms(2);
    }

    // Send REQA (7-bit) and read ATQA (2 bytes)
    // Returns true if a valid ATQA was received.
    bool send_reqa(uint8_t atqa_out[2])
    {
        // Clear FIFO and IRQ flags
        direct_cmd(st25r_cmd::CLEAR_FIFO);
        direct_cmd(st25r_cmd::CLEAR);

        // Set 7-bit transmission for REQA
        write_reg(st25r_reg::ISO14443A_NFC, 0x01); // antcl=0, rx_nfc=1 (no CRC on ATQA)
        write_reg(st25r_reg::NUM_TX_BYTES1, 0x00);
        write_reg(st25r_reg::NUM_TX_BYTES2, 0x07); // 7 bits

        // Load REQA (0x26) into FIFO
        uint8_t reqa = 0x26;
        write_fifo(&reqa, 1);

        // Transmit without CRC
        direct_cmd(st25r_cmd::TRANSMIT_WITHOUT_CRC);

        // Wait for rx done or error
        if (!wait_irq(0x40 | 0x01, 30)) return false; // IRQ_MAIN bit 6=rx_done, 0=err

        // Read ATQA from FIFO
        size_t got = 0;
        if (!read_fifo(atqa_out, 2, &got)) return false;
        return (got >= 2);
    }

    // ISO14443A anti-collision loop: returns UID (up to 10 bytes) and length
    bool anti_collision_loop(uint8_t uid_out[10], uint8_t *uid_len_out)
    {
        uint8_t uid[10] = {0};
        uint8_t uid_pos = 0;
        last_sak_ = 0;

        for (int cascade = 1; cascade <= 3; ++cascade) {
            const uint8_t sel_code = (cascade == 1) ? 0x93 : (cascade == 2) ? 0x95 : 0x97;

            // SDD request: SEL + NVB=0x20 (no UID bits sent)
            direct_cmd(st25r_cmd::CLEAR_FIFO);
            direct_cmd(st25r_cmd::CLEAR);

            write_reg(st25r_reg::ISO14443A_NFC, 0x01); // no CRC for SDD
            write_reg(st25r_reg::NUM_TX_BYTES1, 0x00);
            write_reg(st25r_reg::NUM_TX_BYTES2, 0x10); // 16 bits = 2 bytes

            uint8_t sdd[2] = { sel_code, 0x20 };
            write_fifo(sdd, 2);
            direct_cmd(st25r_cmd::TRANSMIT_WITHOUT_CRC);

            if (!wait_irq(0x40 | 0x01, 30)) return false;

            // Read 5 bytes: CT/UID0, UID1, UID2, UID3, BCC
            uint8_t sdd_resp[5] = {0};
            size_t got = 0;
            if (!read_fifo(sdd_resp, 5, &got) || got < 5) return false;

            // BCC check
            if ((sdd_resp[0] ^ sdd_resp[1] ^ sdd_resp[2] ^ sdd_resp[3] ^ sdd_resp[4]) != 0) {
                return false; // BCC error
            }

            bool is_ct = (sdd_resp[0] == 0x88); // Cascade Tag → UID continues
            uint8_t uid_start = is_ct ? 1 : 0;
            uint8_t uid_bytes = is_ct ? 3 : 4;

            for (uint8_t i = 0; i < uid_bytes && uid_pos < 10; ++i) {
                uid[uid_pos++] = sdd_resp[uid_start + i];
            }

            // SELECT: SEL + NVB=0x70 + 4 UID bytes + BCC
            direct_cmd(st25r_cmd::CLEAR_FIFO);
            direct_cmd(st25r_cmd::CLEAR);

            write_reg(st25r_reg::ISO14443A_NFC, 0x00); // CRC on for SELECT
            uint8_t sel_frame[6];
            sel_frame[0] = sel_code;
            sel_frame[1] = 0x70;
            sel_frame[2] = sdd_resp[0];
            sel_frame[3] = sdd_resp[1];
            sel_frame[4] = sdd_resp[2];
            sel_frame[5] = sdd_resp[3];
            // BCC not sent in SELECT frame (it's only for SDD)
            write_fifo(sel_frame, 6);
            write_reg(st25r_reg::NUM_TX_BYTES1, 0x00);
            write_reg(st25r_reg::NUM_TX_BYTES2, 0x30); // 3 bytes = 24 bits (frame without BCC)
            // Actually: SEL(1) + NVB(1) + 4 UID bytes = 6 bytes
            write_reg(st25r_reg::NUM_TX_BYTES1, 0x00);
            write_reg(st25r_reg::NUM_TX_BYTES2, 0x40); // 4*8=0x30? or just 6 bytes
            // Use TRANSMIT_WITH_CRC so the chip appends CRC
            // Number of bytes: 6 bytes excluding CRC
            {
                const uint16_t nbytes6 = 6 * 8; // bits
                write_reg(st25r_reg::NUM_TX_BYTES1, static_cast<uint8_t>((nbytes6 >> 8) & 0x01));
                write_reg(st25r_reg::NUM_TX_BYTES2, static_cast<uint8_t>(nbytes6 & 0xFF));
            }
            direct_cmd(st25r_cmd::TRANSMIT_WITH_CRC);

            if (!wait_irq(0x40 | 0x01, 30)) return false;

            // Read SAK (1 byte + 2 CRC bytes, but we just need SAK)
            uint8_t sak_resp[3] = {0};
            size_t sak_got = 0;
            if (!read_fifo(sak_resp, 3, &sak_got) || sak_got < 1) return false;

            last_sak_ = sak_resp[0];

            // Check cascade bit in SAK
            if ((last_sak_ & 0x04) == 0) {
                // UID complete
                break;
            }
        }

        std::memcpy(uid_out, uid, uid_pos);
        *uid_len_out = uid_pos;
        return (uid_pos >= 4);
    }

    // Identify ISO14443A protocol from ATQA + SAK
    static std::string identify_protocol(const uint8_t atqa[2], uint8_t sak)
    {
        // SAK-based classification (ISO14443-3)
        if (sak == 0x08 || sak == 0x18 || sak == 0x09 ||
            sak == 0x28 || sak == 0x38 || sak == 0x88 || sak == 0x98) {
            if (sak == 0x18) return "MFC4K";
            return "MFC1K";
        }
        if (sak == 0x00) {
            // NTAG / MIFARE Ultralight
            if (atqa[0] == 0x44) return "NTAG213";
            if (atqa[0] == 0x04 && atqa[1] == 0x00) return "MFUL";
            return "ISO14443A";
        }
        if ((sak & 0x20) != 0) return "ISO14443A"; // ISO-DEP
        return "ISO14443A";
    }
#endif
};

} // namespace nfc_app
