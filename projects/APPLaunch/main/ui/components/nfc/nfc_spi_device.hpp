#pragma once

// Linux spidev-based driver for ST25R3916 NFC SPI HAT.
// Implements ISO14443A card detection (REQA → anti-collision → UID).
// Protocol reference: ST25R3916 datasheet, ST RFAL source (rfal_rfst25r3916.h).

#include "nfc_models.hpp"
#include "nfc_i2c_device.hpp"  // reuse I2cCardInfo
#include "nfc_hex_logger.hpp"

#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <array>
#include <string>
#include <vector>
#include <utility>

#if defined(__linux__)
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>
#include <linux/gpio.h>
#if __has_include(<linux/i2c-dev.h>)
#include <linux/i2c-dev.h>
#define NFC_SPI_HAS_I2CDEV 1
#else
#define NFC_SPI_HAS_I2CDEV 0
#endif
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
    static constexpr uint8_t PASSIVE_TARGET     = 0x08;
    static constexpr uint8_t STREAM_MODE        = 0x09;
    static constexpr uint8_t AUX                = 0x0A;
    static constexpr uint8_t RX_CONF1           = 0x0B;
    static constexpr uint8_t RX_CONF2           = 0x0C;
    static constexpr uint8_t RX_CONF3           = 0x0D;
    static constexpr uint8_t RX_CONF4           = 0x0E;
    static constexpr uint8_t MASK_RX_TIMER      = 0x0F;
    static constexpr uint8_t NO_RESPONSE_TIMER1 = 0x10;
    static constexpr uint8_t NO_RESPONSE_TIMER2 = 0x11;
    static constexpr uint8_t TIMER_EMV_CONTROL  = 0x12;
    static constexpr uint8_t GPT1               = 0x13;
    static constexpr uint8_t GPT2               = 0x14;
    static constexpr uint8_t PPON2              = 0x15;
    static constexpr uint8_t IRQ_MASK_MAIN      = 0x16;
    static constexpr uint8_t IRQ_MASK_TIMER_NFC = 0x17;
    static constexpr uint8_t IRQ_MASK_ERR_WUP   = 0x18;
    static constexpr uint8_t IRQ_MAIN           = 0x1A;
    static constexpr uint8_t IRQ_TIMER_NFC      = 0x1B;
    static constexpr uint8_t IRQ_ERR_WUP        = 0x1C;
    static constexpr uint8_t FIFO_STATUS1       = 0x1E;
    static constexpr uint8_t FIFO_STATUS2       = 0x1F;
    static constexpr uint8_t COLLISION_STATUS   = 0x20;
    static constexpr uint8_t NUM_TX_BYTES1      = 0x22;
    static constexpr uint8_t NUM_TX_BYTES2      = 0x23;
    static constexpr uint8_t NFCIP1_BIT_RATE    = 0x24;
    static constexpr uint8_t AD_RESULT          = 0x25;
    static constexpr uint8_t ANT_TUNE_A         = 0x26;
    static constexpr uint8_t ANT_TUNE_B         = 0x27;
    static constexpr uint8_t TX_DRIVER          = 0x28;
    static constexpr uint8_t PT_MOD             = 0x29;
    static constexpr uint8_t FIELD_THRES_ACTV   = 0x2A;
    static constexpr uint8_t FIELD_THRES_DEACTV = 0x2B;
    static constexpr uint8_t REGULATOR_CONTROL  = 0x2C;
    static constexpr uint8_t REGULATOR_RESULT   = 0x2C;
    static constexpr uint8_t IC_IDENTITY        = 0x3F;
}

// ST25R3916 IC Identity values (bits 7:3) from ST's RFAL register definitions.
static constexpr uint8_t ST25R3916_IC_TYPE_MASK  = 0xF8;
static constexpr uint8_t ST25R3916_IC_TYPE_VALUE = 0x28;  // ST25R3916: 5 << 3
static constexpr uint8_t ST25R3916B_IC_TYPE_VALUE = 0x30; // ST25R3916B: 6 << 3

// ST25R3916 direct command opcodes (sent as 0xC0 | cmd)
namespace st25r_cmd {
    static constexpr uint8_t SET_DEFAULT            = 0x01;
    static constexpr uint8_t STOP                   = 0x02;
    static constexpr uint8_t CLEAR                  = STOP;
    static constexpr uint8_t TRANSMIT_WITH_CRC      = 0x04;
    static constexpr uint8_t TRANSMIT_WITHOUT_CRC   = 0x05;
    static constexpr uint8_t TRANSMIT_REQA          = 0x06;
    static constexpr uint8_t TRANSMIT_WUPA          = 0x07;
    static constexpr uint8_t NFCA_INITIAL_RF_COLLISION_AVOID = 0x08;
    static constexpr uint8_t NFCA_RESP_RF_COLLISION_AVOID    = 0x09;
    static constexpr uint8_t GOTO_SENSE             = 0x0D;
    static constexpr uint8_t GOTO_SLEEP             = 0x0E;
    static constexpr uint8_t MASK_RECEIVE_DATA      = 0x10;
    static constexpr uint8_t UNMASK_RECEIVE_DATA    = 0x11;
    static constexpr uint8_t RESET_RXGAIN           = 0x15;
    static constexpr uint8_t ADJUST_REGULATORS      = 0x16;
    static constexpr uint8_t CLEAR_FIFO             = 0x1B;
}

// SPI command byte encoding
static constexpr uint8_t ST25R_SPI_CMD_WRITE_REG  = 0x00; // bits[7:6]=00
static constexpr uint8_t ST25R_SPI_CMD_READ_REG   = 0x40; // bits[7:6]=01
static constexpr uint8_t ST25R_SPI_CMD_FIFO_WRITE = 0x80; // bits[7:6]=10
static constexpr uint8_t ST25R_SPI_CMD_FIFO_READ  = 0x9F; // special
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
        rst_line_unavailable_ = false;
        bss_line_unavailable_ = false;
        power_gate_enabled_ = false;
        power_enable_level_ = -1;
        power_line_target_ = "unset";
        accepted_nonstandard_ic_ = false;
        pi4io_status_ = "not-checked";
        // /dev/spidev0.2 = ST25R3916 on CardputerZero HAT (verified by reference nfc_linux demo).
        // ST25R3916 SPI spec: CPOL=0/CPHA=1 = SPI_MODE_1, 5 MHz max, CS kernel-managed.
        // Read format: [CMD_BYTE | ADDR, 0x00] → rx[1] is the register value (no extra dummy).
        const bool is_st25r_spidev = (spidev_path.find("spidev0.2") != std::string::npos);
        lora_compat_profile_ = is_st25r_spidev ? false
            : (parse_env_int("NFC_SPI_LORA_COMPAT_PROFILE", 1) != 0);
        strict_probe_profile_ = is_st25r_spidev ? true
            : (parse_env_int("NFC_SPI_STRICT_PROFILE", lora_compat_profile_ ? 1 : 0) != 0);
        bss_wait_before_transfer_ = (parse_env_int("NFC_SPI_BSS_WAIT_BEFORE_XFER", 0) != 0);
        bss_ready_level_ = parse_env_int("NFC_SPI_BSS_READY_LEVEL", 0);
        bss_xfer_ready_timeout_ms_ = parse_env_int("NFC_SPI_BSS_XFER_READY_TIMEOUT_MS", 0);
        bss_manual_select_ = false;
        bss_active_level_ = 0;
        bss_inactive_level_ = 1;
        bss_select_settle_us_ = 0;
        bss_release_settle_us_ = 0;
        spi_no_cs_enabled_ = false;
        probe_7f00_valid_ = false;
        probe_7f00_ok_ = false;
        probe_7f00_rx0_ = 0x00;
        probe_7f00_rx1_ = 0x00;
        rst_sysfs_gpio_ = -1;
        bss_sysfs_gpio_ = -1;
        irq_sysfs_gpio_ = -1;
        // Assign path before prepare_spi_hat_power_gate so that
        // configure_st25r_control_lines() can detect spidev0.2 via spidev_path_.
        spidev_path_ = spidev_path;
        prepare_spi_hat_power_gate();
        fd_ = ::open(spidev_path.c_str(), O_RDWR);
        if (fd_ < 0) {
            if (error) *error = std::string("open(") + spidev_path + "): " + std::strerror(errno);
            return false;
        }

        // SPI mode is selected by probe candidates below.
        // 8 bits per word
        uint8_t bits = 8;
        if (::ioctl(fd_, SPI_IOC_WR_BITS_PER_WORD, &bits) < 0) {
            if (error) *error = "ioctl SPI_IOC_WR_BITS_PER_WORD failed";
            ::close(fd_); fd_ = -1;
            return false;
        }

        // Give the transceiver rail a short settle window after enabling HAT power.
        sleep_ms(20);

        struct ProbeSnapshot {
            uint8_t ic = 0xFF;
            uint8_t r0 = 0xFF;
            uint8_t r1 = 0xFF;
            uint8_t r2 = 0xFF;
            bool ok = false;
        } best;

        const uint8_t mode_candidates_all[] = {
            // spidev0.2 (ST25R3916): MODE_1 is correct per datasheet and reference demo.
            // Other paths retain legacy MODE_2 first for compatibility.
            static_cast<uint8_t>(parse_env_int("NFC_SPI_MODE0", is_st25r_spidev ? SPI_MODE_1 : SPI_MODE_2)),
            static_cast<uint8_t>(parse_env_int("NFC_SPI_MODE1", SPI_MODE_1)),
            static_cast<uint8_t>(parse_env_int("NFC_SPI_MODE2", SPI_MODE_0)),
            static_cast<uint8_t>(parse_env_int("NFC_SPI_MODE3", SPI_MODE_3)),
        };
        // spidev0.2: 5 MHz (reference-verified). Other paths: 1 MHz conservative probe.
        const uint32_t speed_candidates_all[] = {
            static_cast<uint32_t>(parse_env_int("NFC_SPI_SPEED", is_st25r_spidev ? 5000000u : 1000000u)),
        };
        // spidev0.2: ST25R3916 read = CMD + DUMMY → data in rx[1], no extra dummy byte needed.
        // read_dummy=true means 3-byte transfer; read_dummy=false means 2-byte (correct for ST25R).
        const bool read_dummy_candidates_all[] = {
            parse_env_int("NFC_SPI_READ_DUMMY_FIRST",  is_st25r_spidev ? 0 : 1) != 0,
            parse_env_int("NFC_SPI_READ_DUMMY_SECOND", is_st25r_spidev ? 1 : 0) != 0,
        };

        std::vector<uint8_t> mode_candidates;
        std::vector<uint32_t> speed_candidates;
        std::vector<bool> read_dummy_candidates;
        if (strict_probe_profile_) {
            mode_candidates.push_back(mode_candidates_all[0]);
            speed_candidates.push_back(speed_candidates_all[0]);
            read_dummy_candidates.push_back(read_dummy_candidates_all[0]);
        } else {
            mode_candidates.assign(std::begin(mode_candidates_all), std::end(mode_candidates_all));
            speed_candidates.assign(std::begin(speed_candidates_all), std::end(speed_candidates_all));
            read_dummy_candidates.assign(std::begin(read_dummy_candidates_all), std::end(read_dummy_candidates_all));
        }

        bool opened = false;
        bool expanded_probe = false;
        auto run_probe = [&](const std::vector<uint8_t> &modes,
                             const std::vector<uint32_t> &speeds,
                             const std::vector<bool> &dummy_opts) -> bool {
            for (uint8_t mode : modes) {
                for (uint32_t speed : speeds) {
                    uint8_t mode_with_flags = mode;
                    bool no_cs_enabled = false;
                    if (bss_manual_select_) {
                        mode_with_flags = static_cast<uint8_t>(mode_with_flags | SPI_NO_CS);
                        if (::ioctl(fd_, SPI_IOC_WR_MODE, &mode_with_flags) < 0) {
                            mode_with_flags = mode;
                            if (::ioctl(fd_, SPI_IOC_WR_MODE, &mode_with_flags) < 0) continue;
                        } else {
                            no_cs_enabled = true;
                        }
                    } else {
                        if (::ioctl(fd_, SPI_IOC_WR_MODE, &mode_with_flags) < 0) continue;
                    }
                    if (::ioctl(fd_, SPI_IOC_WR_MAX_SPEED_HZ, &speed) < 0) continue;
                    spi_mode_ = mode;
                    spi_no_cs_enabled_ = no_cs_enabled;
                    spi_speed_hz_ = speed;

                    // 2-byte probe: send [0x7F, 0x00] (READ cmd + dummy),
                    // rx[0]=cmd-phase MISO, rx[1]=data-phase MISO (IC identity).
                    if (!probe_7f00_valid_) {
                        uint8_t tx7f[2] = {0x7F, 0x00};
                        uint8_t rx7f[2] = {0x00, 0x00};
                        probe_7f00_ok_ = spi_transfer(tx7f, rx7f, sizeof(tx7f));

                        probe_7f00_rx0_ = rx7f[0];
                        probe_7f00_rx1_ = rx7f[1];
                        probe_7f00_valid_ = true;
                        char msg[160];
                        std::snprintf(msg, sizeof(msg),
                            "probe 0x7F00 mode=%u speed=%u no_cs=%u -> [%02X %02X] ok=%u",
                            static_cast<unsigned>(spi_mode_),
                            static_cast<unsigned>(spi_speed_hz_),
                            spi_no_cs_enabled_ ? 1u : 0u,
                            static_cast<unsigned>(probe_7f00_rx0_),
                            static_cast<unsigned>(probe_7f00_rx1_),
                            probe_7f00_ok_ ? 1u : 0u);
                        NfcHexLog::get().log_event("SPI", msg);
                    }

                    for (bool with_dummy : dummy_opts) {
                        read_reg_with_dummy_ = with_dummy;
                        if (parse_env_int("NFC_SPI_FLIPPER_PROBE_INIT", 1) != 0) {
                            direct_cmd(st25r_cmd::SET_DEFAULT);
                            sleep_ms(2);
                            write_reg(st25r_reg::IO_CONF2, 0x04);
                        }
                        ProbeSnapshot snap;
                        const bool ok_ic = read_reg(st25r_reg::IC_IDENTITY, &snap.ic);
                        const bool ok0 = read_reg(st25r_reg::IO_CONF1, &snap.r0);
                        const bool ok1 = read_reg(st25r_reg::IO_CONF2, &snap.r1);
                        const bool ok2 = read_reg(st25r_reg::OP_CONTROL, &snap.r2);
                        snap.ok = ok_ic && ok0 && ok1 && ok2;

                        if (snap.ok) best = snap;

                        const uint8_t ic_type = static_cast<uint8_t>(snap.ic & ST25R3916_IC_TYPE_MASK);
                        if (snap.ok && is_supported_ic_type(ic_type)) {
                            int confirm_hits = 0;
                            for (int i = 0; i < 3; ++i) {
                                uint8_t confirm_ic = 0;
                                if (!read_reg(st25r_reg::IC_IDENTITY, &confirm_ic)) continue;
                                if (is_supported_ic_type(static_cast<uint8_t>(confirm_ic & ST25R3916_IC_TYPE_MASK))) {
                                    ++confirm_hits;
                                }
                            }
                            if (confirm_hits >= 3) {
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        };

        opened = run_probe(mode_candidates, speed_candidates, read_dummy_candidates);
        if (!opened && strict_probe_profile_) {
            expanded_probe = true;
            const std::vector<uint8_t> all_modes(std::begin(mode_candidates_all), std::end(mode_candidates_all));
            const std::vector<uint32_t> all_speeds(std::begin(speed_candidates_all), std::end(speed_candidates_all));
            const std::vector<bool> all_dummy(std::begin(read_dummy_candidates_all), std::end(read_dummy_candidates_all));
            opened = run_probe(all_modes, all_speeds, all_dummy);
        }

        // Debug fallback: allow bring-up on non-standard IC_ID if SPI reads are
        // at least stable enough to look like a live slave (not uniform stuck bus).
        if (!opened && parse_env_int("NFC_SPI_ACCEPT_ANY_IC", 0) != 0 && best.ok) {
            const bool looks_stuck_hi = (best.ic == 0x0F && best.r0 == 0x0F && best.r1 == 0x0F && best.r2 == 0x0F);
            const bool looks_stuck_lo = (best.ic == 0x00 && best.r0 == 0x00 && best.r1 == 0x00 && best.r2 == 0x00);
            const bool looks_uniform = (best.ic == best.r0 && best.r0 == best.r1 && best.r1 == best.r2);
            if (!looks_stuck_hi && !looks_stuck_lo && !looks_uniform) {
                opened = true;
                accepted_nonstandard_ic_ = true;
            }
        }

probe_done:
        if (!opened) {
            const bool looks_stuck_hi = (best.ic == 0x0F && best.r0 == 0x0F && best.r1 == 0x0F && best.r2 == 0x0F);
            const bool looks_stuck_lo = (best.ic == 0x00 && best.r0 == 0x00 && best.r1 == 0x00 && best.r2 == 0x00);
            const bool looks_uniform = (best.ic == best.r0 && best.r0 == best.r1 && best.r1 == best.r2);
            const bool looks_echo = detect_spi_echo_path();
            const int rst_before = sample_rst_line_level();
            const int bss_before = sample_bss_line_level();
            const int irq_before = sample_irq_line_level();
            uint8_t first_tx[3] = { static_cast<uint8_t>(ST25R_SPI_CMD_READ_REG | (st25r_reg::IC_IDENTITY & 0x3F)), 0x00, 0x00 };
            uint8_t first_rx[3] = {0, 0, 0};
            const bool first_ok = spi_transfer(first_tx, first_rx, sizeof(first_tx));
            const int rst_after = sample_rst_line_level();
            const int bss_after = sample_bss_line_level();
            const int irq_after = sample_irq_line_level();
            if (error) {
                char buf[900];
                std::snprintf(buf, sizeof(buf),
                    "ST25R3916 not found (IC=0x%02X IO0=0x%02X IO1=0x%02X OP=0x%02X mode=%u speed=%u dummy=%u strict=%u expanded=%u lora=%u bss_wait=%u bss_to=%d power5v=%u level=%d pwr_line=%s pi4io=%s) "
                    "GPIO[rst,bss,irq]=[%d,%d,%d]->[%d,%d,%d] firstSPI[%02X %02X %02X]->[%02X %02X %02X] first_ok=%u probe7f00=[%02X %02X] probe_ok=%u%s%s%s%s%s",
                    best.ic, best.r0, best.r1, best.r2,
                    static_cast<unsigned>(spi_mode_),
                    static_cast<unsigned>(spi_speed_hz_),
                    read_reg_with_dummy_ ? 1u : 0u,
                    strict_probe_profile_ ? 1u : 0u,
                    expanded_probe ? 1u : 0u,
                    lora_compat_profile_ ? 1u : 0u,
                    bss_wait_before_transfer_ ? 1u : 0u,
                    bss_xfer_ready_timeout_ms_,
                    power_gate_enabled_ ? 1u : 0u,
                    power_enable_level_,
                    power_line_target_.c_str(),
                    pi4io_status_.c_str(),
                    rst_before, bss_before, irq_before,
                    rst_after, bss_after, irq_after,
                    first_tx[0], first_tx[1], first_tx[2],
                    first_rx[0], first_rx[1], first_rx[2],
                    first_ok ? 1u : 0u,
                    static_cast<unsigned>(probe_7f00_rx0_),
                    static_cast<unsigned>(probe_7f00_rx1_),
                    probe_7f00_ok_ ? 1u : 0u,
                    (looks_stuck_hi || looks_stuck_lo || looks_uniform)
                        ? " [SPI readback is uniform/stuck; check CAP power, CS wiring, and MISO path]"
                        : "",
                    looks_echo
                        ? " [SPI RX resembles TX (echo); check MOSI/MISO routing or missing slave drive on MISO]"
                        : "",
                    bss_line_unavailable_
                        ? " [BSS GPIO unavailable; check GPIO22 ownership]"
                        : "",
                    rst_line_unavailable_
                        ? " [RST GPIO unavailable; verify GPIO26 ownership/permissions]"
                        : "",
                    !best.ok
                        ? " [SPI transfer failed during probe]"
                        : "");
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
            set_rf_field(false);
            ::close(fd_);
            fd_ = -1;
        }
        if (power_line_fd_ >= 0) {
            ::close(power_line_fd_);
            power_line_fd_ = -1;
        }
        if (rst_line_fd_ >= 0) {
            ::close(rst_line_fd_);
            rst_line_fd_ = -1;
        }
        if (bss_line_fd_ >= 0) {
            ::close(bss_line_fd_);
            bss_line_fd_ = -1;
        }
        if (irq_line_fd_ >= 0) {
            ::close(irq_line_fd_);
            irq_line_fd_ = -1;
        }
#endif
        rst_sysfs_gpio_ = -1;
        bss_sysfs_gpio_ = -1;
        irq_sysfs_gpio_ = -1;
        rst_line_unavailable_ = false;
        bss_line_unavailable_ = false;
        accepted_nonstandard_ic_ = false;
        device_kind_ = DeviceKind::Unknown;
    }

    bool is_open() const { return fd_ >= 0; }
    DeviceKind device_kind() const { return device_kind_; }
    const std::string &path() const { return spidev_path_; }
    bool accepted_nonstandard_ic() const { return accepted_nonstandard_ic_; }
    bool has_probe_7f00() const { return probe_7f00_valid_; }
    bool probe_7f00_ok() const { return probe_7f00_ok_; }
    uint8_t probe_7f00_rx0() const { return probe_7f00_rx0_; }
    uint8_t probe_7f00_rx1() const { return probe_7f00_rx1_; }

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
        // Enable RF field
        set_rf_field(true);
        sleep_ms(6);

        // Send REQA
        uint8_t atqa[2] = {0, 0};
        if (!send_reqa(atqa)) {
            set_rf_field(false);
            return false;
        }

        // Anti-collision / UID read
        uint8_t uid[10] = {0};
        uint8_t uid_len = 0;
        if (!anti_collision_loop(uid, &uid_len)) {
            set_rf_field(false);
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

        set_rf_field(false);
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
    int power_line_fd_ = -1;
    int rst_line_fd_ = -1;
    int bss_line_fd_ = -1;
    int irq_line_fd_ = -1;
    int rst_sysfs_gpio_ = -1;
    int bss_sysfs_gpio_ = -1;
    int irq_sysfs_gpio_ = -1;
    bool rst_line_unavailable_ = false;
    bool bss_line_unavailable_ = false;
    uint8_t spi_mode_ = SPI_MODE_0;
    uint32_t spi_speed_hz_ = 1000000;
    bool read_reg_with_dummy_ = false;
    bool lora_compat_profile_ = true;
    bool strict_probe_profile_ = true;
    bool bss_wait_before_transfer_ = true;
    bool bss_manual_select_ = false;
    bool spi_no_cs_enabled_ = false;
    bool power_gate_enabled_ = false;
    int power_enable_level_ = -1;
    std::string power_line_target_ = "unset";
    bool accepted_nonstandard_ic_ = false;
    bool probe_7f00_valid_ = false;
    bool probe_7f00_ok_ = false;
    uint8_t probe_7f00_rx0_ = 0x00;
    uint8_t probe_7f00_rx1_ = 0x00;
    int bss_active_level_ = 0;
    int bss_inactive_level_ = 1;
    int bss_select_settle_us_ = 0;
    int bss_release_settle_us_ = 0;
    int bss_ready_level_ = 0;
    int bss_xfer_ready_timeout_ms_ = 25;
    std::string pi4io_status_ = "not-checked";

    static void sleep_ms(int ms)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }

#if defined(__linux__)
    static bool is_supported_ic_type(uint8_t ic_type)
    {
        return ic_type == ST25R3916_IC_TYPE_VALUE || ic_type == ST25R3916B_IC_TYPE_VALUE;
    }

    static int parse_env_int(const char *name, int fallback, int base = 10)
    {
        const char *value = std::getenv(name);
        if (!value || !*value) return fallback;
        char *end = nullptr;
        const long parsed = std::strtol(value, &end, base);
        if (end == value || (end && *end != '\0')) return fallback;
        return static_cast<int>(parsed);
    }

    static bool gpio_open_output_line(const char *chip_path, int offset, int value, int *line_fd)
    {
        if (!chip_path || !line_fd) return false;
        const int chip_fd = ::open(chip_path, O_RDONLY);
        if (chip_fd < 0) return false;

        struct gpiohandle_request req;
        std::memset(&req, 0, sizeof(req));
        req.lines = 1;
        req.lineoffsets[0] = static_cast<uint32_t>(offset);
        req.flags = GPIOHANDLE_REQUEST_OUTPUT;
        req.default_values[0] = static_cast<uint8_t>(value ? 1 : 0);
        std::snprintf(req.consumer_label, sizeof(req.consumer_label), "applaunch-nfc-5v");

        const bool ok = (::ioctl(chip_fd, GPIO_GET_LINEHANDLE_IOCTL, &req) == 0);
        ::close(chip_fd);
        if (!ok) return false;
        *line_fd = req.fd;
        return true;
    }

    static bool gpio_line_name_matches(const char *name)
    {
        static const char *candidates[] = {
            "G5_HAT_5VOUT_EN", "HAT_5VOUT_EN", "GPIO5_HAT_5VOUT_EN",
        };
        if (!name || !*name) return false;
        for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
            if (std::strcmp(name, candidates[i]) == 0) return true;
        }
        return false;
    }

    static bool gpio_find_named_line(char *chip_path, size_t chip_path_size, int *offset)
    {
        if (!chip_path || chip_path_size == 0 || !offset) return false;
        for (int chip_index = 0; chip_index < 8; ++chip_index) {
            char path[64];
            std::snprintf(path, sizeof(path), "/dev/gpiochip%d", chip_index);
            const int chip_fd = ::open(path, O_RDONLY);
            if (chip_fd < 0) continue;

            struct gpiochip_info chip_info;
            std::memset(&chip_info, 0, sizeof(chip_info));
            if (::ioctl(chip_fd, GPIO_GET_CHIPINFO_IOCTL, &chip_info) < 0) {
                ::close(chip_fd);
                continue;
            }

            for (int line = 0; line < static_cast<int>(chip_info.lines); ++line) {
                struct gpioline_info line_info;
                std::memset(&line_info, 0, sizeof(line_info));
                line_info.line_offset = static_cast<uint32_t>(line);
                if (::ioctl(chip_fd, GPIO_GET_LINEINFO_IOCTL, &line_info) < 0) continue;
                if (gpio_line_name_matches(line_info.name) || gpio_line_name_matches(line_info.consumer)) {
                    std::snprintf(chip_path, chip_path_size, "%s", path);
                    *offset = line;
                    ::close(chip_fd);
                    return true;
                }
            }
            ::close(chip_fd);
        }
        return false;
    }

    static bool gpio_open_input_line(const char *chip_path, int offset, int *line_fd)
    {
        if (!chip_path || !line_fd) return false;
        const int chip_fd = ::open(chip_path, O_RDONLY);
        if (chip_fd < 0) return false;

        struct gpiohandle_request req;
        std::memset(&req, 0, sizeof(req));
        req.lines = 1;
        req.lineoffsets[0] = static_cast<uint32_t>(offset);
        req.flags = GPIOHANDLE_REQUEST_INPUT;
        std::snprintf(req.consumer_label, sizeof(req.consumer_label), "applaunch-nfc-in");

        const bool ok = (::ioctl(chip_fd, GPIO_GET_LINEHANDLE_IOCTL, &req) == 0);
        ::close(chip_fd);
        if (!ok) return false;
        *line_fd = req.fd;
        return true;
    }

    static bool gpio_get_input_line_value(int line_fd, int *value)
    {
        if (line_fd < 0 || !value) return false;
        struct gpiohandle_data data;
        std::memset(&data, 0, sizeof(data));
        if (::ioctl(line_fd, GPIOHANDLE_GET_LINE_VALUES_IOCTL, &data) < 0) return false;
        *value = data.values[0] ? 1 : 0;
        return true;
    }

    static bool gpio_set_output_line_value(int line_fd, int value)
    {
        if (line_fd < 0) return false;
        struct gpiohandle_data data;
        std::memset(&data, 0, sizeof(data));
        data.values[0] = static_cast<uint8_t>(value ? 1 : 0);
        return (::ioctl(line_fd, GPIOHANDLE_SET_LINE_VALUES_IOCTL, &data) == 0);
    }

    static int write_text_file(const char *path, const char *value)
    {
        const int fd = ::open(path, O_WRONLY);
        if (fd < 0) return -1;
        const ssize_t n = ::write(fd, value, std::strlen(value));
        ::close(fd);
        return n < 0 ? -1 : 0;
    }

    static bool gpio_export_if_needed(int gpio)
    {
        char path[64];
        std::snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/value", gpio);
        if (::access(path, F_OK) == 0) return true;

        char gpio_str[16];
        std::snprintf(gpio_str, sizeof(gpio_str), "%d", gpio);
        if (write_text_file("/sys/class/gpio/export", gpio_str) < 0 && errno != EBUSY) {
            return false;
        }
        sleep_ms(50);
        return true;
    }

    static bool gpio_set_output_value_sysfs(int gpio, int value)
    {
        if (!gpio_export_if_needed(gpio)) return false;

        char direction_path[64];
        std::snprintf(direction_path, sizeof(direction_path), "/sys/class/gpio/gpio%d/direction", gpio);
        if (value) {
            if (write_text_file(direction_path, "high") == 0) return true;
        } else {
            if (write_text_file(direction_path, "low") == 0) return true;
        }

        if (write_text_file(direction_path, "out") < 0) return false;
        char value_path[64];
        std::snprintf(value_path, sizeof(value_path), "/sys/class/gpio/gpio%d/value", gpio);
        return write_text_file(value_path, value ? "1" : "0") == 0;
    }

    static bool gpio_prepare_input_sysfs(int gpio)
    {
        if (!gpio_export_if_needed(gpio)) return false;
        char direction_path[64];
        std::snprintf(direction_path, sizeof(direction_path), "/sys/class/gpio/gpio%d/direction", gpio);
        return write_text_file(direction_path, "in") == 0;
    }

    static bool gpio_get_input_value_sysfs(int gpio, int *value)
    {
        if (gpio < 0 || !value) return false;
        char value_path[64];
        std::snprintf(value_path, sizeof(value_path), "/sys/class/gpio/gpio%d/value", gpio);
        const int fd = ::open(value_path, O_RDONLY);
        if (fd < 0) return false;
        char ch = 0;
        const ssize_t n = ::read(fd, &ch, 1);
        ::close(fd);
        if (n != 1) return false;
        *value = (ch == '0') ? 0 : 1;
        return true;
    }

    static bool i2c_write_reg(int fd, uint8_t reg, uint8_t value)
    {
        const uint8_t buf[2] = {reg, value};
        return ::write(fd, buf, sizeof(buf)) == static_cast<ssize_t>(sizeof(buf));
    }

    static std::string try_init_pi4io_power_gate()
    {
#if NFC_SPI_HAS_I2CDEV
        if (parse_env_int("NFC_SPI_PI4IO_ENABLE", 1) == 0) return "disabled";
        const int bus = parse_env_int("NFC_SPI_PI4IO_BUS", 1);
        const int addr = parse_env_int("NFC_SPI_PI4IO_ADDR", 0x43, 0);

        char dev_path[64];
        std::snprintf(dev_path, sizeof(dev_path), "/dev/i2c-%d", bus);
        const int fd = ::open(dev_path, O_RDWR);
        if (fd < 0) return "open-failed";

        if (::ioctl(fd, I2C_SLAVE, addr) < 0) {
            ::close(fd);
            return "select-failed";
        }

        const uint8_t probe = 0x00;
        if (::write(fd, &probe, 1) != 1) {
            ::close(fd);
            return "probe-failed";
        }

        // PI4IO defaults used by LoRa page: set P0 output high.
        (void)i2c_write_reg(fd, 0x02, 0x00);
        (void)i2c_write_reg(fd, 0x01, 0x01);
        (void)i2c_write_reg(fd, 0x03, 0xFE);
        ::close(fd);
        return "ok";
#endif
        return "i2cdev-unavailable";
    }

    bool set_5vout_level(int enable_value)
    {
        const char *chip_env = std::getenv("NFC_SPI_POWER_CHIP");
        const char *offset_env = std::getenv("NFC_SPI_POWER_OFFSET");
        char chip_path[64] = "/dev/gpiochip0";
        int offset = 5;
        bool used_named_line = false;
        if (chip_env && *chip_env) {
            std::snprintf(chip_path, sizeof(chip_path), "%s", chip_env);
            offset = parse_env_int("NFC_SPI_POWER_OFFSET", 5);
        } else if (offset_env && *offset_env) {
            offset = parse_env_int("NFC_SPI_POWER_OFFSET", 5);
        } else {
            int detected_offset = 5;
            char detected_chip[64] = "/dev/gpiochip0";
            if (gpio_find_named_line(detected_chip, sizeof(detected_chip), &detected_offset)) {
                std::snprintf(chip_path, sizeof(chip_path), "%s", detected_chip);
                offset = detected_offset;
                used_named_line = true;
            }
        }
        {
            char buf[96];
            std::snprintf(buf, sizeof(buf), "%s:%d%s", chip_path, offset, used_named_line ? "(named)" : "");
            power_line_target_ = buf;
        }
        if (power_line_fd_ < 0) {
            if (gpio_open_output_line(chip_path, offset, enable_value, &power_line_fd_)) {
                power_enable_level_ = enable_value;
                sleep_ms(50);
                return true;
            }
        } else {
            if (gpio_set_output_line_value(power_line_fd_, enable_value)) {
                power_enable_level_ = enable_value;
                sleep_ms(50);
                return true;
            }
        }

        const int gpio = parse_env_int("NFC_SPI_POWER_GPIO", -1);
        if (gpio >= 0) {
            if (!gpio_set_output_value_sysfs(gpio, enable_value)) return false;
            power_enable_level_ = enable_value;
            {
                char buf[64];
                std::snprintf(buf, sizeof(buf), "sysfs:%d", gpio);
                power_line_target_ = buf;
            }
            sleep_ms(50);
            return true;
        }
        power_line_target_ += "(set-failed)";
        return false;
    }

    bool enable_5vout_before_spi_power_gate(bool invert_polarity)
    {
        if (parse_env_int("NFC_SPI_5VOUT_ENABLE", 1) == 0) return true;
        int active_low = parse_env_int("NFC_SPI_5VOUT_ACTIVE_LOW", 1);
        if (invert_polarity) active_low = active_low ? 0 : 1;
        const int enable_value = active_low ? 0 : 1;
        return set_5vout_level(enable_value);
    }

    void configure_st25r_control_lines(bool pulse_reset)
    {
        if (parse_env_int("NFC_SPI_CTRL_ENABLE", 1) == 0) return;

        const char *chip_env = std::getenv("NFC_SPI_CTRL_CHIP");
        char chip_path[64] = "/dev/gpiochip0";
        if (chip_env && *chip_env) std::snprintf(chip_path, sizeof(chip_path), "%s", chip_env);

        // CardputerZero top pins: G26->RST, G22->BSS (env overrides supported).
        const int rst_offset = parse_env_int("NFC_SPI_RST_OFFSET", 26);
        const int bss_offset = parse_env_int("NFC_SPI_BSS_OFFSET", 22);
        const int irq_offset = parse_env_int("NFC_SPI_IRQ_OFFSET", 23);
        const int irq_input = parse_env_int("NFC_SPI_IRQ_INPUT", 1);
        const int bss_input = parse_env_int("NFC_SPI_BSS_INPUT", 0);
        const int rst_active_level = parse_env_int("NFC_SPI_RST_ACTIVE_LEVEL", 0);
        const int bss_level = parse_env_int("NFC_SPI_BSS_LEVEL", 0);
        const int bss_active_level = bss_level ? 1 : 0;
        const int bss_inactive_level = parse_env_int("NFC_SPI_BSS_INACTIVE_LEVEL", bss_active_level ? 0 : 1) ? 1 : 0;
        const bool prefer_hw_cs = (spidev_path_.find("/dev/spidev0.2") != std::string::npos);

        bss_active_level_ = bss_active_level;
        bss_inactive_level_ = bss_inactive_level;
        bss_select_settle_us_ = parse_env_int("NFC_SPI_BSS_SELECT_SETTLE_US", 0);
        bss_release_settle_us_ = parse_env_int("NFC_SPI_BSS_RELEASE_SETTLE_US", 0);
        bss_manual_select_ = (!bss_input) &&
            (parse_env_int("NFC_SPI_BSS_MANUAL_SELECT", prefer_hw_cs ? 0 : 1) != 0);

        if (irq_input && irq_line_fd_ < 0) {
            if (!gpio_open_input_line(chip_path, irq_offset, &irq_line_fd_)) {
                const int irq_gpio = parse_env_int("NFC_SPI_IRQ_GPIO", irq_offset);
                if (irq_gpio >= 0 && gpio_prepare_input_sysfs(irq_gpio)) {
                    irq_sysfs_gpio_ = irq_gpio;
                }
            } else {
                irq_sysfs_gpio_ = -1;
            }
        }

        if (bss_input) {
            if (bss_line_fd_ < 0) {
                if (!gpio_open_input_line(chip_path, bss_offset, &bss_line_fd_)) {
                    bss_line_unavailable_ = true;
                    const int bss_gpio = parse_env_int("NFC_SPI_BSS_GPIO", bss_offset);
                    if (bss_gpio >= 0 && gpio_prepare_input_sysfs(bss_gpio)) {
                        bss_line_unavailable_ = false;
                        bss_sysfs_gpio_ = bss_gpio;
                    }
                } else {
                    bss_line_unavailable_ = false;
                    bss_sysfs_gpio_ = -1;
                }
            }
            if (bss_line_fd_ >= 0) {
                const int ready_level = parse_env_int("NFC_SPI_BSS_READY_LEVEL", 0);
                const int ready_timeout_ms = parse_env_int("NFC_SPI_BSS_READY_TIMEOUT_MS", lora_compat_profile_ ? 20 : 0);
                bss_ready_level_ = ready_level;
                if (bss_xfer_ready_timeout_ms_ <= 0 && ready_timeout_ms > 0) {
                    bss_xfer_ready_timeout_ms_ = ready_timeout_ms;
                }
                if (ready_timeout_ms > 0) {
                    for (int i = 0; i < ready_timeout_ms; ++i) {
                        int v = -1;
                        if (!gpio_get_input_line_value(bss_line_fd_, &v)) break;
                        if (v == ready_level) break;
                        sleep_ms(1);
                    }
                }
            }
        } else {
            if (bss_line_fd_ < 0) {
                if (!gpio_open_output_line(chip_path, bss_offset, bss_inactive_level_, &bss_line_fd_)) {
                    bss_line_unavailable_ = true;
                }
            } else {
                (void)gpio_set_output_line_value(bss_line_fd_, bss_inactive_level_);
                bss_line_unavailable_ = false;
            }
            bss_sysfs_gpio_ = -1;
        }

        // If BSS line is unavailable, fall back to hardware CS instead of failing transfers.
        if (bss_manual_select_ && bss_line_fd_ < 0 && bss_sysfs_gpio_ < 0) {
            bss_manual_select_ = false;
        }

        if (rst_line_fd_ < 0) {
            if (!gpio_open_output_line(chip_path, rst_offset, rst_active_level, &rst_line_fd_)) {
                rst_line_unavailable_ = true;
                const int rst_gpio = parse_env_int("NFC_SPI_RST_GPIO", -1);
                const int bss_gpio = parse_env_int("NFC_SPI_BSS_GPIO", -1);
                if (bss_gpio >= 0) {
                    (void)gpio_set_output_value_sysfs(bss_gpio, bss_inactive_level_);
                    bss_sysfs_gpio_ = bss_gpio;
                }
                if (rst_gpio >= 0) {
                    rst_sysfs_gpio_ = rst_gpio;
                    (void)gpio_set_output_value_sysfs(rst_gpio, rst_active_level);
                    if (pulse_reset) {
                        sleep_ms(5);
                        (void)gpio_set_output_value_sysfs(rst_gpio, rst_active_level ? 0 : 1);
                        sleep_ms(20);
                    }
                    rst_line_unavailable_ = false;
                }
                return;
            }
        }

        rst_line_unavailable_ = false;
        (void)gpio_set_output_line_value(rst_line_fd_, rst_active_level);
        rst_sysfs_gpio_ = -1;
        if (pulse_reset) {
            sleep_ms(5);
            (void)gpio_set_output_line_value(rst_line_fd_, rst_active_level ? 0 : 1);
            sleep_ms(20);
        }
    }

    void prepare_spi_hat_power_gate()
    {
        // Keep ST25R in reset and force bus-select lines before enabling rails,
        // then release reset after power is stable.
        configure_st25r_control_lines(false);
        power_gate_enabled_ = enable_5vout_before_spi_power_gate(false);
        pi4io_status_ = try_init_pi4io_power_gate();
        if (pi4io_status_ != "ok" && parse_env_int("NFC_SPI_5VOUT_AUTO_FLIP", 1) != 0) {
            if (enable_5vout_before_spi_power_gate(true)) {
                sleep_ms(20);
                const std::string flipped_status = try_init_pi4io_power_gate();
                if (flipped_status == "ok") {
                    pi4io_status_ = "ok(auto-flip)";
                    power_gate_enabled_ = true;
                } else {
                    // Keep deterministic behavior: if flipped polarity did not help,
                    // restore the original polarity before continuing probe.
                    power_gate_enabled_ = enable_5vout_before_spi_power_gate(false);
                }
            }
        }
        sleep_ms(10);
        configure_st25r_control_lines(true);
    }

    bool spi_transfer(const uint8_t *tx, uint8_t *rx, size_t len)
    {
        if (fd_ < 0 || !tx || !rx || len == 0) return false;
        if (!wait_bss_ready_before_transfer()) {
            NfcHexLog::get().log_event("SPI", "transfer skipped: BSS not ready");
            return false;
        }

        bool bss_selected = false;
        auto release_bss = [&]() {
            if (!bss_selected) return;
            if (!set_bss_line_level(bss_inactive_level_)) {
                NfcHexLog::get().log_event("SPI", "BSS release failed");
            }
            bss_selected = false;
            if (bss_release_settle_us_ > 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(bss_release_settle_us_));
            }
        };

        if (bss_manual_select_) {
            if (!set_bss_line_level(bss_active_level_)) {
                NfcHexLog::get().log_event("SPI", "transfer skipped: BSS assert failed");
                return false;
            }
            bss_selected = true;
            if (bss_select_settle_us_ > 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(bss_select_settle_us_));
            }
        }

        struct spi_ioc_transfer tr{};
        tr.tx_buf = (unsigned long)tx;
        tr.rx_buf = (unsigned long)rx;
        tr.len    = static_cast<uint32_t>(len);
        tr.speed_hz = spi_speed_hz_;
        tr.bits_per_word = 8;
        tr.delay_usecs = 0;
        const bool ok = (::ioctl(fd_, SPI_IOC_MESSAGE(1), &tr) >= 0);
        release_bss();
        if (ok) {
            NfcHexLog::get().log_tx("SPI", tx, len);
            NfcHexLog::get().log_rx("SPI", rx, len);
        } else {
            NfcHexLog::get().log_tx("SPI", tx, len);
            NfcHexLog::get().log_event("SPI", "transfer ioctl failed");
        }
        return ok;
    }

    int sample_rst_line_level() const
    {
        int value = -1;
        if (rst_line_fd_ >= 0 && gpio_get_input_line_value(rst_line_fd_, &value)) return value;
        if (gpio_get_input_value_sysfs(rst_sysfs_gpio_, &value)) return value;
        return -1;
    }

    int sample_bss_line_level() const
    {
        int value = -1;
        if (bss_line_fd_ >= 0 && gpio_get_input_line_value(bss_line_fd_, &value)) return value;
        if (gpio_get_input_value_sysfs(bss_sysfs_gpio_, &value)) return value;
        return -1;
    }

    int sample_irq_line_level() const
    {
        int value = -1;
        if (irq_line_fd_ >= 0 && gpio_get_input_line_value(irq_line_fd_, &value)) return value;
        if (gpio_get_input_value_sysfs(irq_sysfs_gpio_, &value)) return value;
        return -1;
    }

    bool wait_bss_ready_before_transfer()
    {
        if (!bss_wait_before_transfer_) return true;
        if (bss_xfer_ready_timeout_ms_ <= 0) return true;

        auto read_bss_level = [this](int *value) {
            if (!value) return false;
            if (bss_line_fd_ >= 0 && gpio_get_input_line_value(bss_line_fd_, value)) return true;
            if (gpio_get_input_value_sysfs(bss_sysfs_gpio_, value)) return true;
            return false;
        };

        int value = -1;
        if (!read_bss_level(&value)) return true;
        if (value == bss_ready_level_) return true;

        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(bss_xfer_ready_timeout_ms_);
        while (std::chrono::steady_clock::now() < deadline) {
            sleep_ms(1);
            if (!read_bss_level(&value)) return true;
            if (value == bss_ready_level_) return true;
        }
        return false;
    }

    bool set_bss_line_level(int level)
    {
        const int value = level ? 1 : 0;
        if (bss_line_fd_ >= 0) return gpio_set_output_line_value(bss_line_fd_, value);
        if (bss_sysfs_gpio_ >= 0) return gpio_set_output_value_sysfs(bss_sysfs_gpio_, value);
        return false;
    }

    bool detect_spi_echo_path()
    {
        const std::array<std::array<uint8_t, 8>, 3> patterns = {{
            {{0xA5, 0x5A, 0x3C, 0xC3, 0xF0, 0x0F, 0x96, 0x69}},
            {{0x11, 0x22, 0x44, 0x88, 0x77, 0xEE, 0x33, 0xCC}},
            {{0x00, 0xFF, 0x12, 0xED, 0x34, 0xCB, 0x56, 0xA9}},
        }};
        int echo_hits = 0;
        for (const auto &txp : patterns) {
            std::array<uint8_t, 8> rxp{};
            if (!spi_transfer(txp.data(), rxp.data(), txp.size())) continue;
            int eq = 0;
            for (size_t i = 0; i < txp.size(); ++i) {
                if (txp[i] == rxp[i]) ++eq;
            }
            if (eq >= 6) ++echo_hits;
        }
        return echo_hits >= 2;
    }

    bool write_reg(uint8_t addr, uint8_t value)
    {
        uint8_t tx[2] = { static_cast<uint8_t>(ST25R_SPI_CMD_WRITE_REG | (addr & 0x3F)), value };
        uint8_t rx[2] = {0, 0};
        return spi_transfer(tx, rx, 2);
    }

    bool read_reg(uint8_t addr, uint8_t *value)
    {
        if (read_reg_with_dummy_) {
            uint8_t tx[3] = { static_cast<uint8_t>(ST25R_SPI_CMD_READ_REG | (addr & 0x3F)), 0x00, 0x00 };
            uint8_t rx[3] = {0, 0, 0};
            if (!spi_transfer(tx, rx, 3)) return false;
            if (value) *value = rx[2];
            return true;
        }

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

    bool set_rf_field(bool enabled)
    {
        // ST25R3916 controls the RF field through OP_CONTROL; there is no
        // RF_TRANSMITTER_ON/OFF direct command in the Flipper/ST command table.
        return write_reg(st25r_reg::OP_CONTROL, enabled ? 0xC8 : 0x80);
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
