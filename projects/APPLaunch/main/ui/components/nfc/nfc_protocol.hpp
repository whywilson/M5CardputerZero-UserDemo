#pragma once

#include "nfc_transport.hpp"

#include <cstdio>
#include <cstdint>
#include <optional>
#include <sstream>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace nfc_app {

struct Pn532FirmwareInfo {
    std::string chip = "";
    std::string version = "";
};

class Pn532FrameCodec {
public:
    static std::vector<uint8_t> build_command(uint8_t command, const std::vector<uint8_t> &payload = {})
    {
        std::vector<uint8_t> data;
        data.push_back(0xD4);
        data.push_back(command);
        data.insert(data.end(), payload.begin(), payload.end());

        const uint8_t len = static_cast<uint8_t>(data.size());
        const uint8_t lcs = static_cast<uint8_t>(0x100 - len);
        uint8_t sum = 0;
        for (uint8_t byte : data) sum = static_cast<uint8_t>(sum + byte);
        const uint8_t dcs = static_cast<uint8_t>(0x100 - sum);

        std::vector<uint8_t> frame = {0x00, 0x00, 0xFF, len, lcs};
        frame.insert(frame.end(), data.begin(), data.end());
        frame.push_back(dcs);
        frame.push_back(0x00);
        return frame;
    }

    static bool is_ack(const std::vector<uint8_t> &bytes)
    {
        static const uint8_t ack[] = {0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00};
        if (bytes.size() < sizeof(ack)) return false;
        for (size_t i = 0; i < bytes.size() - sizeof(ack) + 1; ++i) {
            bool same = true;
            for (size_t j = 0; j < sizeof(ack); ++j) {
                if (bytes[i + j] != ack[j]) {
                    same = false;
                    break;
                }
            }
            if (same) return true;
        }
        return false;
    }

    static bool parse_first_frame(const std::vector<uint8_t> &bytes, std::vector<uint8_t> *data_out)
    {
        for (size_t i = 0; i + 7 < bytes.size(); ++i) {
            if (bytes[i] != 0x00 || bytes[i + 1] != 0x00 || bytes[i + 2] != 0xFF) continue;

            const uint8_t len = bytes[i + 3];
            const uint8_t lcs = bytes[i + 4];
            if (static_cast<uint8_t>(len + lcs) != 0x00) continue;
            if (len == 0) continue;
            if (i + 5 + len + 2 > bytes.size()) continue;

            const size_t data_start = i + 5;
            const size_t data_end = data_start + len;
            uint8_t sum = 0;
            for (size_t cursor = data_start; cursor < data_end; ++cursor) {
                sum = static_cast<uint8_t>(sum + bytes[cursor]);
            }
            const uint8_t dcs = bytes[data_end];
            if (static_cast<uint8_t>(sum + dcs) != 0x00) continue;

            if (data_out) {
                data_out->assign(bytes.begin() + static_cast<long>(data_start), bytes.begin() + static_cast<long>(data_end));
            }
            return true;
        }
        return false;
    }
};

class Pn532KillerClient {
public:
    explicit Pn532KillerClient(INfcTransport *transport) : transport_(transport) {}

    // Send HSU wakeup preamble and drain any stale bytes.
    // Must be called once after opening the serial port.
    void send_wakeup()
    {
        static const uint8_t wake[] = {
            0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        transport_->write_bytes(wake, sizeof(wake), nullptr);
        // Drain any pending RX bytes and wait ~15 ms for the chip to wake.
        uint8_t drain[64];
        transport_->read_bytes(drain, sizeof(drain), 15, nullptr);
    }

    // SAMConfiguration – put PN532 into Normal mode (required before NFC ops).
    bool sam_configuration(std::string *error)
    {
        // Mode 0x01 = Normal, Timeout 0x00, IRQ 0x01
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x14, {0x01, 0x00, 0x01});
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) return false;
        std::vector<uint8_t> rx;
        collect_response(&rx, nullptr); // response is 0xD5 0x15, ignore errors
        return true;
    }

    // SetWorkMode for PN532Killer (0xAC): mode=1 READER, type=1 MFC, index=0.
    bool set_work_mode(uint8_t mode, uint8_t type, uint8_t index, std::string *error)
    {
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0xAC, {mode, type, index});
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) return false;
        std::vector<uint8_t> rx;
        collect_response(&rx, nullptr);
        return true;
    }

    std::optional<Pn532FirmwareInfo> query_firmware(std::string *error)
    {
        if (!transport_ || !transport_->is_open()) {
            if (error) *error = "transport not connected";
            return std::nullopt;
        }

        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x02);
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) {
            return std::nullopt;
        }

        std::vector<uint8_t> rx;
        if (!collect_response(&rx, error)) {
            return std::nullopt;
        }

        std::vector<uint8_t> data;
        if (!Pn532FrameCodec::parse_first_frame(rx, &data)) {
            if (error) *error = "no valid PN532 frame";
            return std::nullopt;
        }

        if (data.size() < 6 || data[0] != 0xD5 || data[1] != 0x03) {
            if (error) *error = "unexpected firmware response";
            return std::nullopt;
        }

        Pn532FirmwareInfo info;
        info.chip = (data[2] == 0x32) ? "PN532" : "PN53x";
        char version[32];
        std::snprintf(version, sizeof(version), "v%d.%d", data[3], data[4]);
        info.version = version;
        if (error) error->clear();
        return info;
    }

    // Detect PN532Killer using checkPn532Killer vendor command (0xAA).
    // PN532Killer responds with TFI=0xD5, cmd=0xAB, status 0x00.
    // Plain PN532 returns an error frame (cmd=0x7F) or times out.
    bool probe_pn532killer(std::string *error)
    {
        if (!transport_ || !transport_->is_open()) {
            if (error) *error = "transport not connected";
            return false;
        }

        // Pn532KillerCommand.checkPn532Killer = 0xAA
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0xAA, {});
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) {
            return false;
        }

        std::vector<uint8_t> rx;
        uint8_t buf[64];
        rx.clear();
        for (int i = 0; i < 5; ++i) {
            ssize_t got = transport_->read_bytes(buf, sizeof(buf), 100, error);
            if (got > 0) rx.insert(rx.end(), buf, buf + got);
            if (Pn532FrameCodec::parse_first_frame(rx, nullptr)) break;
        }
        if (rx.empty()) return false;

        std::vector<uint8_t> data;
        if (!Pn532FrameCodec::parse_first_frame(rx, &data)) return false;
        if (data.size() < 2) return false;
        if (data[0] != 0xD5) return false;
        // Error frame from plain PN532: cmd byte 0x7F
        if (data[1] == 0x7F) return false;
        // PN532Killer responds with cmd = 0xAB (0xAA + 1)
        return (data[1] == 0xAB);
    }

    // Convenience: probe device kind in one call.
    // Returns DeviceKind and fills firmware string.
    // Flow: wakeup → GetFirmwareVersion → checkPn532Killer
    //        → for PN532Killer: SetWorkMode(READER)
    //        → for plain PN532: SAMConfiguration(Normal)
    DeviceKind detect_device(std::string *firmware_out, std::string *error)
    {
        if (firmware_out) firmware_out->clear();

        // Step 1: HSU wakeup preamble (required for both PN532 and PN532Killer)
        send_wakeup();

        // Step 2: query firmware version
        auto fw = query_firmware(error);
        if (!fw) return DeviceKind::Unknown;

        const std::string fw_str = fw->chip + " " + fw->version;
        if (firmware_out) *firmware_out = fw_str;

        // Step 3: distinguish PN532Killer from plain PN532
        if (probe_pn532killer(nullptr)) {
            // Step 4a: set PN532Killer to READER mode (type=MFC=1, slot=0)
            set_work_mode(0x01, 0x01, 0x00, nullptr);
            return DeviceKind::PN532Killer;
        }

        // Step 4b: configure plain PN532 into Normal mode
        sam_configuration(nullptr);
        return DeviceKind::PN532;
    }

    bool in_list_passive_target_iso14443a(TagInfo *tag, std::string *error)
    {
        if (!tag) {
            if (error) *error = "missing tag output";
            return false;
        }

        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x4A, {0x01, 0x00});
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) {
            return false;
        }

        std::vector<uint8_t> rx;
        if (!collect_response(&rx, error)) {
            return false;
        }

        std::vector<uint8_t> data;
        if (!Pn532FrameCodec::parse_first_frame(rx, &data)) {
            if (error) *error = "no card response frame";
            return false;
        }

        if (data.size() < 9 || data[0] != 0xD5 || data[1] != 0x4B) {
            if (error) *error = "unexpected card response";
            return false;
        }
        if (data[2] == 0x00) {
            if (error) *error = "no passive target found";
            return false;
        }

        const uint8_t atqa1 = data[4];
        const uint8_t atqa2 = data[5];
        const uint8_t sak = data[6];
        const uint8_t uid_len = data[7];
        if (data.size() < static_cast<size_t>(8 + uid_len)) {
            if (error) *error = "truncated UID data";
            return false;
        }

        tag->protocol = ProtocolKind::Iso14443A;
        tag->uid = to_hex(data.data() + 8, uid_len);
        tag->tag_type = detect_mifare_classic(sak, uid_len);
        if (tag->tag_type.find("Mifare Classic") != std::string::npos) {
            tag->protocol = ProtocolKind::MifareClassic;
        }
        tag->identity_fields["atqa"] = byte_hex(atqa1) + byte_hex(atqa2);
        tag->identity_fields["sak"] = byte_hex(sak);
        tag->identity_fields["uid_len"] = std::to_string(uid_len);
        tag->raw_data.push_back(bytes_to_hex(data));
        if (error) error->clear();
        return true;
    }

private:
    static std::string byte_hex(uint8_t value)
    {
        char buffer[4];
        std::snprintf(buffer, sizeof(buffer), "%02X", value);
        return buffer;
    }

    static std::string to_hex(const uint8_t *data, size_t size)
    {
        std::string out;
        for (size_t i = 0; i < size; ++i) out += byte_hex(data[i]);
        return out;
    }

    static std::string bytes_to_hex(const std::vector<uint8_t> &data)
    {
        return to_hex(data.data(), data.size());
    }

    static std::string detect_mifare_classic(uint8_t sak, uint8_t uid_len)
    {
        (void)uid_len;
        switch (sak) {
        case 0x09: return "Mifare Classic Mini";
        case 0x08: return "Mifare Classic 1K";
        case 0x18: return "Mifare Classic 4K";
        default: return "ISO14443A Tag";
        }
    }

    bool collect_response(std::vector<uint8_t> *rx, std::string *error)
    {
        rx->clear();
        uint8_t buffer[128];
        for (int attempt = 0; attempt < 6; ++attempt) {
            ssize_t got = transport_->read_bytes(buffer, sizeof(buffer), 120, error);
            if (got < 0) return false;
            if (got == 0) continue;
            rx->insert(rx->end(), buffer, buffer + got);
            if (Pn532FrameCodec::parse_first_frame(*rx, nullptr)) {
                return true;
            }
        }
        if (error) *error = "timeout waiting for PN532 response";
        return false;
    }

    INfcTransport *transport_ = nullptr;
};

} // namespace nfc_app