#pragma once

#include "nfc_protocol.hpp"
#include "nfc_storage.hpp"

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>

namespace nfc_app {

struct ConnectionState {
    bool connected = false;
    TransportEndpoint endpoint;
    std::string status = "Disconnected";
    std::string detail = "Select endpoint";
    bool pn532_ready = false;
    DeviceKind device_kind = DeviceKind::Unknown;
};

struct ScanState {
    bool running = false;
    bool has_result = false;
    SavedRecord last_record;
    std::string status = "Idle";
    std::string error;
};

class NfcDeviceService {
public:
    NfcDeviceService()
    {
        refresh_endpoints();
        emulator_slots_by_protocol_ = storage_.load_emulator_slots_by_protocol();
        seed_mock_saved_records();
    }

    ~NfcDeviceService()
    {
        if (scan_thread_.joinable()) scan_thread_.join();
        if (probe_thread_.joinable()) probe_thread_.join();
        disconnect();
    }

    void refresh_endpoints()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        endpoints_ = NfcTransportFactory::enumerate_endpoints();
        if (selected_endpoint_ >= static_cast<int>(endpoints_.size())) selected_endpoint_ = 0;
    }

    // ── Device probe ─────────────────────────────────────────────────────────

    // Start background probe of all non-mock endpoints.
    // Results become available via probe_results().
    void start_probe_all()
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (probe_running_) return;
            probe_running_ = true;
            // Initialise result list with "probing" placeholders
            probe_results_.clear();
            for (const auto &ep : endpoints_) {
                if (ep.kind == TransportKind::Mock) continue;
                DeviceProbeResult r;
                r.path      = ep.path;
                r.transport = ep.kind;
                r.probing   = true;
                probe_results_.push_back(r);
            }
            if (probe_results_.empty()) {
                probe_running_ = false;
                return;
            }
        }
        if (probe_thread_.joinable()) probe_thread_.join();
        probe_thread_ = std::thread([this]() { perform_probe_all(); });
    }

    bool probe_running() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return probe_running_;
    }

    std::vector<DeviceProbeResult> probe_results() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return probe_results_;
    }

    // ── UART configuration ───────────────────────────────────────────────────

    UartConfig uart_config() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return uart_config_;
    }

    void set_uart_config(const UartConfig &cfg)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        uart_config_ = cfg;
        // Update any matching UART endpoint's baud rate
        for (auto &ep : endpoints_) {
            if (ep.kind == TransportKind::UartSerial && ep.path == cfg.device_path) {
                ep.baud_rate = cfg.baud_rate;
            }
        }
    }

    // Returns UART endpoints only (no mock, no USB)
    std::vector<TransportEndpoint> uart_endpoints() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<TransportEndpoint> out;
        for (const auto &ep : endpoints_) {
            if (ep.kind == TransportKind::UartSerial) out.push_back(ep);
        }
        return out;
    }

    // Pin reference table for common M5CardputerZero UART ports
    // Returns {tx_pin, rx_pin} or {-1,-1} if unknown
    static std::pair<int,int> uart_pin_hint(const std::string &dev_path)
    {
        // AX620Q / CardputerZero UART mappings (from device tree reference)
        if (dev_path.find("ttyTHS0") != std::string::npos) return {14, 15};
        if (dev_path.find("ttyTHS1") != std::string::npos) return {16, 17};
        if (dev_path.find("ttyTHS2") != std::string::npos) return {18, 19};
        if (dev_path.find("ttyS0") != std::string::npos)   return {14, 15};
        if (dev_path.find("ttyAMA0") != std::string::npos) return {8, 9};   // RPi-style
        if (dev_path.find("ttyAMA1") != std::string::npos) return {0, 1};
        return {-1, -1};
    }

    std::vector<TransportEndpoint> endpoints() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return endpoints_;
    }

    TransportEndpoint current_endpoint() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (endpoints_.empty()) return TransportEndpoint{};
        return endpoints_[selected_endpoint_];
    }

    void cycle_endpoint(int delta)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (endpoints_.empty()) return;
        const int count = static_cast<int>(endpoints_.size());
        selected_endpoint_ = (selected_endpoint_ + delta + count) % count;
    }

    // Toggle between USB and UART endpoint groups, prefer configured UART path,
    // then auto-connect and probe the selected device.
    bool cycle_transport_mode(std::string *status = nullptr)
    {
        refresh_endpoints();

        TransportEndpoint selected;
        bool selected_ok = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<TransportKind> available;
            bool has_usb = false;
            bool has_uart = false;
            for (const auto &ep : endpoints_) {
                if (ep.kind == TransportKind::UsbSerial) has_usb = true;
                if (ep.kind == TransportKind::UartSerial) has_uart = true;
            }
            if (has_usb) available.push_back(TransportKind::UsbSerial);
            if (has_uart) available.push_back(TransportKind::UartSerial);
            if (available.empty()) {
                if (status) *status = "No USB/UART device found";
                return false;
            }

            TransportKind current_kind = TransportKind::Mock;
            if (!endpoints_.empty() && selected_endpoint_ < static_cast<int>(endpoints_.size())) {
                current_kind = endpoints_[selected_endpoint_].kind;
            }

            size_t next_kind_idx = 0;
            for (size_t i = 0; i < available.size(); ++i) {
                if (available[i] == current_kind) {
                    next_kind_idx = (i + 1) % available.size();
                    break;
                }
            }
            const TransportKind target_kind = available[next_kind_idx];

            int target_index = -1;
            if (target_kind == TransportKind::UartSerial && !uart_config_.device_path.empty()) {
                for (size_t i = 0; i < endpoints_.size(); ++i) {
                    if (endpoints_[i].kind == target_kind && endpoints_[i].path == uart_config_.device_path) {
                        target_index = static_cast<int>(i);
                        break;
                    }
                }
            }
            if (target_index < 0) {
                for (size_t i = 0; i < endpoints_.size(); ++i) {
                    if (endpoints_[i].kind == target_kind) {
                        target_index = static_cast<int>(i);
                        break;
                    }
                }
            }
            if (target_index < 0) {
                if (status) *status = "No endpoint for selected transport";
                return false;
            }

            if (transport_) transport_->close();
            transport_.reset();
            connection_ = ConnectionState{};
            selected_endpoint_ = target_index;
            selected = endpoints_[selected_endpoint_];
            selected_ok = true;
        }

        if (!selected_ok) return false;

        if (!connect_current()) {
            if (status) *status = std::string(to_string(selected.kind)) + " selected, connect failed";
            return false;
        }

        const auto state = connection_state();
        if (status) {
            *status = std::string(to_string(selected.kind)) + " -> " +
                      (state.pn532_ready ? state.detail : state.status);
        }
        return true;
    }

    bool connect_current()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (endpoints_.empty()) return false;

        transport_ = NfcTransportFactory::create(endpoints_[selected_endpoint_]);
        std::string error;
        if (!transport_->open(endpoints_[selected_endpoint_], &error)) {
            connection_.connected = false;
            connection_.endpoint = endpoints_[selected_endpoint_];
            connection_.status = "Connect failed";
            connection_.detail = error;
            connection_.pn532_ready = false;
            connection_.device_kind = DeviceKind::NotConnected;
            transport_.reset();
            return false;
        }

        connection_.connected = true;
        connection_.endpoint = endpoints_[selected_endpoint_];
        connection_.status = std::string("Connected ") + to_string(connection_.endpoint.kind);
        connection_.detail = connection_.endpoint.path;
        connection_.pn532_ready = false;
        connection_.device_kind = DeviceKind::Unknown;

        if (connection_.endpoint.kind != TransportKind::Mock) {
            Pn532KillerClient client(transport_.get());
            std::string probe_error;
            std::string firmware;
            const auto kind = client.detect_device(&firmware, &probe_error);
            connection_.device_kind = kind;
            if (kind == DeviceKind::PN532Killer || kind == DeviceKind::PN532) {
                connection_.pn532_ready = true;
                connection_.status = std::string("Connected ") + to_string(kind);
                connection_.detail = firmware + " @ " + connection_.endpoint.path;
            } else {
                connection_.detail = std::string("Raw serial only: ") + probe_error;
            }
        } else {
            connection_.pn532_ready = true;
            connection_.device_kind = DeviceKind::PN532Killer;
            connection_.detail = "Built-in mock transport";
        }
        return true;
    }

    void disconnect()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (transport_) transport_->close();
        transport_.reset();
        connection_ = ConnectionState{};
    }

    ConnectionState connection_state() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return connection_;
    }

    ScanState scan_state() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return scan_;
    }

    bool start_scan()
    {
        if (scan_thread_.joinable()) scan_thread_.join();

        std::lock_guard<std::mutex> lock(mutex_);
        if (!transport_ || !transport_->is_open()) {
            scan_.running = false;
            scan_.status = "No device";
            scan_.error = "Connect USB/UART or use mock first";
            return false;
        }
        if (scan_.running) return false;

        scan_.running = true;
        scan_.has_result = false;
        scan_.status = "Scanning";
        scan_.error.clear();

        scan_thread_ = std::thread([this]() { perform_scan(); });
        return true;
    }

    bool connect_and_scan(std::string *status = nullptr)
    {
        const auto state = connection_state();
        if (!state.connected) {
            if (!connect_current()) {
                if (status) *status = "Connect failed";
                return false;
            }
        }

        if (!start_scan()) {
            const auto scan = scan_state();
            if (status) *status = scan.error.empty() ? scan.status : scan.error;
            return false;
        }

        if (status) *status = "Scanning card...";
        return true;
    }

    bool save_last_scan(std::string *error = nullptr)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!scan_.has_result) {
            if (error) *error = "No scan result to save";
            return false;
        }
        return storage_.save_record(scan_.last_record, error);
    }

    std::vector<MifareKeyRecord> list_mifare_keys() const
    {
        return storage_.load_mifare_keys();
    }

    bool upsert_mifare_key(int index, const MifareKeyRecord &record, std::string *err = nullptr)
    {
        auto keys = storage_.load_mifare_keys();
        MifareKeyRecord normalized = record;
        normalized.key_hex = normalize_mifare_key_hex(record.key_hex);
        if (normalized.key_hex.size() != 12) {
            if (err) *err = "Key must be 12 hex chars";
            return false;
        }
        if (normalized.label.empty()) {
            normalized.label = std::string("Key ") + normalized.key_hex.substr(8, 4);
        }
        if (normalized.created_at.empty()) normalized.created_at = iso8601_now();
        if (normalized.source.empty()) normalized.source = "manual";

        if (index < 0 || index >= static_cast<int>(keys.size())) keys.push_back(normalized);
        else keys[index] = normalized;

        if (!storage_.save_mifare_keys(keys)) {
            if (err) *err = "Failed to save keys";
            return false;
        }
        return true;
    }

    bool delete_mifare_key(int index, std::string *err = nullptr)
    {
        auto keys = storage_.load_mifare_keys();
        if (index < 0 || index >= static_cast<int>(keys.size())) {
            if (err) *err = "Key not found";
            return false;
        }
        keys.erase(keys.begin() + index);
        if (!storage_.save_mifare_keys(keys)) {
            if (err) *err = "Failed to save keys";
            return false;
        }
        return true;
    }

    bool toggle_mifare_key_enabled(int index, std::string *err = nullptr)
    {
        auto keys = storage_.load_mifare_keys();
        if (index < 0 || index >= static_cast<int>(keys.size())) {
            if (err) *err = "Key not found";
            return false;
        }
        keys[index].enabled = !keys[index].enabled;
        if (!storage_.save_mifare_keys(keys)) {
            if (err) *err = "Failed to save keys";
            return false;
        }
        return true;
    }

    std::vector<SavedRecord> list_saved_records() const
    {
        auto records = storage_.list_records();
        if (records.empty()) return mock_saved_records_;
        return records;
    }

    std::vector<EmulatorSlotRecord> emulator_slots() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return protocol_slots_padded_locked(selected_emulator_protocol_);
    }

    std::vector<EmulatorSlotRecord> emulator_slots_padded(ProtocolKind protocol) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return protocol_slots_padded_locked(protocol);
    }

    void cycle_slot(int delta)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto &selected_slot = selected_slot_by_protocol_[selected_emulator_protocol_];
        selected_slot = (selected_slot + delta + 8) % 8;
    }

    int selected_slot_index() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = selected_slot_by_protocol_.find(selected_emulator_protocol_);
        return it == selected_slot_by_protocol_.end() ? 0 : it->second;
    }

    int selected_slot_index_for_protocol(ProtocolKind protocol) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = selected_slot_by_protocol_.find(protocol);
        return it == selected_slot_by_protocol_.end() ? 0 : it->second;
    }

    ProtocolKind current_emulator_protocol() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return selected_emulator_protocol_;
    }

    void toggle_slot_protocol()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (selected_emulator_protocol_ == ProtocolKind::Iso14443A) selected_emulator_protocol_ = ProtocolKind::Iso14443B;
        else if (selected_emulator_protocol_ == ProtocolKind::Iso14443B) selected_emulator_protocol_ = ProtocolKind::Iso15693;
        else if (selected_emulator_protocol_ == ProtocolKind::Iso15693) selected_emulator_protocol_ = ProtocolKind::MifareClassic;
        else selected_emulator_protocol_ = ProtocolKind::Iso14443A;
    }

    bool emulation_allowed(std::string *reason = nullptr) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (connection_.endpoint.kind == TransportKind::Mock) return true;
        if (!connection_.connected || connection_.device_kind != DeviceKind::PN532Killer) {
            if (reason) *reason = "PN532Killer required for EMU";
            return false;
        }
        return true;
    }

    void set_default_slot()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto &slots = emulator_slots_by_protocol_[selected_emulator_protocol_];
        ensure_protocol_slots_locked(selected_emulator_protocol_);
        const int selected_slot = selected_slot_by_protocol_[selected_emulator_protocol_];
        for (size_t i = 0; i < slots.size(); ++i) {
            slots[i].default_slot = (static_cast<int>(i) == selected_slot);
        }
        save_emulator_slots_locked();
    }

    bool upload_record_to_slot(const SavedRecord &record)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto &slot = current_slot_for_protocol_locked(record.tag.protocol, selected_slot_by_protocol_[record.tag.protocol]);
        slot.payload_record_id = record.meta.record_id;
        slot.protocol = record.tag.protocol;
        slot.raw_data = record.tag.raw_data;
        return save_emulator_slots_locked();
    }

    // Upload a record to a specific slot index (0-7); auto-expands slots as needed
    bool upload_record_to_slot_n(const SavedRecord &record, int slot_n)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto &slot = current_slot_for_protocol_locked(record.tag.protocol, slot_n);
        selected_slot_by_protocol_[record.tag.protocol] = slot_n;
        slot.payload_record_id = record.meta.record_id;
        slot.protocol = record.tag.protocol;
        slot.raw_data = record.tag.raw_data;
        return save_emulator_slots_locked();
    }

    // Returns exactly 8 slots (padded with empty ones if fewer exist)
    std::vector<EmulatorSlotRecord> emulator_slots_padded() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return protocol_slots_padded_locked(selected_emulator_protocol_);
    }

    bool rename_saved_record(const std::string &record_id, const std::string &new_name, std::string *err = nullptr)
    {
        for (auto &mr : mock_saved_records_) {
            if (mr.meta.record_id == record_id) {
                mr.meta.display_name = new_name;
                return true;
            }
        }
        SavedRecord r;
        if (!storage_.load_record_by_id(record_id, &r)) {
            if (err) *err = "Record not found";
            return false;
        }
        r.meta.display_name = new_name;
        return storage_.save_record(r, err);
    }

    bool update_record_hex(const std::string &record_id, const std::vector<std::string> &raw_data, std::string *err = nullptr)
    {
        for (auto &mr : mock_saved_records_) {
            if (mr.meta.record_id == record_id) {
                mr.tag.raw_data = raw_data;
                return true;
            }
        }
        SavedRecord r;
        if (!storage_.load_record_by_id(record_id, &r)) {
            if (err) *err = "Record not found";
            return false;
        }
        r.tag.raw_data = raw_data;
        return storage_.save_record(r, err);
    }

    bool download_slot_to_saved()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto &slot = current_slot_locked();
        SavedRecord record;
        record.meta.created_at = iso8601_now();
        record.meta.record_id = "emu_slot_" + std::to_string(slot.slot_index) + "_" + record.meta.created_at;
        record.meta.display_name = "Slot " + std::to_string(slot.slot_index) + " Snapshot";
        record.meta.source = "emulator_slot";
        record.meta.transport = TransportKind::Mock;
        record.meta.transport_path = "slot://" + std::to_string(slot.slot_index);
        record.tag.protocol = slot.protocol;
        record.tag.tag_type = "Emulator Slot";
        record.tag.uid = slot.payload_record_id;
        record.tag.raw_data = slot.raw_data;
        record.emulator_slot = slot;
        return storage_.save_record(record, nullptr);
    }

private:
    static std::string normalize_mifare_key_hex(const std::string &value)
    {
        std::string out;
        out.reserve(value.size());
        for (char ch : value) {
            if (std::isxdigit(static_cast<unsigned char>(ch))) {
                out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
            }
        }
        return out;
    }

    void perform_scan()
    {
        SavedRecord record;
        std::string error;

        ConnectionState connection_copy;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            connection_copy = connection_;
        }

        bool success = false;
        if (connection_copy.endpoint.kind == TransportKind::Mock) {
            record = build_mock_record(connection_copy.endpoint);
            success = true;
        } else {
            std::unique_lock<std::mutex> lock(mutex_);
            Pn532KillerClient client(transport_.get());
            TagInfo tag;
            const bool real_ok = client.in_list_passive_target_iso14443a(&tag, &error);
            lock.unlock();
            if (real_ok) {
                record = make_record_from_tag(tag, connection_copy.endpoint, false, "pn532_scan");
                if (record.tag.protocol == ProtocolKind::MifareClassic) {
                    record.mifare_dump = MifareClassicDump{};
                    record.mifare_dump->sector_count = (record.tag.tag_type.find("4K") != std::string::npos) ? 40 : 16;
                    record.mifare_dump->block_count = record.mifare_dump->sector_count * 4;
                    record.mifare_dump->attack.status = AttackStatus::Pending;
                    record.mifare_dump->attack.reason = "v1 reserved task pipeline";
                }
                success = true;
            } else {
                record = build_mock_record(connection_copy.endpoint);
                record.meta.source = "mock_fallback_after_probe";
                record.meta.notes = error;
                success = true;
            }
        }

        std::lock_guard<std::mutex> lock(mutex_);
        scan_.running = false;
        scan_.has_result = success;
        scan_.last_record = record;
        scan_.status = success ? "Scan ready" : "Scan failed";
        scan_.error = success ? record.meta.notes : error;
    }

    SavedRecord build_mock_record(const TransportEndpoint &endpoint) const
    {
        // 轮转三种卡型，让模拟器看起来每次扫描都有变化
        const int kind = scan_mock_counter_++ % 3;

        TagInfo tag;
        if (kind == 0) {
            tag.protocol = ProtocolKind::MifareClassic;
            tag.tag_type = "Mifare Classic 1K";
            tag.uid = "DE AD BE EF";
            tag.identity_fields["atqa"] = "0004";
            tag.identity_fields["sak"]  = "08";
            tag.identity_fields["capacity"] = "1K";
            tag.raw_data = {
                "Block0:  DE AD BE EF 21 08 04 00 46 49 4C 4C 45 44 4B 45",
                "Block1:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "Block3:  FF FF FF FF FF FF FF 07 80 69 FF FF FF FF FF FF",
            };
        } else if (kind == 1) {
            tag.protocol = ProtocolKind::Iso14443A;
            tag.tag_type = "NFC-A Type 4 (NTAG213)";
            tag.uid = "04 B3 7C 2A";
            tag.identity_fields["atqa"] = "0044";
            tag.identity_fields["sak"]  = "00";
            tag.identity_fields["type"] = "NTAG213 144B";
            tag.raw_data = {
                "UID: 04 B3 7C 2A",
                "CC: E1 10 12 00  (NDEF 144B)",
                "NDEF: https://m5stack.com/products/cardputer",
            };
        } else {
            tag.protocol = ProtocolKind::Iso15693;
            tag.tag_type = "ISO 15693 (iCODE SLI)";
            tag.uid = "E0 04 01 00 5A 4B 3C 2D";
            tag.identity_fields["dsfid"] = "00";
            tag.identity_fields["afi"]   = "00";
            tag.identity_fields["blocks"] = "32 x 4B";
            tag.raw_data = {
                "UID(rev): E0 04 01 00 5A 4B 3C 2D",
                "DSFID:00  AFI:00  Blocks:32x4B",
                "Block0: 48 65 6C 6C  ('Hell')",
            };
        }

        SavedRecord record = make_record_from_tag(tag, endpoint, true, "mock_scan");
        if (kind == 0) {
            MifareClassicDump dump;
            dump.sector_count = 16;
            dump.block_count  = 64;
            dump.attack.method = AttackMethod::DefaultKeys;
            dump.attack.status = AttackStatus::Pending;
            dump.attack.reason = "Attack pipeline reserved for v1 follow-up";
            record.mifare_dump = dump;
        }
        record.meta.notes = "Mock data — PN532Killer command set pending";
        return record;
    }

    SavedRecord make_record_from_tag(const TagInfo &tag, const TransportEndpoint &endpoint, bool mock, const std::string &source) const
    {
        SavedRecord record;
        record.meta.created_at = iso8601_now();
        record.meta.record_id = make_record_id(tag);
        record.meta.display_name = make_record_name(tag);
        record.meta.source = source;
        record.meta.transport = endpoint.kind;
        record.meta.transport_path = endpoint.path;
        record.meta.mock = mock;
        record.tag = tag;
        return record;
    }

    EmulatorSlotRecord &current_slot_locked()
    {
        return current_slot_for_protocol_locked(selected_emulator_protocol_, selected_slot_by_protocol_[selected_emulator_protocol_]);
    }

    EmulatorSlotRecord &current_slot_for_protocol_locked(ProtocolKind protocol, int slot_index)
    {
        ensure_protocol_slots_locked(protocol);
        auto &slots = emulator_slots_by_protocol_[protocol];
        if (slot_index < 0) slot_index = 0;
        if (slot_index > 7) slot_index = 7;
        return slots[slot_index];
    }

    void ensure_protocol_slots_locked(ProtocolKind protocol)
    {
        auto &slots = emulator_slots_by_protocol_[protocol];
        while (static_cast<int>(slots.size()) < 8) {
            EmulatorSlotRecord empty;
            empty.slot_index = static_cast<int>(slots.size());
            empty.protocol = protocol;
            slots.push_back(empty);
        }
        for (size_t i = 0; i < slots.size(); ++i) {
            slots[i].slot_index = static_cast<int>(i);
            slots[i].protocol = protocol;
        }
    }

    std::vector<EmulatorSlotRecord> protocol_slots_padded_locked(ProtocolKind protocol) const
    {
        auto it = emulator_slots_by_protocol_.find(protocol);
        std::vector<EmulatorSlotRecord> slots = (it == emulator_slots_by_protocol_.end()) ? std::vector<EmulatorSlotRecord>{} : it->second;
        while (static_cast<int>(slots.size()) < 8) {
            EmulatorSlotRecord empty;
            empty.slot_index = static_cast<int>(slots.size());
            empty.protocol = protocol;
            slots.push_back(empty);
        }
        return slots;
    }

    bool save_emulator_slots_locked()
    {
        ensure_protocol_slots_locked(ProtocolKind::Iso14443A);
        ensure_protocol_slots_locked(ProtocolKind::Iso14443B);
        ensure_protocol_slots_locked(ProtocolKind::Iso15693);
        ensure_protocol_slots_locked(ProtocolKind::MifareClassic);
        return storage_.save_emulator_slots_by_protocol(emulator_slots_by_protocol_);
    }

    mutable std::mutex mutex_;
    NfcStorage storage_;
    std::vector<TransportEndpoint> endpoints_;
    int selected_endpoint_ = 0;
    std::unique_ptr<INfcTransport> transport_;
    ConnectionState connection_;
    ScanState scan_;
    ProtocolKind selected_emulator_protocol_ = ProtocolKind::Iso14443A;
    std::map<ProtocolKind, int> selected_slot_by_protocol_;
    std::map<ProtocolKind, std::vector<EmulatorSlotRecord>> emulator_slots_by_protocol_;
    std::thread scan_thread_;
    std::thread probe_thread_;
    std::vector<SavedRecord> mock_saved_records_;
    mutable int scan_mock_counter_ = 0;
    std::vector<DeviceProbeResult> probe_results_;
    bool probe_running_ = false;
    UartConfig uart_config_;

    void perform_probe_all()
    {
        // Take a snapshot of endpoints to probe (without holding the lock)
        std::vector<TransportEndpoint> to_probe;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto &ep : endpoints_) {
                if (ep.kind != TransportKind::Mock) to_probe.push_back(ep);
            }
        }

        for (size_t i = 0; i < to_probe.size(); ++i) {
            const auto &ep = to_probe[i];
            DeviceProbeResult result;
            result.path      = ep.path;
            result.transport = ep.kind;
            result.probing   = false;

            // Open a temporary transport
            auto transport = NfcTransportFactory::create(ep);
            std::string open_error;
            if (!transport->open(ep, &open_error)) {
                result.device_kind = DeviceKind::NotConnected;
                result.error = open_error;
            } else {
                Pn532KillerClient client(transport.get());
                std::string fw;
                std::string err;
                result.device_kind = client.detect_device(&fw, &err);
                result.firmware    = fw;
                result.error       = err;
                transport->close();
            }

            // Update probe_results_ entry in place
            std::lock_guard<std::mutex> lock(mutex_);
            if (i < probe_results_.size()) {
                probe_results_[i] = result;
            }
        }

        std::lock_guard<std::mutex> lock(mutex_);
        probe_running_ = false;
    }

    void seed_mock_saved_records()
    {
        // Mifare Classic 门禁卡
        {
            TagInfo tag;
            tag.protocol = ProtocolKind::MifareClassic;
            tag.tag_type = "Mifare Classic 1K";
            tag.uid = "DE AD BE EF";
            tag.identity_fields["atqa"] = "0004";
            tag.identity_fields["sak"]  = "08";
            tag.raw_data = {
                "Block0:  DE AD BE EF 21 08 04 00 46 49 4C 4C 45 44 4B 45",
                "Sector0 KeyA=FFFFFFFFFFFF  KeyB=FFFFFFFFFFFF",
            };
            TransportEndpoint ep; ep.kind = TransportKind::Mock; ep.path = "mock://seed";
            SavedRecord r = make_record_from_tag(tag, ep, true, "mock_seed");
            r.meta.record_id    = "mock_mifare_001";
            r.meta.display_name = "Door Fob (Mifare 1K)";
            r.meta.created_at   = "2026-05-01T08:00:00Z";
            r.meta.mock = true;
            MifareClassicDump dump;
            dump.sector_count = 16; dump.block_count = 64;
            dump.attack.method = AttackMethod::DefaultKeys;
            dump.attack.status = AttackStatus::Pending;
            r.mifare_dump = dump;
            mock_saved_records_.push_back(r);
        }

        // NTAG213 名片
        {
            TagInfo tag;
            tag.protocol = ProtocolKind::Iso14443A;
            tag.tag_type = "NFC-A NTAG213";
            tag.uid = "04 B3 7C 2A";
            tag.identity_fields["atqa"] = "0044";
            tag.identity_fields["sak"]  = "00";
            tag.raw_data = {
                "UID: 04 B3 7C 2A",
                "NDEF: https://m5stack.com",
            };
            TransportEndpoint ep; ep.kind = TransportKind::Mock; ep.path = "mock://seed";
            SavedRecord r = make_record_from_tag(tag, ep, true, "mock_seed");
            r.meta.record_id    = "mock_ntag_001";
            r.meta.display_name = "M5Stack NFC Tag";
            r.meta.created_at   = "2026-05-02T10:30:00Z";
            r.meta.mock = true;
            mock_saved_records_.push_back(r);
        }

        // iCODE SLI (ISO 15693) 图书馆卡
        {
            TagInfo tag;
            tag.protocol = ProtocolKind::Iso15693;
            tag.tag_type = "ISO 15693 iCODE SLI";
            tag.uid = "E0 04 01 00 5A 4B 3C 2D";
            tag.identity_fields["dsfid"]  = "00";
            tag.identity_fields["afi"]    = "00";
            tag.identity_fields["blocks"] = "32x4B";
            tag.raw_data = {
                "UID(rev): E0 04 01 00 5A 4B 3C 2D",
                "Block0: 4C 49 42 52  ('LIBR')",
            };
            TransportEndpoint ep; ep.kind = TransportKind::Mock; ep.path = "mock://seed";
            SavedRecord r = make_record_from_tag(tag, ep, true, "mock_seed");
            r.meta.record_id    = "mock_iso15693_001";
            r.meta.display_name = "Library Card (iCODE)";
            r.meta.created_at   = "2026-05-03T14:00:00Z";
            r.meta.mock = true;
            mock_saved_records_.push_back(r);
        }

        // Mifare Classic 4K 停车卡
        {
            TagInfo tag;
            tag.protocol = ProtocolKind::MifareClassic;
            tag.tag_type = "Mifare Classic 4K";
            tag.uid = "A1 B2 C3 D4";
            tag.identity_fields["atqa"] = "0002";
            tag.identity_fields["sak"]  = "38";
            tag.raw_data = {
                "Block0:  A1 B2 C3 D4 81 38 04 00 00 00 00 00 00 00 00 00",
                "Sector0 KeyA=A0A1A2A3A4A5  KeyB=FFFFFFFFFFFF",
            };
            TransportEndpoint ep; ep.kind = TransportKind::Mock; ep.path = "mock://seed";
            SavedRecord r = make_record_from_tag(tag, ep, true, "mock_seed");
            r.meta.record_id    = "mock_mifare4k_001";
            r.meta.display_name = "Parking Card (4K)";
            r.meta.created_at   = "2026-05-04T09:15:00Z";
            r.meta.mock = true;
            MifareClassicDump dump;
            dump.sector_count = 40; dump.block_count = 256;
            dump.attack.method = AttackMethod::DefaultKeys;
            dump.attack.status = AttackStatus::Pending;
            r.mifare_dump = dump;
            mock_saved_records_.push_back(r);
        }
    }
};

} // namespace nfc_app