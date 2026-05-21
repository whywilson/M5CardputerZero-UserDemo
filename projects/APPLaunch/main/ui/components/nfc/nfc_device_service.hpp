#pragma once

#include "nfc_hex_logger.hpp"
#include "nfc_i2c_device.hpp"
#include "nfc_protocol.hpp"
#include "nfc_storage.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <tuple>

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

struct Pn532NdefState {
    bool running = false;
    std::string uri = "https://m5stack.com";
    std::string status = "Idle";
    std::string error;
};

enum class UidMagicGeneration {
    Gen1A = 0,
    Gen2,
    Gen3,
    Gen4,
};

class NfcDeviceService {
public:
    NfcDeviceService()
    {
        refresh_endpoints();
        emulator_slots_by_protocol_ = storage_.load_emulator_slots_by_protocol();
        uart_config_ = storage_.load_uart_config();
        // Apply saved baud rate to any already-enumerated UART endpoint
        for (auto &ep : endpoints_) {
            if (ep.kind == TransportKind::UartSerial &&
                ep.path == uart_config_.device_path) {
                ep.baud_rate = uart_config_.baud_rate;
            }
        }
        // Restore last-used transport kind so the UI starts on the right mode
        const TransportKind saved_kind = storage_.load_last_transport_kind();
        if (saved_kind != TransportKind::Mock) {
            intended_kind_ = saved_kind;
            // Select the first endpoint matching the saved kind
            for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
                if (endpoints_[i].kind == saved_kind) {
                    // Prefer the configured UART path if UART
                    if (saved_kind == TransportKind::UartSerial &&
                        !uart_config_.device_path.empty() &&
                        endpoints_[i].path != uart_config_.device_path) continue;
                    selected_endpoint_ = i;
                    break;
                }
            }
        }
    }

    ~NfcDeviceService()
    {
        cancel_hw_upload_.store(true);
        cancel_hw_mfkey_.store(true);
        stop_pn532_ndef_emulation();
        if (uart_test_thread_.joinable()) uart_test_thread_.join();
        if (hw_upload_thread_.joinable()) hw_upload_thread_.join();
        if (scan_thread_.joinable()) scan_thread_.join();
        if (probe_thread_.joinable()) probe_thread_.join();
        if (emu_probe_thread_.joinable()) emu_probe_thread_.join();
        disconnect();
    }

    // ── Hardware EMU slot probe (PN532Killer) ────────────────────────────────
    struct EmuSlotInfo {
        bool probed      = false;
        std::string uid;           // empty if not available
        std::string block0_hex;    // hex string of first block/page, empty if n/a
        // Full dump — populated only when user triggers "Download Data"
        std::vector<std::string> dump_lines;  // formatted hex lines (e.g. "00: 34 5D 80 C4 ...")
        bool dump_loaded = false;
    };

    EmuSlotInfo emu_slot_info(ProtocolKind protocol, int slot) const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        auto it = emu_slot_cache_.find({protocol, slot});
        return (it != emu_slot_cache_.end()) ? it->second : EmuSlotInfo{};
    }

    bool emu_probe_running() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return emu_probe_running_;
    }

    std::string emu_probe_error() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return emu_probe_error_;
    }

    // Switch hardware emulator slot + probe block0 in background thread.
    // Cancels any in-progress probe so the new switch is never silently dropped.
    bool hw_switch_emu_slot_and_probe(ProtocolKind protocol, int slot)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (scan_.running) return false;
        }
        // Signal any running probe to stop, then join it.
        cancel_emu_probe_.store(true);
        if (emu_probe_thread_.joinable()) emu_probe_thread_.join();
        cancel_emu_probe_.store(false);

        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            emu_probe_running_ = true;
            emu_probe_error_.clear();
        }
        emu_probe_thread_ = std::thread([this, protocol, slot]() {
            perform_emu_slot_probe(protocol, slot);
        });
        return true;
    }

    static uint8_t emu_type_byte(ProtocolKind p)
    {
        switch (p) {
        case ProtocolKind::MifareClassic: return 0x01;
        case ProtocolKind::Iso15693:      return 0x03;
        default:                          return 0x02;  // NTAG / Iso14443A
        }
    }

    // Cycle HW EMU protocol: MFC → NTAG(Iso14443A) → ISO15693 → MFC
    void cycle_hw_emu_protocol()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (selected_emulator_protocol_ == ProtocolKind::MifareClassic)
            selected_emulator_protocol_ = ProtocolKind::Iso14443A;
        else if (selected_emulator_protocol_ == ProtocolKind::Iso14443A)
            selected_emulator_protocol_ = ProtocolKind::Iso15693;
        else
            selected_emulator_protocol_ = ProtocolKind::MifareClassic;
    }

    // Start async full dump download from HW EMU slot. Results stored in EmuSlotInfo::dump_lines.
    bool hw_start_emu_dump_async(ProtocolKind protocol, int slot)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (scan_.running) return false;
        }
        cancel_emu_dump_.store(true);
        if (emu_dump_thread_.joinable()) emu_dump_thread_.join();
        cancel_emu_dump_.store(false);

        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            emu_dump_running_ = true;
        }
        emu_dump_thread_ = std::thread([this, protocol, slot]() {
            perform_emu_slot_dump(protocol, slot);
        });
        return true;
    }

    bool emu_dump_running() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return emu_dump_running_;
    }

    // Start asynchronous upload of a saved MFC record to the given HW EMU slot (0-based).
    // Returns false if already running or scan is running.
    bool hw_start_upload_async(int slot, const SavedRecord &record)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (scan_.running) return false;
            if (record.tag.raw_data.size() != 64) return false;
        }
        cancel_hw_upload_.store(true);
        if (hw_upload_thread_.joinable()) hw_upload_thread_.join();
        cancel_hw_upload_.store(false);
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            hw_upload_running_  = true;
            hw_upload_progress_ = 0;
            hw_upload_ok_       = false;
        }
        hw_upload_thread_ = std::thread([this, slot, record]() {
            perform_hw_upload(slot, record);
        });
        return true;
    }

    bool hw_upload_running() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return hw_upload_running_;
    }

    int hw_upload_progress() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return hw_upload_progress_;
    }

    bool hw_upload_ok() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return hw_upload_ok_;
    }

    void refresh_endpoints()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        endpoints_ = NfcTransportFactory::enumerate_endpoints();
        if (selected_endpoint_ >= static_cast<int>(endpoints_.size())) selected_endpoint_ = 0;
        if (endpoints_.empty()) return;
        // Auto-select the first USB endpoint when the intended mode is USB (default at startup).
        if (intended_kind_ == TransportKind::UsbSerial) {
            for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
                if (endpoints_[i].kind == TransportKind::UsbSerial) {
                    selected_endpoint_ = i;
                    break;
                }
            }
        }
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
                if (ep.kind == TransportKind::I2cBus) continue;
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
        storage_.save_uart_config(cfg);
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

    // ── Async UART connection test ───────────────────────────────────────────
    // Launches a background thread that:
    //   1. Opens the UART port and sends wakeup + SAMConfig + FWVersion frames
    //   2. Logs every TX/RX byte (hex) to both a file and uart_test_log_lines_
    //   3. Sets uart_test_result_ when done.
    // Call uart_test_running() to poll; drain_uart_test_logs() to collect lines.
    void start_uart_test()
    {
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            if (uart_test_running_) return; // already running
            uart_test_running_ = true;
            uart_test_log_lines_.clear();
            uart_test_result_.clear();
        }
        if (uart_test_thread_.joinable()) uart_test_thread_.join();
        uart_test_thread_ = std::thread([this]() {
            // Resolve config
            UartConfig cfg;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                cfg = uart_config_;
                if (cfg.device_path.empty()) {
                    for (const auto &ep : endpoints_) {
                        if (ep.kind == TransportKind::UartSerial) {
                            cfg.device_path = ep.path;
                            if (cfg.baud_rate <= 0) cfg.baud_rate = ep.baud_rate;
                            break;
                        }
                    }
                }
            }
            if (cfg.device_path.empty()) {
                finish_uart_test("No UART port found (/dev/ttyAMA*)");
                return;
            }
            const int baud = 115200; // fixed baud rate

            // Open log file
            const std::string log_dir = storage_.root_dir() + "/logs";
            ::mkdir(log_dir.c_str(), 0755);
            const std::string log_path = log_dir + "/uart_test_latest.log";
            FILE *fp = fopen(log_path.c_str(), "w");
            auto log_line = [&](const std::string &s) {
                {
                    std::lock_guard<std::mutex> lk(pending_log_mutex_);
                    uart_test_log_lines_.push_back(s);
                }
                if (fp) { fputs(s.c_str(), fp); fputc('\n', fp); fflush(fp); }
            };

            log_line("=== UART test " + cfg.device_path + " @" + std::to_string(baud) + " baud ===");

            // Build endpoint and open transport
            TransportEndpoint ep;
            ep.kind      = TransportKind::UartSerial;
            ep.path      = cfg.device_path;
            ep.baud_rate = baud;

            SerialTransport raw_transport;
            std::string open_error;
            if (!raw_transport.open(ep, &open_error)) {
                log_line("Open failed: " + open_error);
                if (fp) fclose(fp);
                finish_uart_test("Open failed: " + open_error);
                return;
            }

            // Wrap with a logging shim
            class LogTransport : public INfcTransport {
            public:
                INfcTransport *inner;
                std::function<void(const std::string&)> log;
                ssize_t write_bytes(const uint8_t *b, size_t n, std::string *err) override {
                    std::string hex = "TX[" + std::to_string(n) + "] ";
                    for (size_t i = 0; i < n && i < 64; ++i) {
                        char buf[3]; std::snprintf(buf, sizeof(buf), "%02X", b[i]);
                        hex += buf;
                    }
                    if (n > 64) hex += "...";
                    log(hex);
                    return inner->write_bytes(b, n, err);
                }
                ssize_t read_bytes(uint8_t *b, size_t n, int timeout_ms, std::string *err) override {
                    ssize_t got = inner->read_bytes(b, n, timeout_ms, err);
                    if (got <= 0) return got;
                    // After the first bytes arrive, drain any immediately available
                    // continuation bytes (0 ms timeout) so the whole response frame
                    // lands in a single log line instead of one-byte-per-line.
                    while ((size_t)got < n) {
                        ssize_t more = inner->read_bytes(b + got, n - (size_t)got, 0, nullptr);
                        if (more <= 0) break;
                        got += more;
                    }
                    std::string hex = "RX[" + std::to_string(got) + "] ";
                    constexpr ssize_t MAX_LOG = 64;
                    for (ssize_t i = 0; i < got && i < MAX_LOG; ++i) {
                        char buf[3]; std::snprintf(buf, sizeof(buf), "%02X", b[i]);
                        hex += buf;
                    }
                    if (got > MAX_LOG) hex += "...";
                    log(hex);
                    return got;
                }
                bool is_open() const override { return inner->is_open(); }
                void close() override { inner->close(); }
                bool open(const TransportEndpoint &ep, std::string *err) override { return inner->open(ep, err); }
                TransportEndpoint endpoint() const override { return inner->endpoint(); }
            };
            LogTransport logging_transport;
            logging_transport.inner = &raw_transport;
            logging_transport.log   = log_line;

            Pn532KillerClient client(&logging_transport);
            std::string probe_error, firmware;
            const DeviceKind kind = client.detect_device(&firmware, &probe_error);
            raw_transport.close();

            std::string result;
            if (kind == DeviceKind::PN532Killer || kind == DeviceKind::PN532) {
                result = std::string("OK: ");
                result += firmware.empty() ? to_string(kind) : firmware;
            } else {
                result = "No device: " + probe_error;
            }
            log_line("=== Result: " + result + " ===");
            if (fp) fclose(fp);
            finish_uart_test(result);
        });
    }

    bool uart_test_running() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return uart_test_running_;
    }

    // Drain pending log lines into out (appends). Returns true if test finished.
    bool drain_uart_test_logs(std::vector<std::string> &out, std::string &result_out)
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        out.insert(out.end(), uart_test_log_lines_.begin(), uart_test_log_lines_.end());
        uart_test_log_lines_.clear();
        if (!uart_test_running_ && !uart_test_result_.empty()) {
            result_out = uart_test_result_;
            return true; // finished
        }
        return false;
    }

    // Returns USB serial endpoints only (no mock, no UART)
    std::vector<TransportEndpoint> usb_endpoints() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<TransportEndpoint> out;
        for (const auto &ep : endpoints_) {
            if (ep.kind == TransportKind::UsbSerial) out.push_back(ep);
        }
        return out;
    }

    // Select a USB endpoint by path and reset connection state.
    // Returns true if found and selected.
    bool select_usb_endpoint_by_path(const std::string &path)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
            if (endpoints_[i].path == path) {
                if (transport_) { transport_->close(); transport_.reset(); }
                connection_ = ConnectionState{};
                selected_endpoint_ = i;
                return true;
            }
        }
        return false;
    }

    // Probe I2C buses on-demand. Returns only devices that responded to the probe.
    std::vector<TransportEndpoint> scan_i2c_devices()
    {
        return NfcTransportFactory::probe_i2c_devices();
    }

    // Select a specific I2C endpoint for connection. If the endpoint is not
    // already in the cached list (e.g. from an on-demand scan), it is appended.
    void select_i2c_endpoint(const TransportEndpoint &ep)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // Disconnect current transport first
        if (transport_) { transport_->close(); transport_.reset(); }
        connection_ = ConnectionState{};
        intended_kind_ = TransportKind::I2cBus;
        // Reuse existing slot if the path is already known
        for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
            if (endpoints_[i].kind == TransportKind::I2cBus &&
                endpoints_[i].path == ep.path) {
                selected_endpoint_ = i;
                return;
            }
        }
        // Not yet in list — append it
        endpoints_.push_back(ep);
        selected_endpoint_ = static_cast<int>(endpoints_.size()) - 1;
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
        if (!endpoints_.empty() && selected_endpoint_ < static_cast<int>(endpoints_.size())) {
            if (endpoints_[selected_endpoint_].kind == intended_kind_)
                return endpoints_[selected_endpoint_];
        }
        // No real endpoint for intended kind: return a synthetic one so UI can display the mode
        TransportEndpoint syn;
        syn.kind = intended_kind_;
        syn.path = "";
        syn.label = std::string(to_string(intended_kind_)) + " (no device)";
        syn.baud_rate = 0;
        return syn;
    }

    void cycle_endpoint(int delta)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (endpoints_.empty()) return;
        const int count = static_cast<int>(endpoints_.size());
        selected_endpoint_ = (selected_endpoint_ + delta + count) % count;
    }

    // Cycle through MOCK → USB → UART → MOCK, always including all three kinds.
    // Does NOT auto-connect; just selects the endpoint and returns.
    bool cycle_device_mode(std::string *status = nullptr)
    {
        // Save current path so we can restore stable selection after re-enumeration
        std::string current_path;
        TransportKind current_kind = TransportKind::UsbSerial;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            // Use intended_kind_ as the authoritative "current" so that if the
            // last cycle landed on an empty slot we still advance from there.
            current_kind = intended_kind_;
            if (!endpoints_.empty() && selected_endpoint_ < static_cast<int>(endpoints_.size())) {
                current_path = endpoints_[selected_endpoint_].path;
            }
        }

        refresh_endpoints();
        std::lock_guard<std::mutex> lock(mutex_);

        // Restore selected_endpoint_ by path after re-enumeration to avoid stale index
        if (!current_path.empty()) {
            for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
                if (endpoints_[i].path == current_path) {
                    selected_endpoint_ = i;
                    break;
                }
            }
        }

        // Build cycle: USB → UART → I2C (always; Mock removed).
        std::vector<TransportKind> cycle;
        cycle.push_back(TransportKind::UsbSerial);
        cycle.push_back(TransportKind::UartSerial);
        cycle.push_back(TransportKind::I2cBus);

        // current_kind already determined above (stable after refresh)

        // Find next kind in cycle
        TransportKind target_kind = cycle[0];
        for (size_t i = 0; i < cycle.size(); ++i) {
            if (cycle[i] == current_kind) {
                target_kind = cycle[(i + 1) % cycle.size()];
                break;
            }
        }

        // Select first endpoint matching target kind (prefer configured UART path)
        int target_index = -1;
        if (target_kind == TransportKind::UartSerial && !uart_config_.device_path.empty()) {
            for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
                if (endpoints_[i].kind == target_kind && endpoints_[i].path == uart_config_.device_path) {
                    target_index = i;
                    break;
                }
            }
        }
        if (target_index < 0) {
            for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
                if (endpoints_[i].kind == target_kind) {
                    target_index = i;
                    break;
                }
            }
        }
        // Disconnect old transport regardless of whether we found an endpoint
        if (transport_) { transport_->close(); transport_.reset(); }
        connection_ = ConnectionState{};
        intended_kind_ = target_kind;

        if (target_index < 0) {
            // No physical device for this kind – stay in the slot, report it
            if (status) *status = std::string(to_string(target_kind)) + ": no device";
            return false;
        }

        selected_endpoint_ = target_index;
        storage_.save_last_transport_kind(target_kind);
        if (status) *status = std::string("Mode: ") + to_string(target_kind);
        return true;
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

            TransportKind current_kind = TransportKind::UsbSerial;
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
        transport_ = std::unique_ptr<INfcTransport>(
            new LoggingTransport(std::move(transport_), "NFC"));
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

        // Set log file mode prefix based on transport type.
        if (connection_.endpoint.kind == TransportKind::I2cBus)
            NfcHexLog::get().set_mode("iic");
        else
            NfcHexLog::get().set_mode("uart");

        if (connection_.endpoint.kind == TransportKind::UsbSerial ||
            connection_.endpoint.kind == TransportKind::UartSerial) {
            Pn532KillerClient client(transport_.get());
            std::string probe_error;
            std::string firmware;
            const auto kind = client.detect_device(&firmware, &probe_error);
            connection_.device_kind = kind;
            if (kind == DeviceKind::PN532Killer || kind == DeviceKind::PN532) {
                connection_.pn532_ready = true;
                connection_.status = std::string("Connected ") + to_string(kind);
                const std::string fw_label = firmware.empty() ? to_string(kind) : firmware;
                connection_.detail = fw_label + std::string(" @ ") + connection_.endpoint.path;
            } else {
                connection_.detail = std::string("Raw serial only: ") + probe_error;
            }
        } else if (connection_.endpoint.kind == TransportKind::I2cBus) {
            // Parse "/dev/i2c-1:0x48" → bus + addr
            const std::string &path = connection_.endpoint.path;
            const auto colon_pos = path.rfind(':');
            if (colon_pos == std::string::npos) {
                connection_.detail = "I2C: invalid endpoint path (missing ':' separator)";
            } else {
                const std::string bus = path.substr(0, colon_pos);
                const uint8_t addr = (uint8_t)std::stoul(path.substr(colon_pos + 1), nullptr, 16);
                i2c_device_ = std::make_unique<I2cGroveNfcDevice>();
                std::string i2c_error;
                if (!i2c_device_->open(bus, addr, &i2c_error)) {
                    connection_.connected = false;
                    connection_.device_kind = DeviceKind::NotConnected;
                    connection_.detail = "I2C open failed: " + i2c_error;
                    i2c_device_.reset();
                } else {
                    connection_.device_kind = i2c_device_->device_kind();
                    connection_.pn532_ready = true;
                    connection_.status = std::string("Connected ") + to_string(connection_.device_kind);
                    const uint16_t hw = i2c_device_->readSysReg(0x0000);
                    const uint16_t fw = i2c_device_->readSysReg(0x0002);
                    char ver[128];
                    std::snprintf(ver, sizeof(ver), "%s @%s HW:%04X FW:%04X",
                        to_string(connection_.device_kind), path.c_str(), hw, fw);
                    connection_.detail = ver;
                }
            }
        }
        return true;
    }

    void disconnect()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (transport_) transport_->close();
        transport_.reset();
        i2c_device_.reset();
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

    Pn532NdefState pn532_ndef_state() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return pn532_ndef_;
    }

    bool start_pn532_ndef_emulation(const std::string &uri, std::string *error = nullptr)
    {
        std::string target_uri = uri.empty() ? "https://m5stack.com" : uri;
        stop_pn532_ndef_emulation();

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!connection_.connected || connection_.device_kind != DeviceKind::PN532) {
                if (error) *error = "PN532 required for NDEF emulation";
                return false;
            }
            pn532_ndef_.running = true;
            pn532_ndef_.uri = target_uri;
            pn532_ndef_.status = "Starting";
            pn532_ndef_.error.clear();
        }

        cancel_pn532_ndef_.store(false);
        pn532_ndef_thread_ = std::thread([this, target_uri]() {
            perform_pn532_ndef_emulation(target_uri);
        });
        if (error) error->clear();
        return true;
    }

    void stop_pn532_ndef_emulation()
    {
        cancel_pn532_ndef_.store(true);
        if (pn532_ndef_thread_.joinable()) pn532_ndef_thread_.join();

        std::lock_guard<std::mutex> lock(mutex_);
        if (pn532_ndef_.running) {
            pn532_ndef_.running = false;
            pn532_ndef_.status = "Stopped";
        }
    }

    bool clear_last_scan_result(std::string *error = nullptr)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (scan_.running) {
                if (error) *error = "Operation already running";
                return false;
            }
            scan_.has_result = false;
            scan_.last_record = SavedRecord{};
            scan_.status = connection_.connected ? "Ready" : "Idle";
            scan_.error.clear();
            last_dump_success_ = false;
        }
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            pending_log_lines_.clear();
        }
        if (error) error->clear();
        return true;
    }

    std::vector<ProtocolKind> supported_protocols_for_current_device() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const bool connected = connection_.connected;
        const DeviceKind kind = connection_.device_kind;
        const TransportKind transport = connected ? connection_.endpoint.kind : intended_kind_;

        if (kind == DeviceKind::PN532) {
            return {ProtocolKind::Iso14443A};
        }
        if (kind == DeviceKind::PN532Killer) {
            return {ProtocolKind::Iso14443A, ProtocolKind::Iso14443B, ProtocolKind::Iso15693};
        }
        if (kind == DeviceKind::GroveNFC) {
            return {ProtocolKind::Iso14443A, ProtocolKind::Iso14443B,
                    ProtocolKind::Iso15693, ProtocolKind::Felica};
        }
        if (kind == DeviceKind::NFCUnit) {
            return {ProtocolKind::Iso14443A, ProtocolKind::Iso14443B,
                    ProtocolKind::Iso15693, ProtocolKind::Felica};
        }

        if (transport == TransportKind::I2cBus) {
            return {ProtocolKind::Iso14443A, ProtocolKind::Iso14443B,
                    ProtocolKind::Iso15693, ProtocolKind::Felica};
        }
        return {ProtocolKind::Iso14443A, ProtocolKind::Iso14443B, ProtocolKind::Iso15693};
    }

    // Drain lines pushed in real-time during a Gen1A dump (called by UI each frame).
    std::vector<std::string> drain_pending_log()
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        std::vector<std::string> out;
        out.swap(pending_log_lines_);
        return out;
    }

    // Switch PN532Killer back to reader mode. Cancel any running EMU probe/dump first.
    void hw_switch_to_reader_mode()
    {
        NfcHexLog::get().log_event("reader", "switching to reader mode");
        cancel_emu_probe_.store(true);
        if (emu_probe_thread_.joinable()) emu_probe_thread_.join();
        cancel_emu_probe_.store(false);
        cancel_emu_dump_.store(true);
        if (emu_dump_thread_.joinable()) emu_dump_thread_.join();
        cancel_emu_dump_.store(false);
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            emu_probe_running_ = false;
            emu_dump_running_  = false;
        }
        INfcTransport *transport_raw = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
        }
        if (transport_raw && transport_raw->is_open()) {
            Pn532KillerClient client(transport_raw);
            client.set_work_mode(0x01, 0x01, 0x00, nullptr);
        }
    }

    // Write UID/block0 to classic magic cards (Gen1A/Gen2/Gen3/Gen4).
    // uid_hex must be 8 or 14 hex chars, block0_hex must be 32 hex chars.
    bool write_magic_uid(UidMagicGeneration generation,
                         const std::string &uid_hex,
                         const std::string &block0_hex,
                         const std::string &gen4_password,
                         const std::string &gen2_sector0_key_a,
                         std::string *error = nullptr)
    {
        INfcTransport *transport_raw = nullptr;
        I2cGroveNfcDevice *i2c_dev = nullptr;
        DeviceKind kind = DeviceKind::Unknown;
        bool busy = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            busy = scan_.running;
            transport_raw = transport_.get();
            i2c_dev = i2c_device_.get();
            kind = connection_.device_kind;
        }

        if (busy) {
            if (error) *error = "Scan/dump running";
            return false;
        }
        std::vector<uint8_t> uid;
        std::vector<uint8_t> block0;
        if (!parse_hex_bytes(uid_hex, &uid)) {
            if (error) *error = "Invalid UID hex";
            return false;
        }
        if (!parse_hex_bytes(block0_hex, &block0) || block0.size() != 16) {
            if (error) *error = "Invalid block0 hex";
            return false;
        }
        if (uid.size() != 4 && uid.size() != 7) {
            if (error) *error = "UID must be 4B or 7B";
            return false;
        }

        std::vector<uint8_t> gen2_key_a;
        if (generation == UidMagicGeneration::Gen2) {
            if (!parse_hex_bytes(gen2_sector0_key_a, &gen2_key_a) || gen2_key_a.size() != 6) {
                if (error) *error = "Sector0 KeyA must be 12 hex";
                return false;
            }
        }

        std::string gen4_pw;
        if (generation == UidMagicGeneration::Gen4) {
            for (char c : gen4_password) {
                if (!std::isspace(static_cast<unsigned char>(c))) {
                    gen4_pw.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
                }
            }
            if (gen4_pw.size() != 8 ||
                !std::all_of(gen4_pw.begin(), gen4_pw.end(),
                             [](char c) { return std::isxdigit(static_cast<unsigned char>(c)); })) {
                if (error) *error = "Gen4 password must be 8 hex";
                return false;
            }
        }

        if (kind == DeviceKind::NFCUnit) {
            if (!i2c_dev || !i2c_dev->is_open()) {
                if (error) *error = "NFC Unit not connected";
                return false;
            }
            if (generation == UidMagicGeneration::Gen1A) {
                return i2c_dev->writeNFCUnitGen1ABlock0(block0, error);
            }
            if (generation == UidMagicGeneration::Gen3) {
                return i2c_dev->writeNFCUnitGen3Block0(uid, block0, error);
            }
            if (error) *error = "NFC Unit supports Gen1A and Gen3 only";
            return false;
        }

        if (!transport_raw || !transport_raw->is_open()) {
            if (error) *error = "Device not connected";
            return false;
        }
        if (kind != DeviceKind::PN532 && kind != DeviceKind::PN532Killer) {
            if (error) *error = "PN532/PN532Killer/NFC Unit required";
            return false;
        }

        Pn532KillerClient client(transport_raw);
        client.send_wakeup();
        client.sam_configuration(nullptr);

        std::string op_err;
        bool ok = false;
        switch (generation) {
        case UidMagicGeneration::Gen1A:
            ok = client.write_gen1a_block0(block0, &op_err);
            break;
        case UidMagicGeneration::Gen2:
            ok = client.write_gen2_block0(block0, gen2_key_a, &op_err);
            break;
        case UidMagicGeneration::Gen3:
            ok = client.set_classic_gen3_uid(uid, block0, &op_err);
            break;
        case UidMagicGeneration::Gen4:
            ok = client.set_gen4_uid(uid, block0, gen4_pw, &op_err);
            break;
        }

        if (!ok) {
            if (error) *error = op_err.empty() ? "UID write failed" : op_err;
            return false;
        }
        if (error) error->clear();
        return true;
    }

    bool scan_uid_once(std::string *uid_hex, std::string *error)
    {
        INfcTransport *transport_raw = nullptr;
        I2cGroveNfcDevice *i2c_dev = nullptr;
        DeviceKind kind = DeviceKind::Unknown;
        bool busy = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            busy = scan_.running;
            transport_raw = transport_.get();
            i2c_dev = i2c_device_.get();
            kind = connection_.device_kind;
        }

        if (busy) {
            if (error) *error = "Scan/dump running";
            return false;
        }
        if (kind == DeviceKind::NFCUnit || kind == DeviceKind::GroveNFC) {
            if (!i2c_dev || !i2c_dev->is_open()) {
                if (error) *error = "I2C device not connected";
                return false;
            }
            I2cCardInfo card;
            if (!i2c_dev->readCard(card) || !card.valid) {
                if (error) *error = "no card";
                return false;
            }
            std::string normalized;
            normalized.reserve(card.uid.size());
            for (char ch : card.uid) {
                if (std::isxdigit(static_cast<unsigned char>(ch))) {
                    normalized.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
                }
            }
            if (normalized.empty()) {
                if (error) *error = "invalid UID";
                return false;
            }
            if (uid_hex) *uid_hex = normalized;
            if (error) error->clear();
            return true;
        }

        if (!transport_raw || !transport_raw->is_open()) {
            if (error) *error = "Device not connected";
            return false;
        }
        if (kind != DeviceKind::PN532 && kind != DeviceKind::PN532Killer) {
            if (error) *error = "PN532/PN532Killer/NFC Unit required";
            return false;
        }

        Pn532KillerClient client(transport_raw);
        client.send_wakeup();
        client.sam_configuration(nullptr);
        TagInfo tag;
        if (!client.in_list_passive_target_iso14443a(&tag, error)) {
            return false;
        }
        if (uid_hex) *uid_hex = tag.uid;
        return true;
    }

    bool start_scan()
    {
        stop_pn532_ndef_emulation();
        if (scan_thread_.joinable()) scan_thread_.join();
        // Cancel any running EMU probe/dump threads to avoid racing set_work_mode calls
        cancel_emu_probe_.store(true);
        if (emu_probe_thread_.joinable()) emu_probe_thread_.join();
        cancel_emu_probe_.store(false);
        cancel_emu_dump_.store(true);
        if (emu_dump_thread_.joinable()) emu_dump_thread_.join();
        cancel_emu_dump_.store(false);

        std::lock_guard<std::mutex> lock(mutex_);
        if (!transport_ || !transport_->is_open()) {
            scan_.running = false;
            scan_.status = "No device";
            scan_.error = "Connect USB/UART first";
            return false;
        }
        if (scan_.running) return false;

        scan_.running = true;
        scan_.has_result = false;
        scan_.status = "Scanning";
        scan_.error.clear();
        last_dump_success_ = false;
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            pending_log_lines_.clear();
        }

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

    bool can_dump_last_scan(std::string *error = nullptr) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (scan_.running) {
            if (error) *error = "Operation already running";
            return false;
        }
        if (!scan_.has_result) {
            if (error) *error = "Scan card first";
            return false;
        }
        if (!transport_ || !transport_->is_open()) {
            if (error) *error = "Connect device first";
            return false;
        }
        if (connection_.endpoint.kind == TransportKind::I2cBus) {
            if (!i2c_device_ || !i2c_device_->is_open()) {
                if (error) *error = "I2C device not open";
                return false;
            }
            const auto p = scan_.last_record.tag.protocol;
            if (p != ProtocolKind::MifareClassic &&
                p != ProtocolKind::Iso14443A &&
                p != ProtocolKind::Iso15693) {
                if (error) *error = "I2C dump supports MFC/MFU/ISO15693 only";
                return false;
            }
            return true;
        }
        if (connection_.device_kind == DeviceKind::PN532 &&
            scan_.last_record.tag.protocol == ProtocolKind::Iso15693) {
            if (error) *error = "PN532 ISO15693 read not supported";
            return false;
        }
        return true;
    }

    bool start_dump_last_scan()
    {
        stop_pn532_ndef_emulation();
        if (scan_thread_.joinable()) scan_thread_.join();
        // Cancel any running EMU probe/dump threads to avoid racing set_work_mode calls
        cancel_emu_probe_.store(true);
        if (emu_probe_thread_.joinable()) emu_probe_thread_.join();
        cancel_emu_probe_.store(false);
        cancel_emu_dump_.store(true);
        if (emu_dump_thread_.joinable()) emu_dump_thread_.join();
        cancel_emu_dump_.store(false);

        std::string precheck_error;
        if (!can_dump_last_scan(&precheck_error)) {
            std::lock_guard<std::mutex> lock(mutex_);
            scan_.running = false;
            scan_.status = "Dump unavailable";
            scan_.error = precheck_error;
            return false;
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            scan_.running = true;
            scan_.status = "Dumping";
            scan_.error.clear();
            last_dump_success_ = false;
        }
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            pending_log_lines_.clear();
        }

        scan_thread_ = std::thread([this]() { perform_dump_from_last_scan(); });
        return true;
    }

    bool can_save_last_dump(std::string *error = nullptr) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!scan_.has_result) {
            if (error) *error = "No scan result to save";
            return false;
        }
        if (!last_dump_success_) {
            if (error) *error = "Dump card first";
            return false;
        }
        if (scan_.last_record.tag.raw_data.empty()) {
            if (error) *error = "No dump data to save";
            return false;
        }
        return true;
    }

    bool save_last_scan(std::string *error = nullptr)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!scan_.has_result) {
            if (error) *error = "No scan result to save";
            return false;
        }
        if (!last_dump_success_) {
            if (error) *error = "Dump card first";
            return false;
        }
        if (scan_.last_record.tag.raw_data.empty()) {
            if (error) *error = "No dump data to save";
            return false;
        }
        return storage_.save_record(scan_.last_record, error);
    }

    bool delete_saved_record(const std::string &record_id, std::string *error = nullptr)
    {
        return storage_.delete_record(record_id, error);
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

    // ── Key dictionary file service ──────────────────────────────────────────

    std::vector<std::string> list_key_files() const
    {
        return storage_.list_key_files();
    }

    std::vector<std::string> load_key_file(const std::string &filename) const
    {
        return storage_.load_key_file(filename);
    }

    bool save_key_file(const std::string &filename,
                       const std::vector<std::string> &keys,
                       std::string *err = nullptr) const
    {
        return storage_.save_key_file(filename, keys, err);
    }

    // Save keys from a SavedRecord's raw_data (MFC sector trailers) to <uid>.dic.
    bool save_keys_from_record(const SavedRecord &rec, std::string *err = nullptr) const
    {
        const std::string uid = rec.tag.uid.empty() ? rec.meta.record_id : rec.tag.uid;
        return storage_.save_uid_key_file(uid, rec.tag.raw_data, err);
    }

    // ── MFKey async crack ────────────────────────────────────────────────────

    struct MfkeyResult {
        uint32_t uid;
        uint8_t  sector;
        uint8_t  key_type; // 0=A, 1=B
        std::string key_hex; // empty if not found
    };

    // Synchronously set sniffer slot UID from 8-char hex string (e.g. "DEADBEEF").
    // Builds block0: uid[4] + BCC[1] + SAK(0x08)[1] + ATQA(0x04,0x00)[2] + pad[8]
    bool hw_sniff_set_uid(const std::string &uid_hex)
    {
        if (uid_hex.size() < 8) return false;
        {
            char msg[32];
            std::snprintf(msg, sizeof(msg), "set sniffer UID: %s", uid_hex.substr(0, 8).c_str());
            NfcHexLog::get().log_event("mfkey32v2", msg);
        }
        uint8_t uid[4];
        for (int i = 0; i < 4; ++i) {
            uid[i] = static_cast<uint8_t>(std::stoul(uid_hex.substr(i * 2, 2), nullptr, 16));
        }
        uint8_t block0[16] = {};
        block0[0] = uid[0]; block0[1] = uid[1]; block0[2] = uid[2]; block0[3] = uid[3];
        block0[4] = uid[0] ^ uid[1] ^ uid[2] ^ uid[3]; // BCC
        block0[5] = 0x08; // SAK MFC 1K
        block0[6] = 0x04; block0[7] = 0x00; // ATQA
        // bytes 8-15 remain 0

        INfcTransport *transport_raw = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
        }
        if (!transport_raw || !transport_raw->is_open()) return false;
        Pn532KillerClient client(transport_raw);
        return client.sniff_set_uid(block0);
    }

    // Synchronously enter sniffer mode on the device.
    // with_card=false → mfkey32v2 (no-card), with_card=true → mfkey64 (card-present)
    bool hw_sniff_enter_mode(bool with_card)
    {
        NfcHexLog::get().log_event(with_card ? "mfkey64" : "mfkey32v2",
                                   with_card ? "enter card-present sniffer mode" : "enter no-card sniffer mode");
        INfcTransport *transport_raw = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
        }
        if (!transport_raw || !transport_raw->is_open()) return false;
        Pn532KillerClient client(transport_raw);
        return client.sniff_enter_mode(with_card);
    }

    bool hw_start_mfkey_async(bool with_card)
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        if (hw_mfkey_running_) return false;
        cancel_hw_mfkey_.store(false);
        hw_mfkey_running_  = true;
        hw_mfkey_progress_ = 0;
        hw_mfkey_results_.clear();
        hw_mfkey_thread_ = std::thread([this, with_card]() {
            perform_hw_mfkey(with_card);
        });
        hw_mfkey_thread_.detach();
        return true;
    }

    bool hw_mfkey_running() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return hw_mfkey_running_;
    }

    int hw_mfkey_progress() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return hw_mfkey_progress_;
    }

    std::vector<MfkeyResult> hw_mfkey_results() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return hw_mfkey_results_;
    }

    // Import a cracked MFKey result into the internal MIFARE keys JSON.
    bool import_mfkey_result(const MfkeyResult &res, std::string *err = nullptr)
    {
        if (res.key_hex.size() != 12) { if (err) *err = "No key"; return false; }
        MifareKeyRecord rec;
        char buf[64];
        std::snprintf(buf, sizeof(buf), "MFKey s%02u%c",
                      static_cast<unsigned>(res.sector), res.key_type == 0 ? 'A' : 'B');
        rec.label    = buf;
        rec.key_hex  = res.key_hex;
        rec.type     = (res.key_type == 0) ? MifareKeyType::KeyA : MifareKeyType::KeyB;
        rec.enabled  = true;
        rec.source   = "mfkey";
        return upsert_mifare_key(-1, rec, err);
    }

    std::vector<SavedRecord> list_saved_records() const
    {
        return storage_.list_records();
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
        if (connection_.connected && (connection_.device_kind == DeviceKind::PN532Killer ||
                                      connection_.device_kind == DeviceKind::PN532 ||
                                      connection_.device_kind == DeviceKind::GroveNFC ||
                                      connection_.device_kind == DeviceKind::NFCUnit)) {
            return true;
        }
        if (reason) {
            *reason = "PN532/PN532Killer/GroveNFC/NFCUnit\nrequired for EMU";
        }
        return false;
    }

    // Activate GroveNFC emulation for the given protocol/slot (GroveNFC 0x48 only).
    bool grovenfc_activate(ProtocolKind protocol, int slot_index, std::string *error = nullptr)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!i2c_device_ || !i2c_device_->is_open() ||
            (i2c_device_->device_kind() != DeviceKind::GroveNFC &&
             i2c_device_->device_kind() != DeviceKind::NFCUnit)) {
            if (error) *error = "I2C emulation device not connected";
            return false;
        }
        i2c_device_->setSlot((uint8_t)(slot_index < 0 ? 0 : slot_index > 7 ? 7 : slot_index));
        bool ok = false;
        switch (protocol) {
        case ProtocolKind::MifareClassic: ok = i2c_device_->startEmulationMifare1K(); break;
        case ProtocolKind::Iso14443B:     ok = i2c_device_->startEmulationChinaII(); break;
        case ProtocolKind::Iso15693:      ok = i2c_device_->startEmulationISO15();   break;
        default:                          ok = i2c_device_->startEmulationNtag213(); break;
        }
        if (!ok && error) *error = "GroveNFC activate failed";
        return ok;
    }

    bool grovenfc_deactivate()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!i2c_device_ || !i2c_device_->is_open()) return false;
        return i2c_device_->stopEmulation();
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

    // Returns true when a full dump for the given (protocol, slot) is cached in memory.
    bool emu_dump_loaded(ProtocolKind protocol, int slot) const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        auto it = emu_slot_cache_.find({protocol, slot});
        return it != emu_slot_cache_.end() && it->second.dump_loaded;
    }

    // Save the most recently downloaded EMU dump (from memory cache) to permanent storage.
    // Called explicitly by the user via "Save Dump" in the EMU modal.
    bool save_emu_dump_cached(ProtocolKind protocol, int slot, std::string *err = nullptr)
    {
        std::vector<std::string> dump_lines;
        std::string uid;
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            auto it = emu_slot_cache_.find({protocol, slot});
            if (it == emu_slot_cache_.end() || !it->second.dump_loaded) {
                if (err) *err = "No cached dump for this slot";
                return false;
            }
            dump_lines = it->second.dump_lines;
            uid = it->second.uid;
        }
        TagInfo tag;
        tag.protocol = protocol;
        tag.uid = uid;
        for (const auto &line : dump_lines) {
            if (line.size() > 4)
                tag.raw_data.push_back(line.substr(4));
            else
                tag.raw_data.push_back(line);
        }
        TransportEndpoint ep;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ep = connection_.endpoint;
        }
        SavedRecord record;
        record.meta.created_at     = iso8601_now();
        record.meta.record_id      = std::string("emu_dump_") + to_string(protocol)
                                     + "_" + std::to_string(slot)
                                     + "_" + record.meta.created_at;
        record.meta.display_name   = std::string("EMU ") + to_string(protocol)
                                     + " Slot" + std::to_string(slot);
        record.meta.source         = "emu_download";
        record.meta.transport      = ep.kind;
        record.meta.transport_path = ep.path;
        record.tag = tag;
        return storage_.save_record(record, err);
    }

    // For I2C emulation devices (GroveNFC / NFC Unit):
    // build an on-screen dump cache from the selected local slot payload,
    // so UI can keep the same Download -> Save Dump flow as PN532Killer.
    bool cache_i2c_slot_dump(ProtocolKind protocol, int slot, std::string *err = nullptr)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!connection_.connected || connection_.endpoint.kind != TransportKind::I2cBus) {
            if (err) *err = "I2C device not connected";
            return false;
        }
        const auto slots = protocol_slots_padded_locked(protocol);
        if (slot < 0 || slot >= static_cast<int>(slots.size())) {
            if (err) *err = "Invalid slot";
            return false;
        }
        const auto &slot_data = slots[slot].raw_data;
        if (slot_data.empty()) {
            if (err) *err = "Selected slot has no payload";
            return false;
        }

        std::vector<std::string> dump_lines;
        dump_lines.reserve(slot_data.size());

        for (size_t i = 0; i < slot_data.size(); ++i) {
            const std::string &line = slot_data[i];
            if (line.size() >= 3 && line[2] == ':') {
                dump_lines.push_back(line);
                continue;
            }
            char prefix[8];
            std::snprintf(prefix, sizeof(prefix), "%02d:", static_cast<int>(i));
            dump_lines.push_back(std::string(prefix) + line);
        }

        auto &cache = emu_slot_cache_[{protocol, slot}];
        cache.probed = true;
        cache.dump_lines = std::move(dump_lines);
        cache.dump_loaded = true;

        if (cache.uid.empty() && !cache.dump_lines.empty()) {
            const std::string first = cache.dump_lines.front();
            if (first.size() > 3) cache.uid = first.substr(3, std::min<size_t>(14, first.size() - 3));
        }
        if (err) err->clear();
        return true;
    }

private:
    static bool parse_hex_bytes(const std::string &value, std::vector<uint8_t> *out)
    {
        if (!out) return false;
        std::string hex;
        hex.reserve(value.size());
        for (char ch : value) {
            if (std::isxdigit(static_cast<unsigned char>(ch))) {
                hex.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
            }
        }
        if (hex.empty() || (hex.size() % 2) != 0) return false;

        out->clear();
        out->reserve(hex.size() / 2);
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            const std::string byte_str = hex.substr(i, 2);
            out->push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
        }
        return true;
    }

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
        NfcHexLog::get().log_event("scan", "start scan");
        auto equals_ci = [](const std::string &a, const char *b) {
            if (!b || a.size() != std::strlen(b)) return false;
            for (size_t i = 0; i < a.size(); ++i) {
                const char ca = static_cast<char>(std::toupper(static_cast<unsigned char>(a[i])));
                const char cb = static_cast<char>(std::toupper(static_cast<unsigned char>(b[i])));
                if (ca != cb) return false;
            }
            return true;
        };

        auto to_upper = [](std::string s) {
            for (char &ch : s) {
                ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
            }
            return s;
        };

        auto normalize_identity_hex = [&](std::string value) {
            value = to_upper(std::move(value));
            std::string out;
            out.reserve(value.size());
            for (char ch : value) {
                if (std::isxdigit(static_cast<unsigned char>(ch))) out.push_back(ch);
            }
            return out;
        };

        auto find_identity = [&](const TagInfo &tag, const char *key) -> std::string {
            for (const auto &kv : tag.identity_fields) {
                if (equals_ci(kv.first, key)) return kv.second;
            }
            return {};
        };

        auto extract_detail_field_hex = [&](const std::string &detail, const char *key) -> std::string {
            if (!key || !*key || detail.empty()) return {};
            const std::string key_token = std::string(key) + ":";
            const std::string detail_up = to_upper(detail);
            const size_t pos = detail_up.find(to_upper(key_token));
            if (pos == std::string::npos) return {};
            size_t start = pos + key_token.size();
            while (start < detail_up.size() && std::isspace(static_cast<unsigned char>(detail_up[start]))) ++start;
            std::string out;
            while (start < detail_up.size()) {
                const char ch = detail_up[start];
                if (!std::isxdigit(static_cast<unsigned char>(ch))) break;
                out.push_back(ch);
                ++start;
            }
            return out;
        };

        auto emit_scan_summary = [&](const std::string &protocol,
                                     const std::string &uid,
                                     const std::string &type,
                                     const std::string &atqa,
                                     const std::string &sak,
                                     const std::string &magic_type) {
            push_log("Result: Tag Found");
            push_log(std::string("Protocol: ") + protocol);
            push_log("UID: " + uid);
            if (!type.empty()) push_log("Type: " + type);

            const std::string atqa_norm = normalize_identity_hex(atqa);
            const std::string sak_norm = normalize_identity_hex(sak);
            push_log(std::string("ATQA: ") + (atqa_norm.empty() ? "-" : atqa_norm));
            push_log(std::string("SAK: ") + (sak_norm.empty() ? "-" : sak_norm));

            std::string type_up = to_upper(type);
            std::string proto_up = to_upper(protocol);
            const bool is_mfc_family =
                (type_up.find("MIFARE CLASSIC") != std::string::npos) ||
                (type_up.find("MFC1K") != std::string::npos) ||
                (type_up.find("MFC4K") != std::string::npos) ||
                (type_up.find("MFCMINI") != std::string::npos) ||
                (sak_norm == "08" || sak_norm == "09" || sak_norm == "18" ||
                 sak_norm == "28" || sak_norm == "38") ||
                ((proto_up.find("MIFARE") != std::string::npos || proto_up.find("MFC") != std::string::npos) &&
                 (type_up.find("1K") != std::string::npos ||
                  type_up.find("4K") != std::string::npos ||
                  type_up.find("MINI") != std::string::npos));
            if (is_mfc_family) {
                push_log(std::string("MAGIC: ") + (magic_type.empty() ? "Normal" : magic_type));
            }
        };

        auto emit_scan_tail = [&]() {
            push_log("=====================");
        };

        // Snapshot connection under lock, then release so UI can call scan_state() freely.
        TransportEndpoint endpoint;
        DeviceKind device_kind = DeviceKind::Unknown;
        INfcTransport *transport_raw = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            endpoint    = connection_.endpoint;
            device_kind = connection_.device_kind;
            transport_raw = transport_.get();
        }

        SavedRecord record;
        std::string error;
        bool success = false;

        if (endpoint.kind == TransportKind::I2cBus) {
            I2cGroveNfcDevice *dev = nullptr;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                dev = i2c_device_.get();
            }
            if (!dev || !dev->is_open()) {
                std::lock_guard<std::mutex> lock(mutex_);
                scan_.running = false;
                scan_.status = "I2C device not open";
                scan_.error = "No I2C device";
                return;
            }
            push_log("> Scanning I2C NFC...");
            I2cCardInfo card;
            const bool card_ok = dev->readCard(card);
            if (card_ok && card.valid) {
                TagInfo tag;
                std::string uid_norm;
                uid_norm.reserve(card.uid.size());
                for (char ch : card.uid) {
                    if (std::isxdigit(static_cast<unsigned char>(ch))) {
                        uid_norm.push_back(static_cast<char>(
                            std::toupper(static_cast<unsigned char>(ch))));
                    }
                }
                tag.uid = uid_norm.empty() ? card.uid : uid_norm;
                tag.protocol = i2c_protocol_to_kind(card.protocol);
                tag.tag_type = i2c_protocol_to_tag_type(card.protocol);
                tag.magic_type = card.magic_type;
                tag.raw_data.clear();
                if (!card.atqa_hex.empty()) tag.identity_fields["ATQA"] = card.atqa_hex;
                if (!card.sak_hex.empty()) tag.identity_fields["SAK"] = card.sak_hex;

                const std::string detail_atqa = !card.atqa_hex.empty()
                    ? card.atqa_hex : extract_detail_field_hex(card.detail, "ATQA");
                const std::string detail_sak = !card.sak_hex.empty()
                    ? card.sak_hex : extract_detail_field_hex(card.detail, "SAK");
                emit_scan_summary(to_string(tag.protocol),
                                  tag.uid,
                                  tag.tag_type,
                                  detail_atqa,
                                  detail_sak,
                                  tag.magic_type);
                emit_scan_tail();

                const std::string src = dev->is_nfc_unit() ? "nfc_unit" : "grovenfc";
                record = make_record_from_tag(tag, endpoint, false, src);
                success = true;
            } else {
                push_log("No card detected");
                emit_scan_tail();
                error = card_ok ? "no card present" : card.detail;
            }
            std::lock_guard<std::mutex> lock(mutex_);
            scan_.running = false;
            scan_.last_record = record;
            scan_.has_result = success;
            scan_.status = success ? "Card found" : "No card";
            scan_.error = error;
            return;
        }

        if (endpoint.kind == TransportKind::Mock) {
            record = build_mock_record(endpoint);
            const std::string atqa = find_identity(record.tag, "ATQA");
            const std::string sak = find_identity(record.tag, "SAK");
            emit_scan_summary(to_string(record.tag.protocol),
                              record.tag.uid,
                              record.tag.tag_type,
                              atqa,
                              sak,
                              record.tag.magic_type);
            emit_scan_tail();
            success = true;
        } else {
            if (!transport_raw) {
                std::lock_guard<std::mutex> lock(mutex_);
                scan_.running = false;
                scan_.status = "No transport";
                scan_.error = "Transport lost during scan";
                return;
            }

            // All I/O done WITHOUT holding mutex_ so UI thread can call scan_state() freely.
            Pn532KillerClient client(transport_raw);

            // For PN532Killer, InListPassiveTarget may return instantly (~50ms) with
            // "no passive target found" because the firmware ignores MxRtyPassiveActivation.
            // Poll for up to 4 seconds (matching nfc-usb-test behaviour) so the user
            // has time to place the card after pressing the scan button.
            // For plain PN532, set_rf_passive_retries(0x20) is configured during
            // detect_device, so each call already waits ~820ms – one call is enough.
            TagInfo tag;
            bool real_ok = false;
            push_log("> Detecting card...");
            {
                auto deadline = std::chrono::steady_clock::now()
                                + std::chrono::seconds(4);
                while (!real_ok && std::chrono::steady_clock::now() < deadline) {
                    tag = TagInfo{};
                    real_ok = client.in_list_passive_target_iso14443a(&tag, &error);
                    if (!real_ok)
                        std::this_thread::sleep_for(std::chrono::milliseconds(150));
                }
            }
            // For PN532Killer: also try ISO15693 if 14A found nothing.
            if (!real_ok && device_kind == DeviceKind::PN532Killer) {
                push_log("> Trying ISO15693...");
                std::string err15;
                tag = TagInfo{};
                real_ok = client.in_list_passive_target_iso15693(&tag, &err15);
                if (!real_ok) error = err15;
            }
            if (real_ok) {
                auto is_mfc_like = [&]() {
                    if (tag.protocol == ProtocolKind::MifareClassic) return true;
                    const std::string type_up = to_upper(tag.tag_type);
                    if (type_up.find("MIFARE CLASSIC") != std::string::npos) return true;
                    std::string sak = normalize_identity_hex(find_identity(tag, "SAK"));
                    if (sak.size() >= 2) {
                        if (sak == "08" || sak == "09" || sak == "18" ||
                            sak == "28" || sak == "38") return true;
                    }
                    return false;
                };

                const bool can_magic_probe = is_mfc_like();

                if (can_magic_probe) {
                    std::string magic_err;
                    // Probe Gen3 first to avoid redundant HALT(0x50 0x00) on Gen3 cards.
                    if (client.is_gen3(&magic_err, &tag)) {
                        tag.magic_type = "Gen3";
                    } else if (client.is_gen1a(&magic_err)) {
                        tag.magic_type = "Gen1A";
                    } else if (client.is_gen4("00000000", &magic_err)) {
                        tag.magic_type = "Gen4";
                    } else {
                        // Explicitly mark MFC cards as Normal when all magic probes fail,
                        // so UI always shows a MAGIC line under SAK.
                        tag.magic_type = "Normal";
                    }
                }

                const std::string atqa = find_identity(tag, "ATQA");
                const std::string sak = find_identity(tag, "SAK");
                emit_scan_summary(to_string(tag.protocol),
                                  tag.uid,
                                  tag.tag_type,
                                  atqa,
                                  sak,
                                  tag.magic_type);

                for (const auto &kv : tag.identity_fields) {
                    if (equals_ci(kv.first, "ATQA") || equals_ci(kv.first, "SAK") ||
                        equals_ci(kv.first, "UID_LEN") || equals_ci(kv.first, "UIDLEN")) continue;
                    push_log("  " + kv.first + ": " + kv.second);
                }
                emit_scan_tail();
                client.release_target_if_listed();
            } else {
                push_log(std::string("ERR ") + (error.empty() ? "no card" : error.substr(0, 22)));
                emit_scan_tail();
            }

            if (real_ok) {
                const std::string scan_source =
                    (device_kind == DeviceKind::PN532Killer) ? "pn532killer" :
                    (device_kind == DeviceKind::PN532)       ? "pn532"       : "nfc";
                record = make_record_from_tag(tag, endpoint, false, scan_source);
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

    void perform_dump_from_last_scan()
    {
        NfcHexLog::get().log_event("dump", "start dump from last scan");

        TransportEndpoint endpoint;
        DeviceKind device_kind = DeviceKind::Unknown;
        INfcTransport *transport_raw = nullptr;
        I2cGroveNfcDevice *i2c_dev = nullptr;
        SavedRecord base_record;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            endpoint = connection_.endpoint;
            device_kind = connection_.device_kind;
            transport_raw = transport_.get();
            i2c_dev = i2c_device_.get();
            base_record = scan_.last_record;
        }

        SavedRecord record = base_record;
        record.tag.raw_data.clear();
        record.tag.block_log.clear();
        record.mifare_dump.reset();

        std::string error;
        bool success = false;

        auto emit_dump_lines = [this](const std::vector<std::string> &lines) {
            for (const auto &line : lines) push_log(line);
        };

        auto to_upper_copy = [](std::string s) {
            for (char &ch : s) {
                ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
            }
            return s;
        };

        auto normalize_hex = [&](std::string value) {
            value = to_upper_copy(std::move(value));
            std::string out;
            out.reserve(value.size());
            for (char ch : value) {
                if (std::isxdigit(static_cast<unsigned char>(ch))) out.push_back(ch);
            }
            return out;
        };

        auto find_identity_field = [&](const TagInfo &tag, const char *key) -> std::string {
            if (!key || !*key) return {};
            const std::string key_up = to_upper_copy(key);
            for (const auto &kv : tag.identity_fields) {
                if (to_upper_copy(kv.first) == key_up) return kv.second;
            }
            return {};
        };

        auto is_mfc_family = [&](const TagInfo &tag) {
            if (tag.protocol == ProtocolKind::MifareClassic) return true;
            const std::string type_up = to_upper_copy(tag.tag_type);
            if (type_up.find("MIFARE CLASSIC") != std::string::npos) return true;
            if (type_up.find(" S20") != std::string::npos || type_up.find(" S50") != std::string::npos ||
                type_up.find(" S70") != std::string::npos) return true;
            const std::string sak = normalize_hex(find_identity_field(tag, "SAK"));
            return (sak == "08" || sak == "09" || sak == "18" || sak == "28" || sak == "38");
        };

        auto is_desfire_family = [&](const TagInfo &tag) {
            const std::string type_up = to_upper_copy(tag.tag_type);
            if (type_up.find("DESFIRE") != std::string::npos) return true;
            const std::string sak = normalize_hex(find_identity_field(tag, "SAK"));
            return sak == "20";
        };

        auto emit_desfire_info_only = [&](SavedRecord &target_record) {
            push_log("> MIFARE DESFire detected");
            push_log("> Info-only mode (dump not supported)");
            const std::string uid = target_record.tag.uid.empty() ? "-" : target_record.tag.uid;
            const std::string atqa = normalize_hex(find_identity_field(target_record.tag, "ATQA"));
            const std::string sak = normalize_hex(find_identity_field(target_record.tag, "SAK"));

            std::vector<std::string> info_lines;
            info_lines.push_back(std::string("Type:") +
                                 (target_record.tag.tag_type.empty() ? "MIFARE DESFire"
                                                                     : target_record.tag.tag_type));
            info_lines.push_back(std::string("UID:") + uid);
            info_lines.push_back(std::string("ATQA:") + (atqa.empty() ? "-" : atqa));
            info_lines.push_back(std::string("SAK:") + (sak.empty() ? "-" : sak));
            info_lines.push_back("DESFire dump is not supported yet.");

            emit_dump_lines(info_lines);
            target_record.tag.raw_data = info_lines;
        };

        if (endpoint.kind == TransportKind::I2cBus) {
            if (!i2c_dev || !i2c_dev->is_open()) {
                error = "I2C device not open";
                push_log(std::string("ERR ") + error);
            } else {
                ProtocolKind dump_protocol = record.tag.protocol;
                if (dump_protocol == ProtocolKind::Iso14443A) {
                    if (is_desfire_family(record.tag)) {
                        emit_desfire_info_only(record);
                        success = true;
                    } else if (is_mfc_family(record.tag)) {
                        dump_protocol = ProtocolKind::MifareClassic;
                        record.tag.protocol = ProtocolKind::MifareClassic;
                        if (record.tag.tag_type.empty()) record.tag.tag_type = "MIFARE Classic";
                    }
                }

                const bool is_mfc = (dump_protocol == ProtocolKind::MifareClassic);
                if (!success) {
                    push_log(std::string("> Dumping I2C ") + (is_mfc ? "MFC" :
                        (dump_protocol == ProtocolKind::Iso15693 ? "ISO15693" : "MFU/NTAG")) + "...");
                }

                std::vector<std::string> mfc_default_keys;
                if (!success && is_mfc) {
                    std::set<std::string> uniq;
                    auto append_key = [&](const std::string &raw_hex) {
                        std::string key;
                        key.reserve(12);
                        for (char c : raw_hex) {
                            if (std::isxdigit(static_cast<unsigned char>(c))) {
                                key.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
                                if (key.size() == 12) break;
                            }
                        }
                        if (key.size() != 12) return;
                        if (uniq.insert(key).second) mfc_default_keys.push_back(key);
                    };

                    const auto json_keys = storage_.load_mifare_keys();
                    for (const auto &k : json_keys) {
                        if (!k.enabled) continue;
                        append_key(k.key_hex);
                    }

                    const auto key_files = storage_.list_key_files();
                    for (const auto &fn : key_files) {
                        const auto file_keys = storage_.load_key_file(fn);
                        for (const auto &k : file_keys) append_key(k);
                    }

                    char key_msg[48];
                    std::snprintf(key_msg, sizeof(key_msg), "MFC keys loaded: %d", static_cast<int>(mfc_default_keys.size()));
                    push_log(key_msg);
                }

                std::vector<std::string> dump_lines;
                std::string i2c_magic_type;
                std::string dump_err;
                if (!success && i2c_dev->dumpCard(dump_protocol,
                                                  record.tag.uid,
                                                  record.tag.tag_type,
                                                  is_mfc ? &mfc_default_keys : nullptr,
                                                  &i2c_magic_type,
                                                  dump_lines,
                                                  &dump_err)) {
                    record.tag.protocol = dump_protocol;
                    record.tag.raw_data = dump_lines;
                    if (!i2c_magic_type.empty()) {
                        record.tag.magic_type = i2c_magic_type;
                        push_log(std::string("MAGIC: ") + i2c_magic_type);
                    }

                    if (dump_protocol == ProtocolKind::MifareClassic) {
                        record.mifare_dump = MifareClassicDump{};
                        const int block_count = static_cast<int>(dump_lines.size());
                        record.mifare_dump->block_count = block_count;
                        record.mifare_dump->sector_count = (block_count >= 256) ? 40 :
                                                           (block_count >= 64)  ? 16 :
                                                           (block_count >= 20)  ? 5 : 0;
                        record.mifare_dump->blocks_hex = dump_lines;
                        record.mifare_dump->attack.method = AttackMethod::DefaultKeys;
                        record.mifare_dump->attack.status = AttackStatus::Success;
                        record.mifare_dump->attack.dump_obtained = !dump_lines.empty();
                        emit_dump_lines(dump_lines);
                    } else {
                        emit_dump_lines(dump_lines);
                    }

                    push_log("Tip: Press Ctrl+S to save dump.");
                    success = !record.tag.raw_data.empty();
                } else if (!success) {
                    error = dump_err.empty() ? "I2C dump failed" : dump_err;
                    push_log(std::string("ERR ") + error);
                }
            }
        } else if (endpoint.kind == TransportKind::Mock) {
            record = build_mock_record(endpoint);
            success = true;
        } else {
            if (!transport_raw) {
                error = "Transport lost during dump";
                push_log(std::string("ERR ") + error);
            } else {
                Pn532KillerClient client(transport_raw);
                TagInfo live_tag;
                bool card_ok = false;

                push_log("> Detecting card for dump...");
                if (base_record.tag.protocol == ProtocolKind::Iso15693) {
                    card_ok = client.in_list_passive_target_iso15693(&live_tag, &error);
                } else {
                    card_ok = client.in_list_passive_target_iso14443a(&live_tag, &error);
                }

                auto bytes_to_hex = [](const std::vector<uint8_t> &bytes) {
                    std::string out;
                    out.reserve(bytes.size() * 2);
                    char hb[3];
                    for (uint8_t byte : bytes) {
                        std::snprintf(hb, sizeof(hb), "%02X", byte);
                        out += hb;
                    }
                    return out;
                };

                if (!card_ok) {
                    push_log(std::string("ERR ") + (error.empty() ? "no card" : error));
                } else {
                    const bool same_or_compatible_protocol =
                        (live_tag.protocol == base_record.tag.protocol) ||
                        ((live_tag.protocol == ProtocolKind::Iso14443A || live_tag.protocol == ProtocolKind::MifareClassic) &&
                         (base_record.tag.protocol == ProtocolKind::Iso14443A || base_record.tag.protocol == ProtocolKind::MifareClassic));
                    if (!same_or_compatible_protocol) {
                        error = "Card type mismatch, rescan card";
                        push_log(std::string("ERR ") + error);
                    } else {
                        record.tag.uid = live_tag.uid;
                        if (live_tag.protocol != ProtocolKind::Unknown)
                            record.tag.protocol = live_tag.protocol;
                        if (!live_tag.tag_type.empty()) record.tag.tag_type = live_tag.tag_type;
                        if (!live_tag.identity_fields.empty())
                            record.tag.identity_fields = live_tag.identity_fields;

                        bool handled = false;
                        if (record.tag.protocol == ProtocolKind::Iso14443A &&
                            is_desfire_family(record.tag)) {
                            emit_desfire_info_only(record);
                            success = true;
                            handled = true;
                        }

                        if (!handled && record.tag.protocol == ProtocolKind::Iso14443A &&
                            (base_record.tag.protocol == ProtocolKind::MifareClassic || is_mfc_family(record.tag))) {
                            record.tag.protocol = ProtocolKind::MifareClassic;
                            if (to_upper_copy(record.tag.tag_type).find("MIFARE CLASSIC") == std::string::npos &&
                                !base_record.tag.tag_type.empty()) {
                                record.tag.tag_type = base_record.tag.tag_type;
                            }
                            handled = false;
                        }

                        if (!handled && record.tag.protocol == ProtocolKind::Iso15693) {
                            if (device_kind == DeviceKind::PN532) {
                                error = "PN532 ISO15693 read not supported";
                                push_log(std::string("ERR ") + error);
                            } else {
                            push_log("> Dumping ISO15693 blocks...");
                            std::vector<std::vector<uint8_t>> blocks;
                            std::string dump_err;
                            if (client.iso15693_read_all_blocks(&blocks, &dump_err, nullptr)) {
                                std::vector<std::string> dump_lines;
                                dump_lines.reserve(blocks.size());
                                for (size_t i = 0; i < blocks.size(); ++i) {
                                    char prefix[8];
                                    std::snprintf(prefix, sizeof(prefix), "%02d:", static_cast<int>(i));
                                    const std::string line = std::string(prefix) + bytes_to_hex(blocks[i]);
                                    dump_lines.push_back(line);
                                    record.tag.raw_data.push_back(line);
                                }
                                emit_dump_lines(dump_lines);
                                push_log("Tip: Press Ctrl+S to save dump.");
                                success = !record.tag.raw_data.empty();
                            } else {
                                error = dump_err.empty() ? "ISO15693 dump failed" : dump_err;
                                push_log(std::string("ERR ") + error);
                            }
                            }
                        } else if (!handled && record.tag.protocol == ProtocolKind::Iso14443A) {
                            push_log("> Dumping NTAG/Ultralight pages...");
                            std::vector<std::vector<uint8_t>> pages;
                            std::string ntag_type;
                            std::string dump_err;
                            if (client.ntag_read_all_pages(&pages, &ntag_type, &dump_err, nullptr)) {
                                if (!ntag_type.empty()) record.tag.tag_type = ntag_type;
                                std::vector<std::string> dump_lines;
                                dump_lines.reserve(pages.size());
                                for (size_t i = 0; i < pages.size(); ++i) {
                                    char prefix[8];
                                    std::snprintf(prefix, sizeof(prefix), "%02d:", static_cast<int>(i));
                                    const std::string line = std::string(prefix) + bytes_to_hex(pages[i]);
                                    dump_lines.push_back(line);
                                    record.tag.raw_data.push_back(line);
                                }
                                emit_dump_lines(dump_lines);
                                if (static_cast<int>(dump_lines.size()) > 24)
                                    push_log("Tip: Press Ctrl+S to save dump.");
                                success = !record.tag.raw_data.empty();
                            } else {
                                error = dump_err.empty() ? "NTAG dump failed" : dump_err;
                                push_log(std::string("ERR ") + error);
                            }
                        } else if (!handled && record.tag.protocol == ProtocolKind::MifareClassic) {
                            std::vector<std::string> mfc_blocks;
                            bool mfc_read_ok = false;
                            const int sc = (record.tag.tag_type.find("4K") != std::string::npos) ? 40 : 16;

                            if (device_kind == DeviceKind::PN532 ||
                                device_kind == DeviceKind::PN532Killer) {
                                std::string magic_err;
                                // Keep the same probe order as scan path to reduce duplicate HALT logs.
                                if (client.is_gen3(&magic_err, &live_tag)) {
                                    record.tag.magic_type = "Gen3";
                                    push_log("MAGIC: Gen3");
                                } else if (client.is_gen1a(&magic_err)) {
                                    record.tag.magic_type = "Gen1A";
                                    push_log("MAGIC: Gen1A");
                                    push_log("> Reading Gen1A blocks...");
                                    client.read_gen1a_full(nullptr, &record.tag.block_log, &magic_err,
                                        [this](const std::string &line) { push_log(line); },
                                        (device_kind == DeviceKind::PN532Killer) ? 5 : 0);
                                } else if (client.is_gen4("00000000", &magic_err)) {
                                    record.tag.magic_type = "Gen4";
                                    push_log("MAGIC: Gen4");
                                }
                            }

                            if (record.tag.magic_type.empty() || record.tag.magic_type == "Gen3" ||
                                record.tag.magic_type == "Gen4") {
                                push_log("> Reading MFC blocks (default keys)...");
                                std::vector<uint8_t> uid_bytes;
                                for (size_t i = 0; i + 1 < live_tag.uid.size(); i += 2) {
                                    uid_bytes.push_back(static_cast<uint8_t>(
                                        std::stoi(live_tag.uid.substr(i, 2), nullptr, 16)));
                                }
                                std::string mfc_err;
                                mfc_read_ok = client.read_mifare_standard(uid_bytes, sc, &mfc_blocks, &mfc_err,
                                    [this](const std::string &line) { push_log(line); });
                                if (!mfc_read_ok && !mfc_err.empty()) error = mfc_err;
                            }

                            record.mifare_dump = MifareClassicDump{};
                            record.mifare_dump->sector_count = sc;
                            record.mifare_dump->block_count = (sc <= 32) ? sc * 4 : 32 * 4 + (sc - 32) * 16;

                            if (mfc_read_ok) {
                                record.mifare_dump->blocks_hex = mfc_blocks;
                                record.mifare_dump->attack.method = AttackMethod::DefaultKeys;
                                record.mifare_dump->attack.status = AttackStatus::Success;
                                record.mifare_dump->attack.dump_obtained = true;
                                record.tag.raw_data = mfc_blocks;
                                success = true;
                            } else if (!record.tag.block_log.empty()) {
                                record.mifare_dump->blocks_hex.assign(record.mifare_dump->block_count, "");
                                for (const auto &line : record.tag.block_log) {
                                    if (line.size() >= 4 && line[2] == ':') {
                                        const int blk = std::stoi(line.substr(0, 2), nullptr, 10);
                                        if (blk >= 0 && blk < record.mifare_dump->block_count)
                                            record.mifare_dump->blocks_hex[blk] = line.substr(3);
                                    }
                                }
                                record.mifare_dump->attack.method = AttackMethod::None;
                                record.mifare_dump->attack.status = AttackStatus::Success;
                                record.mifare_dump->attack.dump_obtained = true;
                                record.tag.raw_data = record.mifare_dump->blocks_hex;
                                success = true;
                            } else {
                                if (error.empty()) error = "Mifare dump failed";
                                record.mifare_dump->attack.status = AttackStatus::Failed;
                                record.mifare_dump->attack.reason = error;
                                push_log(std::string("ERR ") + error);
                            }
                        } else if (!handled) {
                            error = "Unsupported protocol for dump";
                            push_log(std::string("ERR ") + error);
                        }
                    }
                }

                client.release_target_if_listed();
            }
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            scan_.running = false;
            scan_.has_result = true;
            if (success) {
                scan_.last_record = record;
                scan_.status = "Dump ready";
                scan_.error.clear();
                last_dump_success_ = true;
            } else {
                scan_.last_record = base_record;
                scan_.status = "Dump failed";
                scan_.error = error.empty() ? "dump failed" : error;
                last_dump_success_ = false;
            }
        }
    }

    static std::vector<uint8_t> build_ndef_message_from_uri(const std::string &uri)
    {
        auto starts_with = [](const std::string &s, const char *prefix) {
            return s.rfind(prefix, 0) == 0;
        };

        std::vector<uint8_t> record;
        if (starts_with(uri, "https://") || starts_with(uri, "http://") ||
            starts_with(uri, "tel:") || starts_with(uri, "mailto:")) {
            uint8_t prefix = 0x00;
            std::string rest = uri;
            if (starts_with(uri, "http://www.")) {
                prefix = 0x01;
                rest = uri.substr(11);
            } else if (starts_with(uri, "https://www.")) {
                prefix = 0x02;
                rest = uri.substr(12);
            } else if (starts_with(uri, "http://")) {
                prefix = 0x03;
                rest = uri.substr(7);
            } else if (starts_with(uri, "https://")) {
                prefix = 0x04;
                rest = uri.substr(8);
            } else if (starts_with(uri, "tel:")) {
                prefix = 0x05;
                rest = uri.substr(4);
            } else if (starts_with(uri, "mailto:")) {
                prefix = 0x06;
                rest = uri.substr(7);
            }

            std::vector<uint8_t> payload;
            payload.reserve(rest.size() + 1);
            payload.push_back(prefix);
            payload.insert(payload.end(), rest.begin(), rest.end());

            record = {0xD1, 0x01, static_cast<uint8_t>(payload.size()), 0x55};
            record.insert(record.end(), payload.begin(), payload.end());
        } else {
            std::vector<uint8_t> payload = {0x02, 0x65, 0x6E};
            payload.insert(payload.end(), uri.begin(), uri.end());
            record = {0xD1, 0x01, static_cast<uint8_t>(payload.size()), 0x54};
            record.insert(record.end(), payload.begin(), payload.end());
        }

        std::vector<uint8_t> out;
        const uint16_t ndef_len = static_cast<uint16_t>(record.size());
        out.push_back(static_cast<uint8_t>((ndef_len >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(ndef_len & 0xFF));
        out.insert(out.end(), record.begin(), record.end());
        return out;
    }

    void perform_pn532_ndef_emulation(const std::string &uri)
    {
        INfcTransport *transport_raw = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
            pn532_ndef_.status = "Initializing";
            pn532_ndef_.error.clear();
        }
        if (!transport_raw || !transport_raw->is_open()) {
            std::lock_guard<std::mutex> lock(mutex_);
            pn532_ndef_.running = false;
            pn532_ndef_.status = "Init failed";
            pn532_ndef_.error = "Transport not available";
            return;
        }

        // Target mode exchanges must be exclusive on the transport.
        std::lock_guard<std::mutex> op_lock(transport_op_mutex_);

        Pn532KillerClient client(transport_raw);
        const std::vector<uint8_t> tg_init_cfg = {
            0x04, 0x08, 0x00, 0x11, 0x22, 0x33, 0x60, 0x01, 0xFE, 0xA2,
            0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4,
            0xC5, 0xC6, 0xC7, 0xFF, 0xFF, 0xAA, 0x99, 0x88, 0x77, 0x66,
            0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00
        };

        bool init_ok = false;
        std::string init_err;
        for (int attempt = 0; attempt < 8 && !cancel_pn532_ndef_.load(); ++attempt) {
            client.send_wakeup();
            client.sam_configuration(nullptr);
            std::vector<uint8_t> init_resp;
            if (client.tg_init_as_target(tg_init_cfg, &init_resp, &init_err)) {
                init_ok = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(120));
        }

        if (!init_ok) {
            std::lock_guard<std::mutex> lock(mutex_);
            pn532_ndef_.running = false;
            pn532_ndef_.status = "Init failed";
            pn532_ndef_.error = init_err.empty() ? "TgInitAsTarget failed" : init_err;
            return;
        }

        const std::vector<uint8_t> cc = {
            0x00, 0x0F, 0x20, 0x00, 0x54, 0x00, 0xFF, 0x04,
            0x06, 0xE1, 0x04, 0x00, 0xFF, 0x00, 0x00
        };
        const std::vector<uint8_t> ndef = build_ndef_message_from_uri(uri);

        enum class TagFile { None, CC, Ndef };
        TagFile current_file = TagFile::None;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            pn532_ndef_.status = "Emulating";
            pn532_ndef_.error.clear();
        }

        while (!cancel_pn532_ndef_.load()) {
            std::vector<uint8_t> req;
            std::string req_err;
            if (!client.tg_get_data(&req, &req_err)) {
                if (!req_err.empty()) {
                    std::lock_guard<std::mutex> lock(mutex_);
                    pn532_ndef_.error = req_err;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(30));
                continue;
            }
            if (req.empty()) continue;

            const uint8_t tg_status = req[0];
            if (tg_status == 0x29 || tg_status == 0x25) {
                std::vector<uint8_t> init_resp;
                client.tg_init_as_target(tg_init_cfg, &init_resp, nullptr);
                current_file = TagFile::None;
                continue;
            }

            if (req.size() < 6) continue;
            std::vector<uint8_t> apdu(req.begin() + 1, req.end());
            if (apdu.size() < 5) continue;

            const uint8_t ins = apdu[1];
            const uint8_t p1 = apdu[2];
            const uint8_t p2 = apdu[3];
            const uint8_t lc = apdu[4];
            std::vector<uint8_t> rsp;

            // ISO7816 constants used by Bruce's PN532 NDEF emulation flow.
            constexpr uint8_t INS_SELECT_FILE = 0xA4;
            constexpr uint8_t INS_READ_BINARY = 0xB0;
            constexpr uint8_t INS_UPDATE_BINARY = 0xD6;
            constexpr uint8_t SW1_OK = 0x90;
            constexpr uint8_t SW2_OK = 0x00;
            constexpr uint8_t SW1_NF = 0x6A;
            constexpr uint8_t SW2_NF = 0x82;

            if (ins == INS_SELECT_FILE) {
                if (p1 == 0x00) { // select by id
                    if (p2 != 0x0C) {
                        rsp = {SW1_OK, SW2_OK};
                    } else if (lc == 0x02 && apdu.size() >= 7 && apdu[5] == 0xE1 &&
                               (apdu[6] == 0x03 || apdu[6] == 0x04)) {
                        current_file = (apdu[6] == 0x03) ? TagFile::CC : TagFile::Ndef;
                        rsp = {SW1_OK, SW2_OK};
                    } else {
                        rsp = {SW1_NF, SW2_NF};
                    }
                } else if (p1 == 0x04) { // select by AID
                    rsp = {SW1_OK, SW2_OK};
                } else {
                    rsp = {SW1_NF, SW2_NF};
                }
            } else if (ins == INS_READ_BINARY) {
                const uint16_t offset = static_cast<uint16_t>((p1 << 8) | p2);
                const uint8_t le = lc;
                if (current_file == TagFile::CC) {
                    if (offset + le <= cc.size()) {
                        rsp.insert(rsp.end(), cc.begin() + offset, cc.begin() + offset + le);
                    }
                    rsp.push_back(SW1_OK);
                    rsp.push_back(SW2_OK);
                } else if (current_file == TagFile::Ndef) {
                    if (offset + le <= ndef.size()) {
                        rsp.insert(rsp.end(), ndef.begin() + offset, ndef.begin() + offset + le);
                    }
                    rsp.push_back(SW1_OK);
                    rsp.push_back(SW2_OK);
                } else {
                    rsp = {SW1_NF, SW2_NF};
                }
            } else if (ins == INS_UPDATE_BINARY) {
                rsp = {SW1_OK, SW2_OK};
            } else {
                rsp = {SW1_NF, SW2_NF};
            }

            if (!rsp.empty()) {
                std::string set_err;
                client.tg_set_data(rsp, &set_err);
                if (!set_err.empty()) {
                    std::lock_guard<std::mutex> lock(mutex_);
                    pn532_ndef_.error = set_err;
                }
            }
        }

        client.in_release_all();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            pn532_ndef_.running = false;
            if (pn532_ndef_.status != "Init failed") pn532_ndef_.status = "Stopped";
        }
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
            tag.identity_fields["ATQA"] = "0004";
            tag.identity_fields["SAK"]  = "08";
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
            tag.identity_fields["ATQA"] = "0044";
            tag.identity_fields["SAK"]  = "00";
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
            dump.attack.status = AttackStatus::Success;
            dump.attack.dump_obtained = true;
            // Generate 64 mock blocks of 16 bytes each.
            // Sector trailers (blocks 3,7,11,...,63) use FF..FF key pattern.
            for (int blk = 0; blk < 64; ++blk) {
                char hex[33];
                const bool trailer = ((blk + 1) % 4 == 0);
                if (blk == 0) {
                    // Block 0: UID + manufacturer data
                    std::snprintf(hex, sizeof(hex), "DEADBEEF2108040046494C4C45444B45");
                } else if (trailer) {
                    std::snprintf(hex, sizeof(hex), "FFFFFFFFFFFF078069FFFFFFFFFFFF%02X", blk);
                } else {
                    std::snprintf(hex, sizeof(hex), "000000000000000000000000000000%02X", blk);
                }
                dump.blocks_hex.push_back(hex);
            }
            // Populate raw_data so the Hex Editor shows all 64 blocks.
            record.tag.raw_data = dump.blocks_hex;
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

    // Push a log line from ANY thread without holding mutex_.
    void push_log(const std::string &line)
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        pending_log_lines_.push_back(line);
    }

    mutable std::mutex mutex_;
    mutable std::mutex pending_log_mutex_;          // separate — safe to lock inside scan thread
    std::mutex transport_op_mutex_;                 // serialize all transport write/read cycles
    std::vector<std::string> pending_log_lines_;    // real-time per-block lines, drained by UI
    NfcStorage storage_;
    std::vector<TransportEndpoint> endpoints_;
    int selected_endpoint_ = 0;
    TransportKind intended_kind_ = TransportKind::UsbSerial; // tracks user intent even when no device
    std::unique_ptr<INfcTransport> transport_;
    std::unique_ptr<I2cGroveNfcDevice> i2c_device_;
    ConnectionState connection_;
    ScanState scan_;
    bool last_dump_success_ = false;
    ProtocolKind selected_emulator_protocol_ = ProtocolKind::MifareClassic;
    std::map<ProtocolKind, int> selected_slot_by_protocol_;
    std::map<ProtocolKind, std::vector<EmulatorSlotRecord>> emulator_slots_by_protocol_;
    std::thread scan_thread_;
    std::thread probe_thread_;
    std::thread emu_probe_thread_;
    std::atomic<bool> cancel_emu_probe_{false};
    std::thread emu_dump_thread_;
    std::atomic<bool> cancel_emu_dump_{false};
    std::thread pn532_ndef_thread_;
    std::atomic<bool> cancel_pn532_ndef_{false};
    std::thread hw_upload_thread_;
    std::atomic<bool> cancel_hw_upload_{false};
    std::thread hw_mfkey_thread_;
    std::atomic<bool> cancel_hw_mfkey_{false};
    std::map<std::pair<ProtocolKind,int>, EmuSlotInfo> emu_slot_cache_;
    bool emu_probe_running_ = false;
    bool emu_dump_running_  = false;
    bool hw_upload_running_ = false;
    int  hw_upload_progress_ = 0;   // 0-64 (blocks uploaded so far)
    bool hw_upload_ok_       = false;
    bool hw_mfkey_running_   = false;
    int  hw_mfkey_progress_  = 0;
    std::vector<MfkeyResult> hw_mfkey_results_;
    std::string emu_probe_error_;
    mutable int scan_mock_counter_ = 0;
    std::vector<DeviceProbeResult> probe_results_;
    bool probe_running_ = false;
    UartConfig uart_config_;
    // Async UART test
    std::thread uart_test_thread_;
    bool uart_test_running_ = false;          // guarded by pending_log_mutex_
    std::string uart_test_result_;            // guarded by pending_log_mutex_
    std::vector<std::string> uart_test_log_lines_; // guarded by pending_log_mutex_
    Pn532NdefState pn532_ndef_;

    void finish_uart_test(const std::string &result)
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        uart_test_result_ = result;
        uart_test_running_ = false;
    }

    void perform_emu_slot_probe(ProtocolKind protocol, int slot)
    {
        {
            char msg[64];
            std::snprintf(msg, sizeof(msg), "probe EMU slot %d", slot + 1);
            NfcHexLog::get().log_event("emu-probe", msg);
        }
        INfcTransport *transport_raw = nullptr;
        TransportKind ep_kind = TransportKind::UsbSerial;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
            ep_kind = connection_.endpoint.kind;
        }
        // Serialize all UART/USB operations — prevents interleaving with dump/upload threads
        std::lock_guard<std::mutex> op_lock(transport_op_mutex_);

        EmuSlotInfo info;
        info.probed = true;

        if (transport_raw && transport_raw->is_open()) {
            Pn532KillerClient client(transport_raw);
            const uint8_t type_byte = emu_type_byte(protocol);

            // Switch hardware to this emulator slot and stay in EMU mode.
            std::string sw_err;
            client.set_work_mode(0x02, type_byte, static_cast<uint8_t>(slot), &sw_err);

            // Breakable wait for hardware to stabilize.
            // UART needs more time than USB-CDC for the device to settle after SetWorkMode.
            const int stabilize_ticks = (ep_kind == TransportKind::UartSerial) ? 30 : 15;
            for (int i = 0; i < stabilize_ticks; ++i) {
                if (cancel_emu_probe_.load()) {
                    std::lock_guard<std::mutex> lk(pending_log_mutex_);
                    emu_probe_running_ = false;
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            // Prepare read session; UART requires longer flush before reading.
            client.emu_prepare_read(type_byte, static_cast<uint8_t>(slot));
            std::this_thread::sleep_for(std::chrono::milliseconds(
                (ep_kind == TransportKind::UartSerial) ? 60 : 20));

            if (protocol == ProtocolKind::MifareClassic) {
                // MFC: block0 bytes[0..3] = 4-byte UID; retry up to 3 times on failure
                std::vector<uint8_t> block0;
                for (int retry = 0; retry < 3; ++retry) {
                    if (client.emu_download_block(type_byte, static_cast<uint8_t>(slot), 0, &block0)
                        && block0.size() >= 4) break;
                    block0.clear();
                    std::this_thread::sleep_for(std::chrono::milliseconds(
                        (ep_kind == TransportKind::UartSerial) ? 40 : 10));
                }
                if (block0.size() >= 4) {
                    const size_t n = std::min(block0.size(), size_t{16});
                    char buf[33] = {};
                    for (size_t i = 0; i < n; ++i)
                        snprintf(buf + i * 2, 3, "%02X", block0[i]);
                    info.block0_hex = buf;
                    snprintf(buf, 9, "%02X%02X%02X%02X",
                             block0[0], block0[1], block0[2], block0[3]);
                    info.uid = buf;
                }
            } else if (protocol == ProtocolKind::Iso15693) {
                // ISO15693: UID at special index 0xFE00, 8 bytes reversed
                std::vector<uint8_t> uid_bytes;
                if (client.emu_download_block(type_byte, static_cast<uint8_t>(slot), 0xFE00, &uid_bytes)
                    && uid_bytes.size() >= 8) {
                    char buf[17] = {};
                    // Reversed display: uid_bytes[7..0]
                    for (int i = 7; i >= 0; --i)
                        snprintf(buf + (7 - i) * 2, 3, "%02X", uid_bytes[i]);
                    info.uid = buf;
                }
                // Also read block0 so the right panel can show data before full download.
                std::vector<uint8_t> blk0;
                if (client.emu_download_block(type_byte, static_cast<uint8_t>(slot), 0, &blk0)
                    && !blk0.empty()) {
                    const size_t n = std::min(blk0.size(), size_t{16});
                    char buf[33] = {};
                    for (size_t i = 0; i < n; ++i)
                        snprintf(buf + i * 2, 3, "%02X", blk0[i]);
                    info.block0_hex = buf;
                }
            } else {
                // NTAG/MFU: page0[0..2] + page1[0..3] = 7-byte UID
                std::vector<uint8_t> page0, page1;
                if (client.emu_download_block(type_byte, static_cast<uint8_t>(slot), 0, &page0)
                    && page0.size() >= 4) {
                    char buf[9] = {};
                    for (size_t i = 0; i < 4; ++i)
                        snprintf(buf + i * 2, 3, "%02X", page0[i]);
                    info.block0_hex = buf;  // page0 hex
                }
                if (client.emu_download_block(type_byte, static_cast<uint8_t>(slot), 1, &page1)
                    && page0.size() >= 3 && page1.size() >= 4) {
                    char buf[15] = {};
                    snprintf(buf, 15, "%02X%02X%02X%02X%02X%02X%02X",
                             page0[0], page0[1], page0[2],
                             page1[0], page1[1], page1[2], page1[3]);
                    info.uid = buf;
                }
            }
        }

        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        emu_slot_cache_[{protocol, slot}] = info;
        emu_probe_running_ = false;
    }

    // ── HW Upload (hfmfeload-based): upload a MFC SavedRecord to a HW EMU slot ─
    // Uses setEmulatorData (0x1E): one frame per block + done frame (index=0xFFFF).
    void perform_hw_upload(int slot, SavedRecord record)
    {
        {
            char msg[64];
            std::snprintf(msg, sizeof(msg), "upload to HW slot %d", slot + 1);
            NfcHexLog::get().log_event("upload", msg);
        }
        INfcTransport *transport_raw = nullptr;
        TransportEndpoint endpoint;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
            endpoint      = connection_.endpoint;
        }
        // Serialize all transport operations
        std::lock_guard<std::mutex> op_lock(transport_op_mutex_);

        bool ok = false;
        if (transport_raw && transport_raw->is_open() && record.tag.raw_data.size() == 64) {
            Pn532KillerClient client(transport_raw);
            constexpr uint8_t type_mfc = 1;
            const uint8_t actual_slot = static_cast<uint8_t>(slot);
            const bool is_uart = (endpoint.kind == TransportKind::UartSerial);

            // Do NOT call set_work_mode before uploading.
            // pn532-python hf_mf_load uploads all blocks first, then calls set_work_mode(EMULATOR)
            // after upload_done.  Calling set_work_mode before may cause the device to reject
            // subsequent setEmulatorData frames.

            bool any_fail = false;
            for (int blk = 0; blk < 64; ++blk) {
                if (cancel_hw_upload_.load()) break;
                // Parse hex string to 16 bytes
                const std::string &hex = record.tag.raw_data[static_cast<size_t>(blk)];
                if (hex.size() < 32) { any_fail = true; break; }
                std::vector<uint8_t> data;
                data.reserve(16);
                for (int b = 0; b < 16; ++b) {
                    const char hi = hex[static_cast<size_t>(b * 2)];
                    const char lo = hex[static_cast<size_t>(b * 2 + 1)];
                    auto from_hex = [](char c) -> uint8_t {
                        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
                        if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
                        if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
                        return 0;
                    };
                    data.push_back(static_cast<uint8_t>((from_hex(hi) << 4) | from_hex(lo)));
                }
                // Retry each block up to 3 times to handle UART noise
                bool blk_ok = false;
                for (int retry = 0; retry < 3 && !cancel_hw_upload_.load(); ++retry) {
                    if (client.emu_upload_block(type_mfc, actual_slot,
                                               static_cast<uint16_t>(blk), data)) {
                        blk_ok = true;
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(is_uart ? 20 : 5));
                }
                if (!blk_ok) { any_fail = true; break; }
                {
                    std::lock_guard<std::mutex> lk(pending_log_mutex_);
                    hw_upload_progress_ = blk + 1;
                }
                // UART needs more inter-block gap than USB
                std::this_thread::sleep_for(std::chrono::milliseconds(is_uart ? 20 : 5));
            }
            if (!any_fail && !cancel_hw_upload_.load()) {
                client.emu_upload_done(type_mfc, actual_slot);
                // Switch to emulator mode AFTER uploading (pn532-python hf_mf_load flow:
                // upload_data_block * N -> upload_data_block_done -> set_work_mode EMULATOR).
                std::string sw_err;
                client.set_work_mode(0x02, type_mfc, actual_slot, &sw_err);
                ok = true;
            }
        }

        NfcHexLog::get().log_event("upload", ok ? "upload done OK" : "upload failed");
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        hw_upload_running_  = false;
        hw_upload_ok_       = ok;
    }

    // ── MFKey crack worker ────────────────────────────────────────────────────
    // Fetches sniff nonces from PN532Killer and calls mfkey64/mfkey32v2 binaries.
    void perform_hw_mfkey(bool with_card)
    {
        NfcHexLog::get().log_event(with_card ? "mfkey64" : "mfkey32v2",
                                   with_card ? "start mfkey64" : "start mfkey32v2");
        // Wait for device to finish saving sniffer log after reader-mode switch.
        // Without this delay, GetSnifferLog arrives while device is still committing.
        NfcHexLog::get().log_event(with_card ? "mfkey64" : "mfkey32v2", "waiting for device to save sniff log");
        std::this_thread::sleep_for(std::chrono::milliseconds(600));
        NfcHexLog::get().log_event(with_card ? "mfkey64" : "mfkey32v2", "fetching nonce entries");
        INfcTransport *transport_raw = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
        }
        // Serialize transport access against probe/dump/upload threads
        std::lock_guard<std::mutex> op_lock(transport_op_mutex_);

        std::vector<MfkeyResult> results;

        if (transport_raw && transport_raw->is_open()) {
            Pn532KillerClient client(transport_raw);
            const auto entries = client.sniff_get_mfkey_entries(with_card);
            const int total = static_cast<int>(entries.size());
            {
                char msg[64];
                std::snprintf(msg, sizeof(msg), "got %d nonce entries", total);
                NfcHexLog::get().log_event(with_card ? "mfkey64" : "mfkey32v2", msg);
            }
            const std::string bin_dir = hal_path_mfkey_bin_dir();

            if (with_card) {
                // mfkey64: card-present — one auth session per entry
                // De-duplicate by (uid, nt, nr, ar, at)
                std::set<std::tuple<uint32_t,uint32_t,uint32_t,uint32_t,uint32_t>> seen;
                int done = 0;
                for (const auto &e : entries) {
                    if (cancel_hw_mfkey_.load()) break;
                    auto key = std::make_tuple(e.uid, e.nt, e.nr, e.ar, e.at);
                    if (!seen.insert(key).second) continue;
                    char cmd[512];
                    std::snprintf(cmd, sizeof(cmd),
                        "\"%s/mfkey64\" %08x %08x %08x %08x %08x 2>/dev/null",
                        bin_dir.c_str(), e.uid, e.nt, e.nr, e.ar, e.at);
                    NfcHexLog::get().log_event("mfkey64", cmd);
                    std::string out = run_cmd_capture(cmd);
                    MfkeyResult res{e.uid, e.sector, e.key_type, {}};
                    res.key_hex = parse_mfkey_result(out);
                    if (!out.empty()) NfcHexLog::get().log_event("mfkey64", out.substr(0, out.find('\n')).c_str());
                    results.push_back(res);
                    ++done;
                    std::lock_guard<std::mutex> lk(pending_log_mutex_);
                    hw_mfkey_progress_ = done * 100 / std::max(1, total);
                }
            } else {
                // mfkey32v2: no-card — needs 2 nonce pairs per (uid, sector, key_type)
                using GroupKey = std::tuple<uint32_t, uint8_t, uint8_t>;
                std::map<GroupKey, std::vector<Pn532KillerClient::MfkeyEntry>> groups;
                for (const auto &e : entries)
                    groups[{e.uid, e.sector, e.key_type}].push_back(e);
                const int group_count = static_cast<int>(groups.size());
                int done = 0;
                for (auto &[gk, caps] : groups) {
                    if (cancel_hw_mfkey_.load()) break;
                    const auto [uid, sector, key_type] = gk;
                    MfkeyResult res{uid, sector, key_type, {}};
                    // Try all pairs until a key is found
                    for (size_t i = 0; i < caps.size() && res.key_hex.empty(); ++i) {
                        for (size_t j = i + 1; j < caps.size() && res.key_hex.empty(); ++j) {
                            if (caps[i].nt == caps[j].nt) continue;
                            char cmd[512];
                            std::snprintf(cmd, sizeof(cmd),
                                "\"%s/mfkey32v2\" %08x %08x %08x %08x %08x %08x %08x 2>/dev/null",
                                bin_dir.c_str(), uid,
                                caps[i].nt, caps[i].nr, caps[i].ar,
                                caps[j].nt, caps[j].nr, caps[j].ar);
                            NfcHexLog::get().log_event("mfkey32v2", cmd);
                            std::string out = run_cmd_capture(cmd);
                            if (!out.empty()) NfcHexLog::get().log_event("mfkey32v2", out.substr(0, out.find('\n')).c_str());
                            res.key_hex = parse_mfkey_result(out);
                        }
                    }
                    results.push_back(res);
                    ++done;
                    std::lock_guard<std::mutex> lk(pending_log_mutex_);
                    hw_mfkey_progress_ = done * 100 / std::max(1, group_count);
                }
            }
        }

        {
            int found_count = 0;
            for (const auto &r : results) if (!r.key_hex.empty()) ++found_count;
            char msg[64];
            std::snprintf(msg, sizeof(msg), "done, %d/%d keys found", found_count, static_cast<int>(results.size()));
            NfcHexLog::get().log_event(with_card ? "mfkey64" : "mfkey32v2", msg);
        }
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        hw_mfkey_running_  = false;
        hw_mfkey_progress_ = 100;
        hw_mfkey_results_  = results;
    }

    // Run a shell command and capture stdout (max 4KB).
    static std::string run_cmd_capture(const char *cmd)
    {
        FILE *f = popen(cmd, "r");
        if (!f) return {};
        std::string out;
        char buf[256];
        while (fgets(buf, sizeof(buf), f)) out += buf;
        pclose(f);
        return out;
    }

    // Parse "Found Key: [XXXXXXXXXXXX]" from mfkey output.
    static std::string parse_mfkey_result(const std::string &output)
    {
        static const char *PREFIX = "Found Key: [";
        const size_t pos = output.find(PREFIX);
        if (pos == std::string::npos) return {};
        const size_t start = pos + strlen(PREFIX);
        const size_t end   = output.find(']', start);
        if (end == std::string::npos || end <= start) return {};
        std::string key = output.substr(start, end - start);
        // Normalize to uppercase 12 chars
        if (key.size() < 12) key = std::string(12 - key.size(), '0') + key;
        for (char &c : key) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        return key.size() == 12 ? key : std::string{};
    }

    // ── Full dump download (triggered by user action "Download Data") ─────────
    // Downloads all blocks/pages from the current HW EMU slot and stores formatted
    // hex lines in EmuSlotInfo::dump_lines.  Runs in a background thread.
    void perform_emu_slot_dump(ProtocolKind protocol, int slot)
    {
        {
            char msg[64];
            std::snprintf(msg, sizeof(msg), "fetch dump slot %d", slot + 1);
            NfcHexLog::get().log_event("emu-dump", msg);
        }
        INfcTransport *transport_raw = nullptr;
        TransportEndpoint endpoint;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
            endpoint      = connection_.endpoint;
        }
        // Serialize all transport operations
        std::lock_guard<std::mutex> op_lock(transport_op_mutex_);

        std::vector<std::string> lines;
        bool ok = false;

        if (transport_raw && transport_raw->is_open()) {
            Pn532KillerClient client(transport_raw);
            const uint8_t type_byte = emu_type_byte(protocol);

            // Determine block count and bytes per block
            int block_count  = 64;
            int bytes_per_block = 16;
            if (protocol == ProtocolKind::Iso14443A) {          // NTAG
                block_count  = 45;  // NTAG213 default
                bytes_per_block = 4;
            } else if (protocol == ProtocolKind::Iso15693) {
                block_count  = 40;
                bytes_per_block = 4;
            }

            // Switch hardware to the correct slot before dumping.
            // Without this, switching slots then downloading reads stale data.
            std::string sw_err;
            client.set_work_mode(0x02, type_byte, static_cast<uint8_t>(slot), &sw_err);
            const int stabilize_ticks = (endpoint.kind == TransportKind::UartSerial) ? 30 : 15;
            for (int i = 0; i < stabilize_ticks; ++i) {
                if (cancel_emu_dump_.load()) {
                    std::lock_guard<std::mutex> lk(pending_log_mutex_);
                    emu_dump_running_ = false;
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            client.emu_prepare_read(type_byte, static_cast<uint8_t>(slot));
            std::this_thread::sleep_for(std::chrono::milliseconds(
                (endpoint.kind == TransportKind::UartSerial) ? 60 : 20));

            for (int blk = 0; blk < block_count; ++blk) {
                if (cancel_emu_dump_.load()) break;

                std::vector<uint8_t> data;
                if (!client.emu_download_block(type_byte, static_cast<uint8_t>(slot),
                                               static_cast<uint16_t>(blk), &data)) break;

                // Format line: "00: XXYYZZ..." (no spaces between bytes)
                char linebuf[80] = {};
                int pos = snprintf(linebuf, sizeof(linebuf), "%02X: ", blk);
                const int max_bytes = std::min((int)data.size(), bytes_per_block);
                for (int b = 0; b < max_bytes; ++b)
                    pos += snprintf(linebuf + pos, sizeof(linebuf) - pos, "%02X", data[b]);
                lines.push_back(linebuf);
                ok = true;

                std::this_thread::sleep_for(std::chrono::milliseconds(
                    (endpoint.kind == TransportKind::UartSerial) ? 20 : 5));
            }
        }

        // Dump data is stored in cache only — NOT auto-saved to storage.
        // User must explicitly call save_emu_dump_cached() (e.g. via "Save Dump" in UI).

        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        if (ok) {
            auto &info = emu_slot_cache_[{protocol, slot}];
            info.dump_lines  = std::move(lines);
            info.dump_loaded = true;
        }
        emu_dump_running_ = false;
    }

    void perform_probe_all()
    {
        // Take a snapshot of endpoints to probe (without holding the lock)
        std::vector<TransportEndpoint> to_probe;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto &ep : endpoints_) {
                if (ep.kind != TransportKind::I2cBus) to_probe.push_back(ep);
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

};

} // namespace nfc_app