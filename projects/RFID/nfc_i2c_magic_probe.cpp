#include "main/ui/components/nfc/nfc_i2c_device.hpp"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>
#include <thread>

extern "C" const char *hal_path_nfc_log_dir(void)
{
    return "/tmp";
}

int main(int argc, char **argv)
{
    const std::string bus = (argc > 1) ? argv[1] : "/dev/i2c-1";
    const int attempts = (argc > 2) ? std::max(1, std::atoi(argv[2])) : 5;
    const uint8_t addr = 0x50;

    nfc_app::I2cGroveNfcDevice dev;
    std::string err;
    if (!dev.open(bus, addr, &err)) {
        std::cout << "OPEN_FAIL bus=" << bus << " addr=0x" << std::hex << std::uppercase
                  << static_cast<int>(addr) << std::dec << " err=" << err << "\n";
        return 2;
    }

    bool found = false;
    nfc_app::I2cCardInfo card;
    for (int i = 0; i < attempts; ++i) {
        card = nfc_app::I2cCardInfo{};
        if (dev.readCard(card) && card.valid) {
            found = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
    }

    if (!found) {
        for (const auto &line : nfc_app::NfcHexLog::get().get_lines(0, 512)) {
            std::cerr << line << "\n";
        }
        std::cout << "SCAN_NONE" << "\n";
        return 1;
    }

    for (const auto &line : nfc_app::NfcHexLog::get().get_lines(0, 512)) {
        std::cerr << line << "\n";
    }

    std::cout << "SCAN_OK"
              << " uid=" << card.uid
              << " protocol=" << card.protocol
              << " atqa=" << (card.atqa_hex.empty() ? "-" : card.atqa_hex)
              << " sak=" << (card.sak_hex.empty() ? "-" : card.sak_hex)
              << " magic=" << (card.magic_type.empty() ? "None" : card.magic_type)
              << " detail=" << card.detail
              << "\n";

    return 0;
}
