#pragma once
#include <cstddef>
#include <cstdint>
#if defined(_WIN32)
#define SIDECAR_RAW_API __declspec(dllexport)
#else
#define SIDECAR_RAW_API __attribute__((visibility("default")))
#endif
extern "C" {
SIDECAR_RAW_API int sidecar_raw_abi_version();
SIDECAR_RAW_API int sidecar_raw_open(void** out, uint16_t vid, uint16_t pid,
    const char* serial, const char* usb_path, const char* manufacturer,
    const char* product, const char* interface_name, uint32_t expected_idcode,
    uint32_t jtag_clock_hz);
SIDECAR_RAW_API int sidecar_raw_user_scan(void* context, uint8_t chain,
    const uint8_t* tx, size_t tx_size, uint8_t* rx, size_t rx_capacity,
    size_t* rx_size);
SIDECAR_RAW_API int sidecar_raw_close(void* context);
SIDECAR_RAW_API const char* sidecar_raw_last_error();
}
