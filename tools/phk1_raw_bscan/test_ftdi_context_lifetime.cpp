/* Link-time FTDI/libusb fixture. No real library or hardware is opened. */
#include "libftdi_io.hpp"
#include <libusb-1.0/libusb.h>

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

namespace {
alignas(16) unsigned char fake_device_storage[256];
alignas(16) unsigned char fake_handle_storage[128];
ftdi_context *created_context = nullptr;
ftdi_context *opened_context = nullptr;
ftdi_context *reset_context = nullptr;
ftdi_context *mpsse_context = nullptr;
int sequence = 0, interface_sequence = 0, open_sequence = 0;
int string_calls = 0, strings_after_open = 0, bitmode_calls = 0;
int open_return = 0, open_calls = 0, close_calls = 0;
bool opened = false, context_same = true;
ftdi_context *closed_context = nullptr;
}

extern "C" {
ftdi_context *ftdi_new(void) {
  created_context = static_cast<ftdi_context *>(std::calloc(1, sizeof(ftdi_context)));
  if (created_context) created_context->error_str = "fixture error";
  return created_context;
}
void ftdi_free(ftdi_context *ctx) { std::free(ctx); }
int ftdi_set_interface(ftdi_context *ctx, enum ftdi_interface iface) {
  context_same &= ctx == created_context;
  ctx->interface = (iface == INTERFACE_A ? 0 : 1);
  interface_sequence = ++sequence;
  return 0;
}
int ftdi_usb_find_all(ftdi_context *ctx, ftdi_device_list **out, int, int) {
  context_same &= ctx == created_context;
  auto *node = static_cast<ftdi_device_list *>(std::calloc(1, sizeof(ftdi_device_list)));
  node->dev = reinterpret_cast<libusb_device *>(fake_device_storage);
  *out = node;
  return 1;
}
void ftdi_list_free(ftdi_device_list **list) {
  while (list && *list) { auto *n=(*list)->next; std::free(*list); *list=n; }
}
int ftdi_usb_get_strings(ftdi_context *ctx, libusb_device *, char *m, int ml,
                         char *d, int dl, char *s, int sl) {
  context_same &= ctx == created_context;
  ++string_calls;
  if (opened) { ++strings_after_open; ctx->usb_dev = nullptr; }
  std::snprintf(m, ml, "Xilinx"); std::snprintf(d, dl, "SQRL FK");
  std::snprintf(s, sl, "FIXTURE");
  return 0;
}
int ftdi_usb_open_dev(ftdi_context *ctx, libusb_device *) {
  context_same &= ctx == created_context;
  ++open_calls;
  opened_context = ctx;
  open_sequence = ++sequence;
  if (ctx->interface != 0) return -1;
  ctx->usb_dev = reinterpret_cast<libusb_device_handle *>(fake_handle_storage);
  opened = true;
  return open_return;
}
int ftdi_set_bitmode(ftdi_context *ctx, unsigned char, unsigned char mode) {
  context_same &= ctx == created_context && ctx == opened_context;
  if (!ctx->usb_dev) return -2;
  ++bitmode_calls;
  if (mode == BITMODE_RESET) reset_context = ctx;
  if (mode == BITMODE_MPSSE) mpsse_context = ctx;
  return 0;
}
int ftdi_write_data(ftdi_context *ctx, const unsigned char *, int size) {
  context_same &= ctx==created_context; return ctx->usb_dev ? size : -2;
}
int ftdi_read_data(ftdi_context *ctx, unsigned char *, int) {
  context_same &= ctx==created_context; return ctx->usb_dev ? 0 : -2;
}
int ftdi_set_latency_timer(ftdi_context *ctx, unsigned char) { context_same &= ctx==created_context; return ctx->usb_dev ? 0 : -2; }
int ftdi_read_data_set_chunksize(ftdi_context *ctx, unsigned int) { context_same &= ctx==created_context; return ctx->usb_dev ? 0 : -2; }
int ftdi_write_data_set_chunksize(ftdi_context *ctx, unsigned int) { context_same &= ctx==created_context; return ctx->usb_dev ? 0 : -2; }
int ftdi_tcioflush(ftdi_context *ctx) { context_same &= ctx==created_context; return ctx->usb_dev ? 0 : -2; }
int ftdi_usb_close(ftdi_context *ctx) { context_same &= ctx==created_context; closed_context=ctx; ++close_calls; ctx->usb_dev=nullptr; return 0; }
const char *ftdi_get_error_string(ftdi_context *ctx) { return ctx ? ctx->error_str : "null"; }
uint8_t libusb_get_bus_number(libusb_device *) { return 1; }
int libusb_get_port_numbers(libusb_device *, uint8_t *ports, int length) {
  if (length < 2) return -1;
  ports[0]=9; ports[1]=3;
  return 2;
}
int libusb_get_device_descriptor(libusb_device *, libusb_device_descriptor *desc) {
  std::memset(desc,0,sizeof(*desc)); desc->idVendor=0x0403; desc->idProduct=0x6010; return 0;
}
libusb_device *libusb_get_device(libusb_device_handle *handle) {
  return handle == reinterpret_cast<libusb_device_handle *>(fake_handle_storage)
      ? reinterpret_cast<libusb_device *>(fake_device_storage) : nullptr;
}
}

int main() {
  sidecar::jtag::UsbIdentity id{0x0403,0x6010,"FIXTURE","1-9.3","Xilinx","SQRL FK","A"};
  sidecar::jtag::LibFtdiIo io(id);
  assert(created_context && opened_context == created_context);
  assert(interface_sequence < open_sequence);
  assert(string_calls == 1 && strings_after_open == 0);
  assert(bitmode_calls == 2 && reset_context == created_context && mpsse_context == created_context);
  assert(context_same && created_context->usb_dev != nullptr);
  io.close();
  assert(closed_context == created_context);
  std::cout << "FTDI_CONTEXT_IDENTITY_CONTINUOUS=PASS\n"
            << "DESCRIPTOR_LOOKUP_PRESERVES_OPEN_HANDLE=PASS\n"
            << "FTDI_INTERFACE_ORDER_VALID=PASS\n"
            << "FTDI_CONTEXT_LIFETIME_REGRESSION=PASS\n";

  // A nonzero open result must fail closed before the first bitmode call.
  sequence=interface_sequence=open_sequence=string_calls=strings_after_open=bitmode_calls=0;
  open_calls=close_calls=0; opened=false; context_same=true; created_context=nullptr;
  open_return=1;
  bool rejected=false;
  try { sidecar::jtag::LibFtdiIo should_reject(id); }
  catch (const sidecar::jtag::BackendFailure& e) {
    rejected = e.phase()=="P06_OPEN_FTDI";
  }
  assert(rejected && open_calls==1 && bitmode_calls==0 && close_calls==1);
  std::cout << "NONZERO_OPEN_RETURN_REJECTED=PASS\n";
}
