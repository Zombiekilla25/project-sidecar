#include "sidecar_transport_abi.h"
#include "libftdi_io.hpp"
#include "mpsse_backend.hpp"
#include "usb_identity.hpp"
#include <algorithm>
#include <memory>
#include <string>
#include <vector>

namespace {
struct Context {
  std::unique_ptr<sidecar::jtag::LibFtdiIo> io;
  std::unique_ptr<sidecar::jtag::MpsseTap> tap;
  bool closed = false;
};
thread_local std::string last_error;
constexpr int kOk=0, kTargetNotFound=1, kTargetAmbiguous=2, kIdcodeMismatch=3,
  kFtdiOpen=4, kMpsseSync=5, kTap=6, kInvalid=7, kDisconnected=8;
void fail(const char* value) { last_error=value ? value : "native RAW_BSCAN error"; }
uint8_t ir_for(uint8_t chain) {
  switch(chain) { case 1:return 0x02; case 2:return 0x03; case 3:return 0x22; default:throw std::invalid_argument("USER chain not allowed"); }
}
bool valid_scan(uint8_t chain,size_t size) {
  return (chain==1 && (size==1 || size==96)) ||
         (chain==2 && (size==1 || size==24608)) ||
         (chain==3 && size==4);
}
}
extern "C" int sidecar_raw_abi_version() { return 1; }
extern "C" int sidecar_raw_open(void** out,uint16_t vid,uint16_t pid,
    const char* serial,const char* usb_path,const char* manufacturer,
    const char* product,const char* interface_name,uint32_t expected_idcode,
    uint32_t jtag_clock_hz) {
  if(out)*out=nullptr; last_error.clear();
  if(!out||!serial||!usb_path||!manufacturer||!product||!interface_name) {fail("invalid native target arguments");return kInvalid;}
  std::unique_ptr<Context> context(new Context());
  try {
    sidecar::jtag::UsbIdentity id{vid,pid,serial,usb_path,manufacturer,product,interface_name};
    context->io=std::make_unique<sidecar::jtag::LibFtdiIo>(id);
    context->tap=std::make_unique<sidecar::jtag::MpsseTap>(*context->io);
    context->tap->synchronize_and_configure(jtag_clock_hz);
    const auto got=context->tap->read_single_vu33p_idcode();
    if(got!=expected_idcode){fail("IDCODE mismatch after open");return kIdcodeMismatch;}
    *out=context.release(); return kOk;
  } catch(const sidecar::jtag::BackendFailure& e) {
    fail(e.what());
    if(e.phase()=="P05_MATCH_FTDI_DEVICE" && std::string(e.what()).find("not found")!=std::string::npos)return kTargetNotFound;
    if(e.phase()=="P05_MATCH_FTDI_DEVICE" && std::string(e.what()).find("duplicate")!=std::string::npos)return kTargetAmbiguous;
    if(e.phase()=="P04_ENUMERATE_USB"||e.phase()=="P05_MATCH_FTDI_DEVICE"||e.phase()=="P06_OPEN_FTDI"||e.phase()=="P07_SELECT_INTERFACE_A")return kFtdiOpen;
    if(e.phase()=="P09_MPSSE_SYNC"||e.phase()=="P10_SET_JTAG_CLOCK"||e.phase()=="P08_INIT_MPSSE")return kMpsseSync;
    return kTap;
  } catch(const std::exception& e) { fail(e.what()); return kTap; }
}
extern "C" int sidecar_raw_user_scan(void* opaque,uint8_t chain,const uint8_t* tx,
    size_t tx_size,uint8_t* rx,size_t rx_capacity,size_t* rx_size) {
  last_error.clear(); auto* ctx=static_cast<Context*>(opaque);
  if(!ctx||ctx->closed||!ctx->tap)return (fail("native transport is closed"),kDisconnected);
  if(!tx||!rx||!rx_size||!valid_scan(chain,tx_size)||rx_capacity<tx_size)
    return (fail("PHK1 USER scan shape is outside allowlist"),kInvalid);
  try {
    ctx->tap->shift_ir(ir_for(chain),6);
    std::vector<uint8_t> input(tx,tx+tx_size);
    const auto result=ctx->tap->shift_dr(input,tx_size*8);
    if(result.tdo.size()!=tx_size)return (fail("short TDO response"),kTap);
    std::copy(result.tdo.begin(),result.tdo.end(),rx);*rx_size=result.tdo.size();return kOk;
  } catch(const std::exception& e) { fail(e.what()); return kTap; }
}
extern "C" int sidecar_raw_close(void* opaque) {
  last_error.clear(); auto* ctx=static_cast<Context*>(opaque);if(!ctx)return kOk;
  ctx->closed=true;int rc=0;
  try { if(ctx->io) rc=ctx->io->close_checked(); }
  catch(const std::exception& e){fail(e.what());rc=-1;}
  delete ctx;return rc==0?kOk:kDisconnected;
}
extern "C" const char* sidecar_raw_last_error(){return last_error.c_str();}
