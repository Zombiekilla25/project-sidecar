/* Local ABI/error-semantics probe. It does not enumerate or open USB devices. */
#include <libftdi1/ftdi.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    struct ftdi_context *ctx = ftdi_new();
    if (!ctx) return 2;
    const int handle_is_null = ctx->usb_dev == NULL;
    const int interface_rc = ftdi_set_interface(ctx, INTERFACE_A);
    const int rc = ftdi_set_bitmode(ctx, 0x0b, BITMODE_RESET);
    const char *message = ftdi_get_error_string(ctx);
    printf("POINTER_WIDTH_BITS=%zu\n", sizeof(void *) * 8);
    printf("FTDI_NEW_RESTYPE=struct_ftdi_context_pointer\n");
    printf("CTX_NONNULL=%s\n", ctx ? "true" : "false");
    printf("USB_DEV_NULL=%s\n", handle_is_null ? "true" : "false");
    printf("INTERFACE_A_SET_RETURN=%d\n", interface_rc);
    printf("FTDI_CONTEXT_INTERFACE=%d\n", ctx->interface);
    printf("FTDI_CONTEXT_INDEX=%d\n", ctx->index);
    printf("FTDI_INTERFACE_A_INDEX=%s\n",
           interface_rc == 0 && ctx->interface == 0 && ctx->index == 1 ? "PASS" : "FAIL");
    printf("BITMODE_WITHOUT_OPEN_RETURN=%d\n", rc);
    printf("ERROR_STRING=%s\n", message ? message : "NONE");
    const int interface_a_ok = interface_rc == 0 &&
                               ctx->interface == 0 && ctx->index == 1;
    const int semantics_ok = handle_is_null && rc == -2 && interface_a_ok;
    ftdi_free(ctx);
    return semantics_ok ? 0 : 1;
}
