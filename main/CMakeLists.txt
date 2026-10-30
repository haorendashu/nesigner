set(COMPONENT_SRCS
    "memory_pool.c"
    "utils.c"
    "nesigner.c"
    "store.c"
    "nostr.c"
    "transport/signer_transport.c"
)

if(CONFIG_SIGNER_TRANSPORT_TINYUSB)
    list(APPEND COMPONENT_SRCS "transport/transport_tinyusb.c")
endif()

if(CONFIG_SIGNER_TRANSPORT_USB_SERIAL_JTAG)
    list(APPEND COMPONENT_SRCS "transport/transport_usb_serial_jtag.c")
endif()

if(CONFIG_SIGNER_TRANSPORT_UART)
    list(APPEND COMPONENT_SRCS "transport/transport_uart.c")
endif()

idf_component_register(
    SRCS ${COMPONENT_SRCS}
    INCLUDE_DIRS "." "transport"
    REQUIRES mbedtls cJSON driver esp_timer nvs_flash
)
