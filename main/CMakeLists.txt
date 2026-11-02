set(COMPONENT_SRCS
    "memory_pool.c"
    "utils.c"
    "nesigner.c"
    "store.c"
    "nostr.c"
    "protocol/packet_codec.c"
    "protocol/session_crypto.c"
    "protocol/command_router.c"
    "crypto/crypto_secp256k1.c"
    "crypto/crypto_mbedtls.c"
    "nostr/nostr_ecdh_cache.c"
    "nostr/nostr_nip01.c"
    "nostr/nostr_nip04.c"
    "nostr/nostr_nip44.c"
    "storage/storage_nvs.c"
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
    INCLUDE_DIRS "." "transport" "crypto" "nostr" "storage" "protocol"
    REQUIRES mbedtls cjson driver esp_timer nvs_flash secp256k1 esp_driver_usb_serial_jtag esp_driver_uart esp_driver_gpio
)
