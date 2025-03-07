idf_component_register(SRCS "nesigner.c" "store.c" "nostr.c"
                    INCLUDE_DIRS "."
                    REQUIRES mbedtls cJSON driver esp_timer nvs_flash
                    )
