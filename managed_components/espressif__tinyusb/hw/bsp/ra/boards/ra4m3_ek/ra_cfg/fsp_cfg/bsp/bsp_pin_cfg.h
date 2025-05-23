/* generated configuration header file - do not edit */
#ifndef BSP_PIN_CFG_H_
#define BSP_PIN_CFG_H_
#include "r_ioport.h"

/* Common macro for FSP header files. There is also a corresponding FSP_FOOTER macro at the end of this file. */
FSP_HEADER

#define ARDUINO_A0_MIKROBUS_AN (BSP_IO_PORT_00_PIN_00)
#define ARDUINO_A1 (BSP_IO_PORT_00_PIN_01)
#define ARDUINO_A2 (BSP_IO_PORT_00_PIN_03)
#define SW1 (BSP_IO_PORT_00_PIN_05)
#define SW2 (BSP_IO_PORT_00_PIN_06)
#define ARDUINO_A3 (BSP_IO_PORT_00_PIN_07)
#define PMOD1_INT (BSP_IO_PORT_00_PIN_08)
#define ARDUINO_A4 (BSP_IO_PORT_00_PIN_14)
#define ARDUINO_A5 (BSP_IO_PORT_00_PIN_15)
#define ARDUINO_RX_MIKROBUS_RX (BSP_IO_PORT_01_PIN_00)
#define ARDUINO_TX_MIKROBUS_TX (BSP_IO_PORT_01_PIN_01)
#define ARDUINO_D2 (BSP_IO_PORT_01_PIN_05)
#define ARDUINO_D3 (BSP_IO_PORT_01_PIN_11)
#define MIKROBUS_RST (BSP_IO_PORT_01_PIN_15)
#define ARDUINO_MISO_MIKROBUS_MISO_PMOD1_MISO (BSP_IO_PORT_02_PIN_02)
#define ARDUINO_MOSI_MIKROBUS_MOSI_PMOD1_MOSI (BSP_IO_PORT_02_PIN_03)
#define ARDUINO_CLK_MIKROBUS_CLK_PMOD1_CLK (BSP_IO_PORT_02_PIN_04)
#define ARDUINO_SS_MIKCRBUS_SS (BSP_IO_PORT_02_PIN_05)
#define PMOD1_SS1 (BSP_IO_PORT_02_PIN_06)
#define PMOD1_SS2 (BSP_IO_PORT_02_PIN_07)
#define PMOD1_SS3 (BSP_IO_PORT_03_PIN_02)
#define ARDUINO_D9 (BSP_IO_PORT_03_PIN_03)
#define ARDUINO_D7 (BSP_IO_PORT_03_PIN_04)
#define QSPI_CLK (BSP_IO_PORT_03_PIN_05)
#define QSPI_SSL (BSP_IO_PORT_03_PIN_06)
#define QSPI_IO0 (BSP_IO_PORT_03_PIN_07)
#define QSPI_IO1 (BSP_IO_PORT_03_PIN_08)
#define QSPI_IO2 (BSP_IO_PORT_03_PIN_09)
#define QSPI_IO3 (BSP_IO_PORT_03_PIN_10)
#define PMOD1_RST (BSP_IO_PORT_03_PIN_11)
#define LED3 (BSP_IO_PORT_04_PIN_00)
#define LED2 (BSP_IO_PORT_04_PIN_04)
#define USB_VBUS (BSP_IO_PORT_04_PIN_07)
#define ARDUINO_D6_MIKROBUS_PWM (BSP_IO_PORT_04_PIN_08)
#define MIKROBUS_INT (BSP_IO_PORT_04_PIN_09)
#define PMOD2_INT (BSP_IO_PORT_04_PIN_14)
#define LED1 (BSP_IO_PORT_04_PIN_15)
#define USB_VBUS_EN (BSP_IO_PORT_05_PIN_00)
#define USB_VBUS_OC (BSP_IO_PORT_05_PIN_01)
#define GROVE2_AN1 (BSP_IO_PORT_05_PIN_05)
#define GROVE2_AN2 (BSP_IO_PORT_05_PIN_06)
#define GROVE1_SDA_QWIIC_SDA (BSP_IO_PORT_05_PIN_11)
#define GROVE1_SCL_QWIIC_SCL (BSP_IO_PORT_05_PIN_12)
#define ARDUINO_SCL_MIKROBUS_SCL (BSP_IO_PORT_06_PIN_01)
#define ARDUINO_SDA_MIKROBUS_SDA (BSP_IO_PORT_06_PIN_02)
#define ARDUINO_D8 (BSP_IO_PORT_06_PIN_11)
#define ARDUINO_RST (BSP_IO_PORT_06_PIN_12)
#define PMOD2_RST (BSP_IO_PORT_07_PIN_08)
#define PMOD2_SS2 (BSP_IO_PORT_07_PIN_09)
#define PMOD2_SS3 (BSP_IO_PORT_07_PIN_10)
#define ARDUINO_D5 (BSP_IO_PORT_07_PIN_12)
#define ARDUINO_D4 (BSP_IO_PORT_07_PIN_13)
extern const ioport_cfg_t g_bsp_pin_cfg; /* RA4M3 EK */

void BSP_PinConfigSecurityInit();

/* Common macro for FSP header files. There is also a corresponding FSP_HEADER macro at the top of this file. */
FSP_FOOTER
#endif /* BSP_PIN_CFG_H_ */
