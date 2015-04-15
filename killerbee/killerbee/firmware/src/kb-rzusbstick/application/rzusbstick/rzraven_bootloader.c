// This file has been prepared for Doxygen automatic documentation generation.
/*! \file *********************************************************************
 *
 * \brief  This is the main file for the bootloader that runs on the RZUSBSTICK.
 *         
 *         The bootloader can be entered either by shorting PD2 and PD3 (and then
 *         perform a power on reset), or writing a value to the device's 
 *         internal EEPROM and then do a chip reset. The reset source can be 
 *         generated by the watchdog timer.
 *
 * \par Application note:
 *      AVR2017: RZRAVEN FW
 *
 * \par Documentation
 *      For comprehensive code documentation, supported compilers, compiler
 *      settings and supported devices see readme.html
 *
 * \author
 *      Atmel Corporation: http://www.atmel.com \n
 *      Support email: avr@atmel.com
 *
 * $Id: rzraven_bootloader.c 41242 2008-05-03 20:13:34Z vkbakken $
 *
 * Copyright (c) 2008 , Atmel Corporation. All rights reserved.
 *
 * Licensed under Atmel�s Limited License Agreement (RZRaven Evaluation and Starter Kit). 
 *****************************************************************************/

/*================================= INCLUDES         =========================*/
#include <stdint.h>
#include <stdbool.h>

#include "compiler.h"
#include "board.h"
#include "vrt_kernel.h"
#include "self_programming.h"
#include "self_programming_conf.h"
#include "led.h"
#include "cmd_if_bootloader.h"
#include "wdt_avr.h"
#include "eep.h"

#include "usb_drv.h"
#include "usb_descriptors.h"
#include "usb_task.h"
/*================================= MACROS           =========================*/
/*================================= TYEPDEFS         =========================*/
/*================================= GLOBAL VARIABLES =========================*/
/*================================= LOCAL VARIABLES  =========================*/
static void(* const start_application)(void) = (void(*)(void))0x0000;
/*================================= PROTOTYPES       =========================*/
/*! \brief Initialize the AVR peripheral modules.
 *
 *  \retval true All peripheral modules are disabled.
 *  \retval false Will never happen.
 */
static bool avr_init(void);

/*! \brief Error handler trap.
 *
 *         This function will be called if a serious error occurs. The red LED will
 *         be lit to inidicate that something went seriously wrong. The RZUSBSTICK
 *         must be reset to leave this state.
 */
static void error_handler(void);


static bool avr_init(void) {
    PRR0 = (1 << PRTWI)  |   // Disable TWI.
	       (1 << PRTIM2) |   // Disable TIMER2.
	       (1 << PRTIM0) |   // Disable TIMER0.
           (1 << PRTIM1) |   // Disable TIMER1.
           (1 << PRSPI)  |   // Disable SPI.
	       (1 << PRADC);     // Disable ADC.
    
    PRR1 = (1 << PRUSB)  |   // Disable USB.
	       (1 << PRTIM3) |   // Disable TIMER3.
	       (1 << PRUSART1);  // Disable USART1.
	
	ACSR |= (1 << ACD);      // Disable Analog Comparator.
	
	DIDR0 = (1 << ADC7D) |   // Disable digital input buffer for analog input pins.
	        (1 << ADC6D) |   // Disable digital input buffer for analog input pins.
	        (1 << ADC5D) |   // Disable digital input buffer for analog input pins.
	        (1 << ADC4D);    // Disable digital input buffer for analog input pins.
    
    /* Initialize LEDs. */
    LED_INIT();
    
    /* Set the RX-TX pins to input with pull-up. */
    BOOT_DDR &= ~(1 << BOOT_RX);
    BOOT_DDR |= (1 << BOOT_TX);
    
    BOOT_PORT |= (1 << BOOT_RX);
    BOOT_PORT &= ~(1 << BOOT_TX);
    
    return true;
}


static void error_handler(void) {
    /* Inidicate serious HW error by turning the red LED on. */
    LED_RED_ON();
    
    /* Enter non-interryuptable endless loop. */
    cli();
    while (true) {
        ;
    }
}


/*! \brief This is the main loop for the RZRAVEN bootloader. */
#if defined(__ICCAVR__)
#pragma type_attribute = __task
void main(void) {
#else
int main(void) {
#endif
    /* Ensure that the watchdog is not running. */
    wdt_disable();
        
    /* Initialize AVR peripheral modules. */
    (bool)avr_init();
    
    /* Check if the RX and TX pins are shorted. If they are shorted, the RZUSBSTICK
     * shall start the bootloader. If not, continue to verify if the application
     * requested to enter the bootloader.
     */
    
    /* Check if the application has requested to enter the bootloader. */
    if ((BOOT_PIN & (1 << BOOT_RX)) != (1 << BOOT_RX)) {
        /* Check that RX goes high when TX is pulled high. */
        BOOT_PORT |= (1 << BOOT_TX);
        
        nop();
        nop();
        nop();
        nop();
        
        if ((BOOT_PIN & (1 << BOOT_RX)) != (1 << BOOT_RX)) {
            start_application();
        }
    } else {
        /* Check if the application has requested to enter the bootloader. */
        uint8_t volatile magic_value = 0xAA;
        EEGET(magic_value, EE_BOOT_MAGIC_ADR);
   
        if (EE_BOOT_MAGIC_VALUE != magic_value) {
            start_application();
        } else {
            EEPUT(EE_BOOT_MAGIC_ADR, 0xFF);
        }
    }
    
    /* Set the interrupt vectors to the bootloader, initialize the LEDs and the
     * VRT kernel.
     */
    ENTER_CRITICAL_REGION();
    uint8_t temp_mcucr = MCUCR;
    MCUCR = (1 << IVCE);
    MCUCR = (1 << IVSEL);
    MCUCR = temp_mcucr;
    LEAVE_CRITICAL_REGION();

    LED_INIT();
    vrt_init();
    
    if (true != eep_init()) {
        error_handler();
    } else if (true != cmd_if_init()) {
        error_handler();
    }
    
    LED_ORANGE_ON();
    
    /* Enable Interrupts. */
    sei();
    
    /* Enter the endless application loop. */
    for (;;) {
        vrt_dispatch_event();
        usb_task();
    }
}
/*EOF*/
