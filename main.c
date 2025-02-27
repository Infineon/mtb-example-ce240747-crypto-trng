/******************************************************************************
* File Name:   main.c
*
* Description: This is the source code for the PDL:Cryptography True
*              Random Number Generation Example for ModusToolbox.
*
* Related Document: See README.md
*
*
*******************************************************************************
* Copyright 2024-2025, Cypress Semiconductor Corporation (an Infineon company) or
* an affiliate of Cypress Semiconductor Corporation.  All rights reserved.
*
* This software, including source code, documentation and related
* materials ("Software") is owned by Cypress Semiconductor Corporation
* or one of its affiliates ("Cypress") and is protected by and subject to
* worldwide patent protection (United States and foreign),
* United States copyright laws and international treaty provisions.
* Therefore, you may use this Software only as provided in the license
* agreement accompanying the software package from which you
* obtained this Software ("EULA").
* If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
* non-transferable license to copy, modify, and compile the Software
* source code solely for use in connection with Cypress's
* integrated circuit products.  Any reproduction, modification, translation,
* compilation, or representation of this Software except as specified
* above is prohibited without the express written permission of Cypress.
*
* Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
* reserves the right to make changes to the Software without notice. Cypress
* does not assume any liability arising out of the application or use of the
* Software or any product or circuit described in the Software. Cypress does
* not authorize its products for use in any products where a malfunction or
* failure of the Cypress product may reasonably be expected to result in
* significant property damage, injury or death ("High Risk Product"). By
* including Cypress's product in a High Risk Product, the manufacturer
* of such system or application assumes all risk of such use and in doing
* so agrees to indemnify Cypress against all liability.
*******************************************************************************/

/*******************************************************************************
* Header Files
*******************************************************************************/
#include "cy_pdl.h"
#include "cybsp.h"  
#include "cy_retarget_io.h"
#include "mtb_hal.h"

/*******************************************************************************
* Macros
********************************************************************************/
/* Macro for the maximum value of the random number generated in bits */
#define ASCII_7BIT_MASK                 (0x7F)

#define PASSWORD_LENGTH                 (8u)
#define PASSWOED_DATA_SIZE              (32u)
#define ASCII_VISIBLE_CHARACTER_START   (33u)
#define ASCII_RETURN_CARRIAGE           (0x0D)

#define SCREEN_HEADER "\r\n__________________________________________________"\
           "____________________________\r\n*\tPDL: Cryptography "\
           "True Random Number Generation\r\n*\r\n*\tThis code example "\
           "demonstrates generating a One-Time Password (OTP)\r\n*\tusing the"\
           " True Random Number generation feature of MCU\r\n*\t"\
           "cryptography block\r\n*\r\n*\tUART Terminal Settings\tBaud Rate:"\
           "115200 bps 8N1 \r\n*"\
           "\r\n__________________________________________________"\
           "____________________________\r\n\n"

#define SCREEN_HEADER1 "\r\n================================================="\
           "=============================\r\n"

/* \x1b[2J\x1b[;H - ANSI ESC sequence for clear screen */
#define CLEAR_SCREEN         "\x1b[2J\x1b[;H"

#define TIME_OUT_TICKS                  (1u)

/*******************************************************************************
* Global Variables
********************************************************************************/
/* Variable for storing character read from terminal */
static uint8_t uart_read_value;

/*******************************************************************************
* Function Prototypes
********************************************************************************/
static void generate_password();
static uint8_t check_range(uint8_t value);
static cy_en_scb_uart_status_t get_character(CySCB_Type * base, \
                                             uint8_t *value,    \
                                             uint32_t timeout);

/* For the Retarget -IO (Debug UART) usage */
static cy_stc_scb_uart_context_t    UART_context;           /** UART context */
static mtb_hal_uart_t               UART_hal_obj;           /** Debug UART HAL object  */
/*******************************************************************************
* Function Name: main 
********************************************************************************
* Summary:
* This is the main function for CM7 CPU. It configures the CRYPTO block to
* generate random number and convert it to a alpha-numeric password. A new 
* password is generated every time the user presses the Enter key.
*
* Parameters:
*  void
*
* Return:
*  int
*
*******************************************************************************/
int main(void)
{
    cy_rslt_t result;

    /* Initialize the device and board peripherals */
    result = cybsp_init();
    
    /* Board init failed. Stop program execution */
    if (CY_RSLT_SUCCESS != result)
    {
        CY_ASSERT(0);
    }

    /* Enable global interrupts */
    __enable_irq();
    
    /* Debug UART init */
    result = (cy_rslt_t)Cy_SCB_UART_Init(UART_HW, &UART_config, &UART_context);

    /* UART init failed. Stop program execution */
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    Cy_SCB_UART_Enable(UART_HW);

    /* Setup the HAL UART */
    result = mtb_hal_uart_setup(&UART_hal_obj, &UART_hal_config, &UART_context, NULL);

    /* HAL UART init failed. Stop program execution */
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    result = cy_retarget_io_init(&UART_hal_obj);

    /* HAL retarget_io init failed. Stop program execution */
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    /* \x1b[2J\x1b[;H - ANSI ESC sequence for clear screen */
    printf(CLEAR_SCREEN);

    printf(SCREEN_HEADER);

    printf("Press the Enter key to generate password\r\n");

    for(;;)
    {
        /* Check if 'Enter' key was pressed */
        if (get_character(UART_HW, &uart_read_value, TIME_OUT_TICKS) \
            == CY_SCB_UART_SUCCESS)
        {
            if (uart_read_value == ASCII_RETURN_CARRIAGE)
            {
                /* Generate a password of 8 characters in length */
                generate_password();
            }
        }
    }
}

/*******************************************************************************
* Function Name: generate_password
********************************************************************************
* Summary: This function generates a 8 character long password
*
* Parameters:
*  None
*
* Return
*  void
*
*******************************************************************************/
static void generate_password()
{
    int8_t index;
    uint32_t random_val;
    uint8_t temp_value = 0;
    cy_rslt_t rslt;

    /* Array to hold the generated password. Array size is inclusive of
       string NULL terminating character */
    uint8_t password[PASSWORD_LENGTH + 1]= {0};

    /* Initialize the TRNG generator block */
    uint32_t GAROPoly = Cy_Crypto_Core_Trng_GetGaroPoly(CRYPTO);
    uint32_t FIROPoly = Cy_Crypto_Core_Trng_GetFiroPoly(CRYPTO);
        for (index = 0; index < PASSWORD_LENGTH;)
        {
            /* Generate a random 32 bit number */
            Cy_Crypto_Core_Enable(CRYPTO);

            /* Generate a random 32 bit number */
            rslt = Cy_Crypto_Core_Trng(CRYPTO,             \
                                       GAROPoly,           \
                                       FIROPoly,           \
                                       PASSWOED_DATA_SIZE, \
                                       &random_val);

            if(CY_CRYPTO_SUCCESS != rslt)
            {
                CY_ASSERT(0);
            }

            /* reset CRYPTO registers */
            Cy_Crypto_Core_Trng_DeInit(CRYPTO);

            uint8_t bit_position  = 0;

            for(int8_t j=0;j<4;j++)
            {
                /* extract byte from the bit position offset 0, 8, 16, and 24 */
                temp_value=((random_val>>bit_position )& ASCII_7BIT_MASK);
                temp_value=check_range(temp_value);
                password[index++] = temp_value;
                bit_position  = bit_position  + 8;
            }
         }

        /* Terminate the password with end of string character */
        password[index] = '\0';

        /* Display the generated password on the UART Terminal */
        printf("One-Time Password: %s\r\n\n",password);
        printf("Press the Enter key to generate new password\r\n");
        printf(SCREEN_HEADER1);
}

/*******************************************************************************
* Function Name: check_range
********************************************************************************
* Summary: This function check if the generated random number is in the 
*          range of alpha-numeric, special characters ASCII codes.  
*          If not, convert to that range.
*
* Parameters:
*  uint8_t
*
* Return
*  uint8_t 
*
*******************************************************************************/
static uint8_t check_range(uint8_t value)
{
    if (value < ASCII_VISIBLE_CHARACTER_START)
    {
         value += ASCII_VISIBLE_CHARACTER_START;
    }
     return value;
}

/*******************************************************************************
* Function Name: get_character
********************************************************************************
* Summary: This function gets character via UART.
*
* Parameters:
*  CySCB_Type *, uint8_t *, uint32_t
*
* Return
*  cy_en_scb_uart_status_t
*
*******************************************************************************/
static cy_en_scb_uart_status_t get_character(CySCB_Type *base, \
                                             uint8_t *value,   \
                                             uint32_t timeout)
{
    /* Get character via UART */
    uint32_t read_value = Cy_SCB_UART_Get(base);
    uint32_t timeoutTicks = timeout;
    
    while (read_value == CY_SCB_UART_RX_NO_DATA)
    {
        if(timeout != 0UL)
        {
            if(timeoutTicks > 0UL)
            {
                /* Wait 1ms */
                Cy_SysLib_Delay(1);
                timeoutTicks--;
            }
            else
            {
                return CY_SCB_UART_BAD_PARAM;
            }
        }
        /* Try to get character again */
        read_value = Cy_SCB_UART_Get(base);
    }

    *value = (uint8_t)read_value;
    return CY_SCB_UART_SUCCESS;
}

/* [] END OF FILE */
