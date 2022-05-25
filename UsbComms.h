/*
*   This file is part of fusee-toy
*   Copyright (C) 2022 Swiftloke
*
*   This program is free software: you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation, either version 3 of the License, or
*   (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
*
*   You should have received a copy of the GNU General Public License
*   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
*   Additional Terms 7.b and 7.c of GPLv3 apply to this file:
*       * Requiring preservation of specified reasonable legal notices or
*         author attributions in that material or in the Appropriate Legal
*         Notices displayed by works containing it.
*       * Prohibiting misrepresentation of the origin of that material,
*         or requiring that modified versions of such material be marked in
*         reasonable ways as different from the original version.
*/

//
// Created by Swiftloke on 1/16/21.
//

#ifndef FUSEE_TOY_USBCOMMS_H
#define FUSEE_TOY_USBCOMMS_H
#include "PayloadConstructor.h"


class UsbComms
{
protected:
    PayloadConstructor::Payload& Payload;
    unsigned int PayloadLen;
    //RCM starts with the low buffer.
    bool High_Buf = false;
    unsigned int rcx = 0;

    virtual bool WritePayload() = 0;
    virtual bool SubmitVuln() = 0;

    static constexpr int SWITCH_RCM_VENDOR_ID = 0x0955;
    static constexpr int SWITCH_RCM_PRODUCT_ID = 0x7321;
    static constexpr int TEGRA_RCM_ENDPOINT_IN = 0x81;
    static constexpr int TEGRA_RCM_ENDPOINT_OUT = 0x01;
    static constexpr unsigned int TEGRA_RCM_BLOCK_SIZE = 0x1000;
    /*
    fusee-launcher appears to define a "length" variable defining the amount of stack smash necessary
    in the vulnerable GET_STATUS request. However, this code appears to be vestigial in origin, coming before
    the decision was made in the exploit logic to ALWAYS kickstart the exploit from the high buffer.

    fusee-nano understands this and always sends the amount that can be derived from this logic, 0x7000.
    This value is set because the stack end is at 0x40010000, or so fusee-launcher says (believeable, given
    its origins in the RE of the Erista bootrom) and the high DMA buffer that the memcpy starts at is at 0x40009000.
    */
    static constexpr int STACK_SMASH_LEN = 0x7000;


public:

    explicit UsbComms(PayloadConstructor::Payload& payload, unsigned int payloadlen)
    : Payload(payload), PayloadLen(payloadlen) {}

    virtual bool OpenDevice() = 0;
    virtual bool TriggerExploit() = 0;

};


#endif //FUSEE_TOY_USBCOMMS_H
