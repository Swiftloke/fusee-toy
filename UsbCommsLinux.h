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

#ifndef FUSEE_TOY_USBCOMMSLINUX_H
#define FUSEE_TOY_USBCOMMSLINUX_H


#include <libusb-1.0/libusb.h>
#include "UsbComms.h"

class UsbCommsLinux : public UsbComms
{
protected:
    libusb_context *context = nullptr;
    libusb_device_handle* dev = nullptr;
    int kernel_fd;
    std::array<unsigned char, 16> RcmDeviceId{};

    bool WritePayload() override;
    bool SubmitVuln() override;

    static constexpr const char* LINUX_USBFS_ADDR = "/dev/bus/usb/%03d/%03d";

public:
    bool OpenDevice() override;

    explicit UsbCommsLinux(PayloadConstructor::Payload& payload, unsigned int payloadLen)
    : UsbComms(payload, payloadLen)
    {

    }

    bool TriggerExploit() override
    {
        WritePayload();
        SubmitVuln();
        return true;
    }

    ~UsbCommsLinux()
    {
        libusb_exit(context);
    }
};


#endif //FUSEE_TOY_USBCOMMSLINUX_H
