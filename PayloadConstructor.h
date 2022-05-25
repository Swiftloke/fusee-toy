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
// Created by Swiftloke on 1/1/21.
//

//Todo: This code was written using memory-efficient C++ features
//  in mind, but it's not perfect because of file loading.
//  -fno-exceptions will be fine to keep the exception code in
//  for brevity, but the std::vector is a huge red flag.

#ifndef FUSEE_TOY_PAYLOADCONSTRUCTOR_H
#define FUSEE_TOY_PAYLOADCONSTRUCTOR_H

#include <array>
#include <string>
#include <cstdio>
#include <vector>

//This is for my own convenience. Done globally, as I quite like it.
using u32 = uint32_t;

class PayloadConstructor
{
private:
    static constexpr int PAYLOAD_MAX_LENGTH = 0x30298;

    static constexpr int RCM_CMD_PADDING = 0x42;
    static constexpr int RCM_CMD_LEN = 680;

    static constexpr int INTERMEZZO_PADDING = 0x64;

    static constexpr int PAYLOAD_ADDR_START = 0x40010000;
    //Todo: Can this be anywhere?
    static constexpr int PAYLOAD_ADDR_INTERMEZZO = 0x4001F000;
    //Todo: Can this also be anywhere?
    static constexpr int PAYLOAD_ADDR_PAYLOAD = 0x40020000;

public:
    using Payload = std::array<unsigned char, PAYLOAD_MAX_LENGTH>;
private:

    u32 rcx = 0;
    u32 len;

private:
    FILE* intermezzo_fp;
    FILE* payload_fp;
    std::vector<char> intermezzo_file;
    std::vector<char> payload_file;
    Payload payload{};

    //Basic convenience function... Writes to byte array as little-endian.
    void write_u32_to_payload(u32 val, u32 loc);


public:

    PayloadConstructor(const char *intermezzo_file_loc, const char *payload_file_loc);

    Payload& GeneratePayload();

    u32 Len() const
    {
        return len;
    }
};


#endif //FUSEE_TOY_PAYLOADCONSTRUCTOR_H
