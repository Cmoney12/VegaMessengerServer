//
// Created by corey on 2/27/22.
//

#ifndef VEGAMESSENGERSERVER_SERIALIZATION_H
#define VEGAMESSENGERSERVER_SERIALIZATION_H

#include <string>
#include <vector>
#include <msgpack.hpp>
#include <cstdint>
#include <cstring>

struct Message {
    std::string sender;
    std::string receiver;
    std::string type;
    std::string data;
    std::vector<unsigned char> bin_data;
    MSGPACK_DEFINE(sender, receiver, type, data, bin_data);
};

class Serializer {
public:
    enum { HEADER_LENGTH = 4 };

    Serializer();

    char* data();

    const char* data() const;

    char* body();

    std::size_t length() const;

    std::size_t body_length() const;

    char* header();

    void serialize_message(const Message& message);

    std::string get_username();

    Message unpack_message();

    bool decode_header();

    bool encode_header();

private:
    int body_length_;
    std::unique_ptr<char[]> data_;
    enum { MAX_MESSAGE_SIZE = 9999999999 };
    char header_[HEADER_LENGTH + 1]{};
};

#endif //VEGAMESSENGERSERVER_SERIALIZATION_H
