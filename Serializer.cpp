//
// Created by corey on 5/9/22.
//

#include "Serialization.h"

Serializer::Serializer(): body_length_(0) {}

char *Serializer::data() { return data_.get() + HEADER_LENGTH; }

const char *Serializer::data() const { return data_.get() + HEADER_LENGTH; }

std::size_t Serializer::length() const { return HEADER_LENGTH + body_length_; }

std::size_t Serializer::body_length() const { return body_length_; }

char *Serializer::header() { return header_; }

void Serializer::serialize_message(const Message &message) {
    //pack our data
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, message);

    // serialize it to an array with a
    // four byte header
    body_length_ = sbuf.size() + 1;
    data_ = std::make_unique<char[]>(HEADER_LENGTH + body_length_);
    encode_header();
    std::memcpy(data_.get() + HEADER_LENGTH, sbuf.data(), sbuf.size());
}

Message Serializer::unpack_message() {
    msgpack::object_handle handle = msgpack::unpack(data_.get() + HEADER_LENGTH, body_length_);
    msgpack::object obj = handle.get();
    Message message = obj.as<Message>();

    return message;
}

bool Serializer::decode_header() {
    body_length_ = std::atoi(header_);
    if (body_length_ > MAX_MESSAGE_SIZE)
    {
        body_length_ = 0;
        return false;
    }
    data_ = std::make_unique<char[]>(body_length_ + 1);
    return true;
}

void Serializer::encode_header() {
    char header[HEADER_LENGTH + 1] = "";
    std::sprintf(header, "%4d", static_cast<int>(body_length_));
    std::memcpy(data_.get(), header, HEADER_LENGTH);
}

std::string Serializer::get_username() {
    msgpack::object_handle handle = msgpack::unpack(data_.get() + HEADER_LENGTH, body_length_);
    msgpack::object obj = handle.get();
    Message message = obj.as<Message>();

    return message.receiver;
}
