//
// Created by corey on 5/9/22.
//

#include "Serialization.h"

Serializer::Serializer(): body_length_(0) {}

char *Serializer::data() { return data_.get(); }

const char *Serializer::data() const { return data_.get(); }

char *Serializer::body() { return data_.get() + HEADER_LENGTH; }

std::size_t Serializer::length() const { return HEADER_LENGTH + body_length_; }

std::size_t Serializer::body_length() const { return body_length_; }

char *Serializer::header() { return header_; }

void Serializer::serialize_message(const Message &message) {
    //pack our data
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, message);

    // serialize it to an array with a
    // four byte header
    body_length_ = sbuf.size();
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
    body_length_ = (header_[0] | (header_[1] << 8) | header_[2] << 16) | (header_[3] << 24);
    if (body_length_ > MAX_MESSAGE_SIZE)
    {
        body_length_ = 0;
        return false;
    }
    data_ = std::make_unique<char[]>(body_length_ + HEADER_LENGTH);
    encode_header();
    return true;
}

bool Serializer::encode_header() {
    if (body_length_ <= MAX_MESSAGE_SIZE && body_length_) {
        data_.get()[3] = (body_length_ >> 24) & 0xFF;
        data_.get()[2] = (body_length_ >> 16) & 0xFF;
        data_.get()[1] = (body_length_ >> 8) & 0xFF;
        data_.get()[0] = body_length_ & 0xFF;
        return true;
    }
    return false;
}

std::string Serializer::get_username() {
    msgpack::object_handle handle = msgpack::unpack(data_.get() + HEADER_LENGTH, body_length_);
    msgpack::object obj = handle.get();
    Message message = obj.as<Message>();

    return message.receiver;
}
