#include <iostream>
#include <cstdlib>
#include <deque>
#include <list>
#include <memory>
#include <set>
#include <utility>
#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <unordered_map>
#include <boost/asio/ssl.hpp>
#include <boost/filesystem.hpp>
#include "Serialization.h"

using boost::asio::ip::tcp;
using ssl_socket = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;

//----------------------------------------------------------------------

typedef std::deque<std::shared_ptr<Serializer>> chat_message_queue;

//----------------------------------------------------------------------

class chat_participant
{
public:
    virtual ~chat_participant() = default;
    virtual void deliver(const std::string& recipient, const std::shared_ptr<Serializer>& msg) = 0;
};

typedef std::shared_ptr<chat_participant> chat_participant_ptr;

//----------------------------------------------------------------------

class chat_room {
public:

    void join(const std::string& username, const chat_participant_ptr& participant)
    {
        participants_.emplace(username, participant);
        //for (const auto& msg: recent_msgs_)
        //    participant->deliver(msg);
    }

    void leave(const chat_participant_ptr& participant)
    {
        for (auto it = participants_.begin(); it != participants_.end(); )
        {
            if (it->second == participant) {
                participants_.erase(it++);
            }
            else {
                ++it;
            }
        }

    }

    void deliver(const std::string& recipient, const std::shared_ptr<Serializer>& msg)
    {
        if (participants_.find(recipient) != participants_.end()) {
            recent_msgs_.push_back(msg);
            while (recent_msgs_.size() > max_recent_msgs)
                recent_msgs_.pop_front();

            auto it = participants_.find(recipient);
            it->second->deliver(recipient, msg);
        }
    }

private:
    std::unordered_map<std::string, chat_participant_ptr> participants_;
    enum { max_recent_msgs = 100 };
    chat_message_queue recent_msgs_;
};

//----------------------------------------------------------------------

class chat_session
        : public chat_participant,
          public std::enable_shared_from_this<chat_session>
{
public:
    chat_session(boost::asio::ssl::stream<tcp::socket> socket, chat_room& room, boost::asio::io_context::strand& strand)
            : socket_(std::move(socket)),
              room_(room),
              strand_(strand)
    {
    }

    void start()
    {
        do_handshake();
    }

    void do_handshake()
    {
        auto self(shared_from_this());
        socket_.async_handshake(boost::asio::ssl::stream_base::server,
                                boost::asio::bind_executor(strand_,  [this, self](boost::system::error_code ec)
                                {
                                    if (!ec)
                                    {
                                        read_username();
                                        do_read_header();
                                    }
                                }));
    }

    void deliver(const std::string& recipient, const std::shared_ptr<Serializer>& msg) override
    {
        bool write_in_progress = !write_msgs_.empty();
        write_msgs_.push_back(msg);
        if (!write_in_progress)
        {
            do_write();
        }
    }

    void read_username() {
        boost::asio::async_read_until(socket_, buf, "\n",
                                      boost::asio::bind_executor(strand_,[this]
                                              (boost::system::error_code ec, std::size_t size) {
                                          if(!ec) {
                                              handle_username(ec, size);
                                          }
                                      }));
    }

    void handle_username(boost::system::error_code, std::size_t size) {
        std::stringstream message;

        message << std::istream(&buf).rdbuf();
        buf.consume(size);
        std::string username = message.str();
        message.clear();
        int pos = username.find('\n');
        username = username.substr(0,pos);
        room_.join(username, shared_from_this());
    }

private:
    void do_read_header()
    {
        auto self(shared_from_this());
        boost::asio::async_read(socket_,
                                boost::asio::buffer(read_msg_->header(), Serializer::HEADER_LENGTH),
                                boost::asio::bind_executor(strand_,[this, self](boost::system::error_code ec, std::size_t /*length*/)
                                {
                                    if (!ec && read_msg_->decode_header())
                                    {
                                        do_read_body();
                                    }
                                    else
                                    {
                                        room_.leave(shared_from_this());
                                    }
                                }));
    }

    void do_read_body()
    {
        auto self(shared_from_this());
        boost::asio::async_read(socket_,
                                boost::asio::buffer(read_msg_->body(), read_msg_->body_length()),
                                boost::asio::bind_executor(strand_,[this, self](boost::system::error_code ec, std::size_t /*length*/)
                                {
                                    if (!ec) {
                                        // allow through network to get external ip
                                        //std::string client_ip = socket_.remote_endpoint().address().to_string();
                                        //local ip
                                        std::string username = read_msg_->get_username();
                                        room_.deliver(username, read_msg_);
                                        do_read_header();
                                    }
                                    else
                                    {
                                        room_.leave(shared_from_this());
                                    }
                                }));
    }

    void do_write()
    {
        auto self(shared_from_this());
        boost::asio::async_write(socket_,
                                 boost::asio::buffer(write_msgs_.front()->data(),
                                                     write_msgs_.front()->length()),
                                 boost::asio::bind_executor(strand_,
                                                            [this, self](boost::system::error_code ec, std::size_t /*length*/)
                                                            {
                                                                if (!ec)
                                                                {
                                                                    write_msgs_.pop_front();
                                                                    if (!write_msgs_.empty())
                                                                    {
                                                                        do_write();

                                                                    }
                                                                }
                                                                else
                                                                {
                                                                    room_.leave(shared_from_this());
                                                                }
                                                            }));
    }

    ssl_socket socket_;
    chat_room& room_;
    std::shared_ptr<Serializer> read_msg_ = std::make_shared<Serializer>();
    chat_message_queue write_msgs_;
    boost::asio::streambuf buf;
    boost::asio::io_context::strand& strand_;
};

//----------------------------------------------------------------------

class chat_server
{
public:
    chat_server(boost::asio::io_context& io_context,
                const tcp::endpoint& endpoint, boost::asio::io_context::strand& strand)
            : acceptor_(io_context, endpoint), strand_(strand), context_(boost::asio::ssl::context::sslv23)
    {
        context_.set_options(
                boost::asio::ssl::context::default_workarounds
                | boost::asio::ssl::context::no_sslv2
                | boost::asio::ssl::context::single_dh_use);
        context_.set_password_callback(std::bind(&chat_server::get_password));
        context_.use_certificate_chain_file(server_crt_path_.string());
        context_.use_private_key_file(server_key_path.string(), boost::asio::ssl::context::pem);
        context_.use_tmp_dh_file(dh_path.string());

        do_accept();
    }

private:
    static std::string get_password()
    {
        return "test";
    }

    void do_accept()
    {
        acceptor_.async_accept(
                boost::asio::bind_executor(strand_, [this](boost::system::error_code ec, tcp::socket socket)
                {
                    if (!ec)
                    {
                        std::make_shared<chat_session>(
                                boost::asio::ssl::stream<tcp::socket>(
                                        std::move(socket), context_), room_, strand_)->start();
                    }

                    do_accept();
                }));
    }

    tcp::acceptor acceptor_;
    chat_room room_;
    boost::asio::io_context::strand& strand_;
    boost::asio::ssl::context context_;
    boost::filesystem::path full_path{boost::filesystem::current_path().parent_path()};
    boost::filesystem::path server_crt_path_ = full_path / "server.crt";
    boost::filesystem::path server_key_path = full_path / "server.key";
    boost::filesystem::path dh_path = full_path / "dh2048.pem";
};

//----------------------------------------------------------------------

int main(int argc, char* argv[])
{
    try
    {
        if (argc < 2)
        {
            std::cerr << "Usage: chat_server <port> [<port> ...]\n";
            return 1;
        }
        int port = 1234;
        int thread_number = 3;
        boost::asio::io_context io_context;
        std::vector<std::thread> server_threads;

        tcp::endpoint endpoint(tcp::v4(), port);
        boost::asio::io_context::strand strand_ = boost::asio::io_service::strand(io_context);
        std::shared_ptr<chat_server> server = std::make_shared<chat_server>(io_context, endpoint, strand_);

        // Run the I/O service on the requested number of threads
        boost::asio::signal_set signals(io_context, SIGINT, SIGTERM);
        signals.async_wait(
                [&io_context](boost::system::error_code const&, int)
                {
                    // Stop the io_context. This will cause run()
                    // to return immediately, eventually destroying the
                    // io_context and any remaining handlers in it.
                    io_context.stop();
                });
        // Run the I/O service on the requested number of threads
        server_threads.reserve(thread_number);
        for(auto i = thread_number - 1; i > 0; --i)
            server_threads.emplace_back(
                    [&io_context]
                    {
                        io_context.run();
                    });
        io_context.run();
        // Block until all the threads exit
        for (auto& i: server_threads)
            i.join();
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}
