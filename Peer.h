#ifndef XRPL_PEERSMON_PEER_H
#define XRPL_PEERSMON_PEER_H

#include <ripple/protocol/PublicKey.h>
#include <ripple/protocol/SecretKey.h>
#include <ripple/protocol/messages.h>

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <memory>
#include <unordered_map>

namespace ripple {

class Overlay;
class Message;
struct MessageHeader;

class Peer : public std::enable_shared_from_this<Peer>
{
private:
    using error_code = boost::system::error_code;

    using endpoint_type = boost::asio::ip::tcp::endpoint;

    using request_type =
        boost::beast::http::request<boost::beast::http::empty_body>;

    using response_type =
        boost::beast::http::response<boost::beast::http::dynamic_body>;

    using identity_type = std::pair<ripple::PublicKey, ripple::SecretKey>;

    using socket_type = boost::asio::ip::tcp::socket;
    using middle_type = boost::beast::tcp_stream;
    using stream_type = boost::beast::ssl_stream<middle_type>;
    using shared_context = std::shared_ptr<boost::asio::ssl::context>;

    Overlay& overlay_;
    boost::asio::io_service::strand strand_;
    std::unique_ptr<stream_type> streamPtr_;
    socket_type& socket_;
    stream_type& stream_;
    endpoint_type remoteEndpoint_;
    boost::beast::multi_buffer read_buf_;
    response_type response_;
    request_type req_;
    identity_type const& identity_;
    boost::asio::basic_waitable_timer<std::chrono::steady_clock> timer_;
    bool gracefulClose_ = false;
    static inline std::mutex logMutex_;
    std::unordered_map<int, bool> const& shouldLog_;

public:
    Peer(
        Overlay&,
        boost::asio::io_service& io_service,
        shared_context const& context,
        endpoint_type const& endpoint,
        identity_type const& identity,
        std::unordered_map<int, bool> const& shouldLog);

    ~Peer();

    void
    run();

    void
    onMessage(MessageHeader const&, protocol::TMManifests& m);
    void
    onMessage(MessageHeader const&, protocol::TMPing& m);
    void
    onMessage(MessageHeader const&, protocol::TMCluster& m);
    void
    onMessage(MessageHeader const&, protocol::TMEndpoints& m);
    void
    onMessage(MessageHeader const&, protocol::TMTransaction& m);
    void
    onMessage(MessageHeader const&, protocol::TMGetLedger& m);
    void
    onMessage(MessageHeader const&, protocol::TMLedgerData& m);
    void
    onMessage(MessageHeader const&, protocol::TMProposeSet& m);
    void
    onMessage(MessageHeader const&, protocol::TMStatusChange& m);
    void
    onMessage(MessageHeader const&, protocol::TMHaveTransactionSet& m);
    void
    onMessage(MessageHeader const&, protocol::TMValidation& m);
    void
    onMessage(MessageHeader const&, protocol::TMGetPeerShardInfo& m);
    void
    onMessage(MessageHeader const&, protocol::TMPeerShardInfo& m);
    void
    onMessage(MessageHeader const&, protocol::TMValidatorList& m);
    void
    onMessage(MessageHeader const&, protocol::TMValidatorListCollection& m);
    void
    onMessage(MessageHeader const&, protocol::TMGetObjectByHash& m);
    void
    onMessage(MessageHeader const&, protocol::TMHaveTransactions& m);
    void
    onMessage(MessageHeader const&, protocol::TMTransactions& m);
    void
    onMessage(MessageHeader const&, protocol::TMSquelch& m);
    void
    onMessage(MessageHeader const&, protocol::TMProofPathRequest& m);
    void
    onMessage(MessageHeader const&, protocol::TMProofPathResponse& m);
    void
    onMessage(MessageHeader const&, protocol::TMReplayDeltaRequest& m);
    void
    onMessage(MessageHeader const&, protocol::TMReplayDeltaResponse& m);
    void
    onMessage(MessageHeader const&, protocol::TMGetPeerShardInfoV2& m);
    void
    onMessage(MessageHeader const&, protocol::TMPeerShardInfoV2& m);

private:
    void
    setTimer();
    void
    cancelTimer();
    void onTimer(error_code);
    void
    onConnect(error_code ec);
    void
    onHandshake(error_code ec);
    std::optional<ripple::uint256>
    makeSharedValue(stream_type& ssl);
    void
    onWrite(error_code ec);
    void
    onRead(error_code ec);
    void
    onShutdown(error_code ec);
    void
    processResponse();
    void
    close();
    void onReadMessage(error_code, std::size_t);
    void
    gracefulClose();
    void
    send(std::shared_ptr<Message> const&);
    template <typename V>
    std::string
    qstr(V&& v)
    {
        std::stringstream str;
        str << "\"" << v << "\"";
        return str.str();
    }
    void
    dumpJson();
    template <typename Arg2, typename... Args>
    void
    dumpJson(
        MessageHeader const& h,
        std::string const& arg1,
        Arg2&& arg2,
        Args&&... args)
    {
        std::lock_guard l(logMutex_);
        dumpJson(h);
        std::cout << ", " << arg1 << ":" << arg2;
        dumpJson(args...);
    }
    void
    dumpJson(MessageHeader const& h);
    template <typename Arg2, typename... Args>
    void
    dumpJson(std::string const& arg1, Arg2&& arg2, Args&&... args)
    {
        std::cout << ", " << arg1 << ":" << arg2;
        dumpJson(args...);
    }
    bool
    shouldLog(int type)
    {
        return shouldLog_.find(type) != shouldLog_.end();
    }
};

}  // namespace ripple

#endif  // XRPL_PEERSMON_PEER_H
