#ifndef XRPL_PEERSMON_OVERLAY_H
#define XRPL_PEERSMON_OVERLAY_H

#include <ripple/protocol/PublicKey.h>
#include <ripple/protocol/SecretKey.h>
#include <ripple/protocol/messages.h>
#include <Peer.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl/context.hpp>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace ripple {

class Overlay : public std::enable_shared_from_this<Overlay>
{
private:
    using error_code = boost::system::error_code;
    using shared_context = std::shared_ptr<boost::asio::ssl::context>;
    using endpoint_type = boost::asio::ip::tcp::endpoint;
    boost::asio::io_service& io_service_;
    shared_context sharedContext_;
    std::unordered_map<std::string, std::shared_ptr<Peer>> peers_;
    std::pair<ripple::PublicKey, ripple::SecretKey> identity_;
    boost::asio::basic_waitable_timer<std::chrono::steady_clock> timer_;
    std::mutex peersMutex_;
    boost::asio::io_service::strand strand_;
    std::mutex manifestsMutex_;
    ripple::hash_map<ripple::PublicKey, ripple::PublicKey> signingToMasterKeys_;
    std::unordered_map<int, bool> const& messagesToLog_;

public:
    Overlay(
        boost::asio::io_service& io_service,
        std::vector<std::string> const& peers,
        std::unordered_map<int, bool> const& messagesToLog);
    void
    start();
    void
    onPeerDestroyed(std::string const&);
    void
    onManifests(protocol::TMManifests& m);
    std::optional<ripple::PublicKey>
    haveSigning(ripple::PublicKey const& key) const
    {
        std::lock_guard l(manifestsMutex_);
        auto it = signingToMasterKeys_.find(key);
        if (it != signingToMasterKeys_.end())
            return it->second;
        return std::nullopt;
    }
    bool
    shouldLog(int type)
    {
        return messagesToLog_.find(type) != messagesToLog_.end();
    }

private:
    void
    setTimer();
    void onTimer(error_code);
    void
    runPeers();
};

}  // namespace ripple

#endif  // XRPL_PEERSMON_OVERLAY_H
