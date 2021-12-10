#include <ripple/protocol/KeyType.h>
#include <ripple/protocol/Seed.h>
#include <Overlay.h>
#include <make_SSLContext.h>

#include <boost/regex.hpp>

namespace ripple {

Overlay::Overlay(
    boost::asio::io_service& io_service,
    std::vector<std::string> const& peers,
    std::unordered_map<int, bool> const& messagesToLog)
    : io_service_(io_service)
    , sharedContext_(make_SSLContext(""))
    , identity_(ripple::generateKeyPair(
          ripple::KeyType::secp256k1,
          ripple::generateSeed("masterpassphrase")))
    , timer_(io_service)
    , strand_(io_service)
    , messagesToLog_(messagesToLog)
{
    for (auto& peer : peers)
        peers_.emplace(peer, nullptr);
}

void
Overlay::runPeers()
{
    using namespace boost::asio::ip;
    for (auto const& [peerAddr, p] : peers_)
    {
        if (p != nullptr)
            continue;
        std::uint16_t port = 51235;
        std::string addr = peerAddr;
        boost::regex rx("^([^:]+):(\\d+)$");
        boost::smatch match;
        if (boost::regex_search(peerAddr, match, rx))
        {
            addr = match[1];
            port = std::stoi(match[2]);
        }
        auto const ep = tcp::endpoint{address::from_string(addr), port};
        auto peer = std::make_shared<Peer>(
            *this, io_service_, sharedContext_, ep, identity_);
        {
            peers_.emplace(peerAddr, peer);
        }
        peer->run();
    }
}

void
Overlay::start()
{
    if (!strand_.running_in_this_thread())
        return post(strand_, std::bind(&Overlay::start, shared_from_this()));
    runPeers();
}

void
Overlay::setTimer()
{
    error_code ec;
    timer_.expires_from_now(std::chrono::seconds(15), ec);
    if (ec)
    {
        return;
    }

    timer_.async_wait(strand_.wrap(std::bind(
        &Overlay::onTimer, shared_from_this(), std::placeholders::_1)));
}

void
Overlay::onTimer(error_code ec)
{
    if (ec == boost::asio::error::operation_aborted)
        return;
    if (ec)
    {
        // This should never happen
        return;
    }

    runPeers();

    setTimer();
}

void
Overlay::onPeerDestroyed(const std::string& peerAddr)
{
    if (!strand_.running_in_this_thread())
        return post(
            strand_,
            std::bind(&Overlay::onPeerDestroyed, shared_from_this(), peerAddr));

    if (auto it = peers_.find(peerAddr); it != peers_.end())
        it->second = nullptr;
}

void
Overlay::onManifests(protocol::TMManifests& m)
{
    if (!strand_.running_in_this_thread())
        return post(
            strand_, std::bind(&Overlay::onManifests, shared_from_this(), m));
    auto const n = m.list_size();
    for (int i = 0; i < n; ++i)
    {
        auto& st = m.list().Get(i).stobject();
        auto s = ripple::makeSlice(st);
        if (s.empty())
            return;

        static ripple::SOTemplate const manifestFormat{
            // A manifest must include:
            // - the master public key
            {ripple::sfPublicKey, ripple::soeREQUIRED},

            // - a signature with that public key
            {ripple::sfMasterSignature, ripple::soeREQUIRED},

            // - a sequence number
            {ripple::sfSequence, ripple::soeREQUIRED},

            // It may, optionally, contain:
            // - a version number which defaults to 0
            {ripple::sfVersion, ripple::soeDEFAULT},

            // - a domain name
            {ripple::sfDomain, ripple::soeOPTIONAL},

            // - an ephemeral signing key that can be changed as necessary
            {ripple::sfSigningPubKey, ripple::soeOPTIONAL},

            // - a signature using the ephemeral signing key, if it is present
            {ripple::sfSignature, ripple::soeOPTIONAL},
        };

        try
        {
            ripple::SerialIter sit{s};
            ripple::STObject st{sit, ripple::sfGeneric};

            st.applyTemplate(manifestFormat);

            if (st.isFieldPresent(ripple::sfVersion) &&
                st.getFieldU16(ripple::sfVersion) != 0)
                return;

            auto const pk = st.getFieldVL(ripple::sfPublicKey);

            if (!ripple::publicKeyType(ripple::makeSlice(pk)))
                return;

            auto const masterKey = ripple::PublicKey(ripple::makeSlice(pk));
            if (!st.isFieldPresent(ripple::sfSigningPubKey))
                return;

            auto const spk = st.getFieldVL(ripple::sfSigningPubKey);

            if (!ripple::publicKeyType(ripple::makeSlice(spk)))
                return;

            auto const signingKey = ripple::PublicKey(ripple::makeSlice(spk));
            {
                std::lock_guard l(manifestsMutex_);
                signingToMasterKeys_.emplace(signingKey, masterKey);
            }
        }
        catch (...)
        {
        }
    }
}

}  // namespace ripple
