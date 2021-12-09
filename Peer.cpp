#include <ripple/basics/base64.h>
#include <ripple/beast/utility/Zero.h>
#include <ripple/json/json_value.h>
#include <ripple/json/to_string.h>
#include <ripple/protocol/STTx.h>
#include <ripple/protocol/STValidation.h>
#include <ripple/protocol/Serializer.h>
#include <ripple/protocol/digest.h>
#include <Message.h>
#include <Overlay.h>
#include <Peer.h>
#include <ProtocolMessage.h>

#include <iostream>

namespace ripple {

Peer::Peer(
    Overlay& overlay,
    boost::asio::io_service& io_service,
    shared_context const& context,
    endpoint_type const& endpoint,
    identity_type const& identity,
    std::unordered_map<int, bool> const& shouldLog)
    : overlay_(overlay)
    , strand_{io_service}
    , streamPtr_(std::make_unique<stream_type>(
          socket_type(std::forward<boost::asio::io_service&>(io_service)),
          *context))
    , socket_(streamPtr_->next_layer().socket())
    , stream_(*streamPtr_)
    , remoteEndpoint_(endpoint)
    , identity_(identity)
    , timer_(io_service)
    , shouldLog_(shouldLog)
{
}

Peer::~Peer()
{
    overlay_.onPeerDestroyed(remoteEndpoint_.address().to_string());
}

void
Peer::setTimer()
{
    error_code ec;
    timer_.expires_from_now(std::chrono::seconds(15), ec);
    if (ec)
    {
        return;
    }

    timer_.async_wait(strand_.wrap(
        std::bind(&Peer::onTimer, shared_from_this(), std::placeholders::_1)));
}

void
Peer::cancelTimer()
{
    error_code ec;
    timer_.cancel(ec);
}

void
Peer::onTimer(error_code ec)
{
    if (!socket_.is_open())
        return;
    if (ec == boost::asio::error::operation_aborted)
        return;
    fail("operation timed-out");
}

void
Peer::fail(std::string const& message)
{
    std::lock_guard l(logMutex_);
    using namespace std::chrono;
    auto now =
        duration_cast<milliseconds>(system_clock::now().time_since_epoch())
            .count();
    std::cout << "{" << qstr("tstamp") << ":" << now << ", " << qstr("host")
              << ":"
              << "\"" << remoteEndpoint_ << "\""
              << ", " << qstr("error") << ":" << qstr(message) << "}\n";
    close();
}

void
Peer::run()
{
    setTimer();
    stream_.next_layer().async_connect(
        remoteEndpoint_,
        strand_.wrap(std::bind(
            &Peer::onConnect, shared_from_this(), std::placeholders::_1)));
}

void
Peer::onConnect(error_code ec)
{
    cancelTimer();

    if (ec == boost::asio::error::operation_aborted)
        return;
    endpoint_type local_endpoint;
    if (!ec)
        local_endpoint = socket_.local_endpoint(ec);
    if (ec)
        return fail(ec.message());
    if (!socket_.is_open())
        return;

    setTimer();
    stream_.set_verify_mode(boost::asio::ssl::verify_none);
    stream_.async_handshake(
        boost::asio::ssl::stream_base::client,
        strand_.wrap(std::bind(
            &Peer::onHandshake, shared_from_this(), std::placeholders::_1)));
}

static std::optional<base_uint<512>>
hashLastMessage(SSL const* ssl, size_t (*get)(const SSL*, void*, size_t))
{
    constexpr std::size_t sslMinimumFinishedLength = 12;

    unsigned char buf[1024];
    size_t len = get(ssl, buf, sizeof(buf));

    if (len < sslMinimumFinishedLength)
        return std::nullopt;

    ripple::sha512_hasher h;

    ripple::base_uint<512> cookie;
    SHA512(buf, len, cookie.data());
    return cookie;
}

std::optional<ripple::uint256>
Peer::makeSharedValue(stream_type& ssl)
{
    auto const cookie1 =
        ripple::hashLastMessage(ssl.native_handle(), SSL_get_finished);
    if (!cookie1)
    {
        return std::nullopt;
    }

    auto const cookie2 =
        ripple::hashLastMessage(ssl.native_handle(), SSL_get_peer_finished);
    if (!cookie2)
    {
        return std::nullopt;
    }

    auto const result = (*cookie1 ^ *cookie2);

    // Both messages hash to the same value and the cookie
    // is 0. Don't allow this.
    if (result == beast::zero)
    {
        return std::nullopt;
    }

    return sha512Half(Slice(result.data(), result.size()));
}

void
Peer::onHandshake(error_code ec)
{
    cancelTimer();
    if (!socket_.is_open())
        return;
    if (ec == boost::asio::error::operation_aborted)
        return;
    if (ec)
        return fail(ec.message());
    req_.method(boost::beast::http::verb::get);
    req_.target("/");
    req_.version(11);
    req_.insert("User-Agent", "rippled-1.8.0");
    req_.insert("Upgrade", "XRPL/2.0");
    req_.insert("Connection", "Upgrade");
    req_.insert("Connect-As", "Peer");
    req_.insert("Crawl", "private");
    req_.insert(
        "Public-Key",
        ripple::toBase58(ripple::TokenType::NodePublic, identity_.first));
    auto const sharedValue = makeSharedValue(*streamPtr_);
    if (!sharedValue)
        return;
    auto const sig =
        ripple::signDigest(identity_.first, identity_.second, *sharedValue);
    req_.insert(
        "Session-Signature", ripple::base64_encode(sig.data(), sig.size()));

    setTimer();
    boost::beast::http::async_write(
        stream_,
        req_,
        strand_.wrap(std::bind(
            &Peer::onWrite, shared_from_this(), std::placeholders::_1)));
}

void
Peer::onWrite(error_code ec)
{
    cancelTimer();
    if (!socket_.is_open())
        return;
    if (ec == boost::asio::error::operation_aborted)
        return;
    if (ec)
        return fail(ec.message());
    setTimer();
    boost::beast::http::async_read(
        stream_,
        read_buf_,
        response_,
        strand_.wrap(std::bind(
            &Peer::onRead, shared_from_this(), std::placeholders::_1)));
}

void
Peer::onRead(error_code ec)
{
    cancelTimer();
    if (!socket_.is_open())
        return;
    if (ec == boost::asio::error::operation_aborted)
        return;
    if (ec == boost::asio::error::eof)
    {
        setTimer();
        return stream_.async_shutdown(strand_.wrap(std::bind(
            &Peer::onShutdown, shared_from_this(), std::placeholders::_1)));
    }
    if (ec)
        return fail(ec.message());
    processResponse();
}

void
Peer::onShutdown(error_code ec)
{
    cancelTimer();
    close();
}

void
Peer::close()
{
    if (socket_.is_open())
    {
        error_code ec;
        socket_.close(ec);
    }
}

//--------------------------------------------------------------------------

void
Peer::processResponse()
{
    // 503
    if (response_.result() == boost::beast::http::status::service_unavailable)
        return fail("service unavailable");

    // not the upgrade
    if (response_.version() < 11)
        return fail("not upgrade");
    if (!boost::beast::http::token_list{response_["Connection"]}.exists(
            "upgrade"))
        return fail("not upgrade");

    auto const sharedValue = makeSharedValue(*streamPtr_);
    if (!sharedValue)
        return fail("failed shared value");  // makeSharedValue logs

    try
    {
        // verify handshake
        PublicKey const publicKey = [&] {
            if (auto const iter = response_.find("Public-Key");
                iter != response_.end())
            {
                auto pk = ripple::parseBase58<ripple::PublicKey>(
                    ripple::TokenType::NodePublic, iter->value().to_string());

                if (pk)
                {
                    if (ripple::publicKeyType(*pk) !=
                        ripple::KeyType::secp256k1)
                        throw std::runtime_error("Unsupported public key type");

                    return *pk;
                }
            }

            throw std::runtime_error("Bad node public key");
        }();

        {
            auto const iter = response_.find("Session-Signature");

            if (iter == response_.end())
                throw std::runtime_error("No session signature specified");

            auto sig = ripple::base64_decode(iter->value().to_string());

            if (!ripple::verifyDigest(
                    publicKey, *sharedValue, makeSlice(sig), false))
                throw std::runtime_error("Failed to verify session");
        }
    }
    catch (std::exception const& e)
    {
        return fail(e.what());
    }
    onReadMessage(error_code(), 0);
}

void
Peer::onReadMessage(error_code ec, std::size_t bytes_transferred)
{
    if (!socket_.is_open())
        return;
    if (ec == boost::asio::error::operation_aborted)
        return;
    if (ec == boost::asio::error::eof)
    {
        return gracefulClose();
    }
    if (ec)
        return fail(ec.message());

    read_buf_.commit(bytes_transferred);

    std::size_t const readBufferBytes = 16384;

    auto hint = readBufferBytes;

    while (read_buf_.size() > 0)
    {
        std::size_t bytes_consumed;
        std::tie(bytes_consumed, ec) =
            invokeProtocolMessage(read_buf_.data(), *this, hint);
        if (ec)
            return fail(ec.message());
        if (!socket_.is_open())
            return;
        if (gracefulClose_)
            return;
        if (bytes_consumed == 0)
            break;
        read_buf_.consume(bytes_consumed);
    }

    // Timeout on writes only
    stream_.async_read_some(
        read_buf_.prepare(std::max(readBufferBytes, hint)),
        std::bind(
            &Peer::onReadMessage,
            shared_from_this(),
            std::placeholders::_1,
            std::placeholders::_2));
}

void
Peer::gracefulClose()
{
    gracefulClose_ = true;
    stream_.async_shutdown(bind_executor(
        strand_,
        std::bind(
            &Peer::onShutdown, shared_from_this(), std::placeholders::_1)));
}

void
Peer::send(std::shared_ptr<Message> const& m)
{
    auto shared = shared_from_this();
    boost::asio::async_write(
        stream_,
        boost::asio::buffer(m->getBuffer(compression::Compressed::Off)),
        [shared, m](error_code ec, std::size_t bytes_transferred) {
            if (!shared->socket_.is_open())
                return;
            if (ec == boost::asio::error::operation_aborted)
                return;
            if (ec)
                shared->fail(ec.message());
        });
}

void
Peer::onMessageBegin(const MessageHeader& h)
{
    using namespace std::chrono;
    auto now =
        duration_cast<milliseconds>(system_clock::now().time_since_epoch())
            .count();
    std::cout << "{" << qstr("tstamp") << ":" << now << ", " << qstr("host")
              << ":" << qstr(remoteEndpoint_.address().to_string()) << ", "
              << qstr("type") << ":" << h.message_type << ", "
              << qstr("msgsize") << ":" << h.total_wire_size;
}

void
Peer::onMessageEnd()
{
    std::cout << "}" << std::endl;
}

void
Peer::onMessage(protocol::TMManifests& m)
{
    overlay_.onManifests(m);
    std::lock_guard l(logMutex_);
    if (shouldLog(protocol::mtMANIFESTS))
        dumpJson("size", m.list_size());
}

void
Peer::onMessage(protocol::TMPing& m)
{
    m.set_type(protocol::TMPing::ptPONG);
    send(std::make_shared<Message>(m, protocol::mtPING));
    if (shouldLog(protocol::mtPING))
        dumpJson(
            qstr("seq"),
            m.seq(),
            qstr("pingtime"),
            m.pingtime(),
            qstr("nettime"),
            m.nettime());
}

void
Peer::onMessage(protocol::TMCluster& m)
{
    dumpJson(
        qstr("sizenodes"),
        m.clusternodes_size(),
        qstr("sizesources"),
        m.loadsources_size());
}

void
Peer::onMessage(protocol::TMEndpoints& m)
{
    dumpJson(qstr("size"), m.endpoints_v2_size());
}

void
Peer::onMessage(protocol::TMTransaction& m)
{
    const std::string& st = m.rawtransaction();
    ripple::SerialIter sit(ripple::makeSlice(st));
    ripple::STTx stx(sit);
    ripple::uint256 txID = stx.getTransactionID();
    dumpJson(qstr("txhash"), qstr(txID));
}

void
Peer::onMessage(protocol::TMGetLedger& m)
{
    dumpJson(qstr("itype"), m.itype());
}

void
Peer::onMessage(protocol::TMLedgerData& m)
{
    dumpJson(
        qstr("hash"),
        ripple::uint256{m.ledgerhash()},
        qstr("seq"),
        m.ledgerseq(),
        qstr("itype"),
        m.type());
}

ripple::uint256
proposalUniqueId(
    ripple::uint256 const& proposeHash,
    ripple::uint256 const& previousLedger,
    std::uint32_t proposeSeq,
    ripple::NetClock::time_point closeTime,
    ripple::Slice const& publicKey,
    ripple::Slice const& signature)
{
    ripple::Serializer s(512);
    s.addBitString(proposeHash);
    s.addBitString(previousLedger);
    s.add32(proposeSeq);
    s.add32(closeTime.time_since_epoch().count());
    s.addVL(publicKey);
    s.addVL(signature);

    return s.getSHA512Half();
}

void
Peer::onMessage(protocol::TMProposeSet& m)
{
    ripple::uint256 const proposeHash{m.currenttxhash()};
    ripple::uint256 const prevLedger{m.previousledger()};
    ripple::PublicKey const publicKey{ripple::makeSlice(m.nodepubkey())};
    ripple::NetClock::time_point const closeTime{
        ripple::NetClock::duration{m.closetime()}};
    auto const sig = ripple::makeSlice(m.signature());

    auto const propID = proposalUniqueId(
        proposeHash,
        prevLedger,
        m.proposeseq(),
        closeTime,
        publicKey.slice(),
        sig);
    dumpJson(
        qstr("validator"),
        qstr(ripple::makeSlice(m.nodepubkey())),
        qstr("prophash"),
        qstr(propID));
}

void
Peer::onMessage(protocol::TMStatusChange& m)
{
    if (m.has_newstatus())
        dumpJson(qstr("newstatus"), m.newstatus());
}

void
Peer::onMessage(protocol::TMHaveTransactionSet& m)
{
    dumpJson(
        qstr("status"), m.status(), qstr("hash"), ripple::uint256(m.hash()));
}

void
Peer::onMessage(protocol::TMValidation& m)
{
    auto valID = ripple::sha512Half(ripple::makeSlice(m.validation()));
    ripple::SerialIter sit(ripple::makeSlice(m.validation()));
    ripple::STValidation stval(
        std::ref(sit),
        [&](ripple::PublicKey const& pk) {
            if (auto master = overlay_.haveSigning(pk); master)
                return ripple::calcNodeID(*master);
            dumpJson(
                qstr("error"),
                qstr("manifest sigpk to master not found"),
                qstr("key"),
                qstr(ripple::Slice(pk)));
            return ripple::NodeID{1};
        },
        false);
    dumpJson(
        qstr("validator"),
        qstr(ripple::Slice(stval.getSignerPublic())),
        qstr("valhash"),
        qstr(valID));
}

void
Peer::onMessage(protocol::TMGetPeerShardInfo& m)
{
}

void
Peer::onMessage(protocol::TMPeerShardInfo& m)
{
}

void
Peer::onMessage(protocol::TMValidatorList& m)
{
    dumpJson(qstr("version"), m.version());
}

void
Peer::onMessage(protocol::TMValidatorListCollection& m)
{
    dumpJson(qstr("version"), m.version());
}

void
Peer::onMessage(protocol::TMGetObjectByHash& m)
{
    dumpJson(
        qstr("type"),
        m.type(),
        qstr("query"),
        m.query(),
        qstr("size"),
        m.objects_size());
}

void
Peer::onMessage(protocol::TMHaveTransactions& m)
{
    dumpJson(qstr("size_hashes"), m.hashes_size());
}

void
Peer::onMessage(protocol::TMTransactions& m)
{
    dumpJson(qstr("size_transactions"), m.transactions_size());
}

void
Peer::onMessage(protocol::TMSquelch& m)
{
    dumpJson(
        qstr("squelch"),
        m.squelch(),
        qstr("valhash"),
        ripple::uint256{m.validatorpubkey()});
}

void
Peer::onMessage(protocol::TMProofPathRequest& m)
{
    dumpJson(
        qstr("key"),
        ripple::uint256{m.key()},
        qstr("ledger_hash"),
        ripple::uint256{m.ledgerhash()});
}

void
Peer::onMessage(protocol::TMProofPathResponse& m)
{
    dumpJson(
        qstr("key"),
        ripple::uint256{m.key()},
        qstr("ledger_hash"),
        ripple::uint256{m.ledgerhash()},
        qstr("type"),
        m.type());
}

void
Peer::onMessage(protocol::TMReplayDeltaRequest& m)
{
    dumpJson(qstr("ledger_hash"), ripple::uint256{m.ledgerhash()});
}

void
Peer::onMessage(protocol::TMReplayDeltaResponse& m)
{
    dumpJson(qstr("ledger_hash"), ripple::uint256{m.ledgerhash()});
}

void
Peer::onMessage(protocol::TMGetPeerShardInfoV2& m)
{
    dumpJson(
        qstr("peerchain_size"), m.peerchain_size(), qstr("relays"), m.relays());
}

void
Peer::onMessage(protocol::TMPeerShardInfoV2& m)
{
    dumpJson(
        qstr("timestamp"), m.timestamp(), qstr("publickey"), m.publickey());
}

}  // namespace ripple
