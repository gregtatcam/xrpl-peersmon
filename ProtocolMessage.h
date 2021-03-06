//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2012, 2013 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#ifndef RIPPLE_OVERLAY_PROTOCOLMESSAGE_H_INCLUDED
#define RIPPLE_OVERLAY_PROTOCOLMESSAGE_H_INCLUDED

#include <ripple/basics/ByteUtilities.h>
#include <ripple/overlay/Compression.h>
#include <ripple/overlay/impl/ZeroCopyStream.h>
#include <ripple/protocol/messages.h>
#include <ripple.pb.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/buffers_iterator.hpp>
#include <boost/system/error_code.hpp>
#include <cassert>
#include <cstdint>
#include <memory>
#include <optional>
#include <type_traits>
#include <vector>

namespace ripple {

struct MessageHeader
{
    /** The size of the message on the wire.

        @note This is the sum of sizes of the header and the payload.
    */
    std::uint32_t total_wire_size = 0;

    /** The size of the header associated with this message. */
    std::uint32_t header_size = 0;

    /** The size of the payload on the wire. */
    std::uint32_t payload_wire_size = 0;

    /** Uncompressed message size if the message is compressed. */
    std::uint32_t uncompressed_size = 0;

    /** The type of the message. */
    std::uint16_t message_type = 0;

    /** Indicates which compression algorithm the payload is compressed with.
     * Currenly only lz4 is supported. If None then the message is not
     * compressed.
     */
    compression::Algorithm algorithm = compression::Algorithm::None;
};

template <typename BufferSequence>
auto
buffersBegin(BufferSequence const& bufs)
{
    return boost::asio::buffers_iterator<BufferSequence, std::uint8_t>::begin(
        bufs);
}

template <typename BufferSequence>
auto
buffersEnd(BufferSequence const& bufs)
{
    return boost::asio::buffers_iterator<BufferSequence, std::uint8_t>::end(
        bufs);
}

/** Parse a message header
 * @return a seated optional if the message header was successfully
 *         parsed. An unseated optional otherwise, in which case
 *         @param ec contains more information:
 *         - set to `errc::success` if not enough bytes were present
 *         - set to `errc::no_message` if a valid header was not present
 *         @bufs - sequence of input buffers, can't be empty
 *         @size input data size
 */
template <class BufferSequence>
std::optional<MessageHeader>
parseMessageHeader(
    boost::system::error_code& ec,
    BufferSequence const& bufs,
    std::size_t size)
{
    using namespace ripple::compression;

    MessageHeader hdr;
    auto iter = buffersBegin(bufs);
    assert(iter != buffersEnd(bufs));

    // Check valid header compressed message:
    // - 4 bits are the compression algorithm, 1st bit is always set to 1
    // - 2 bits are always set to 0
    // - 26 bits are the payload size
    // - 32 bits are the uncompressed data size
    if (*iter & 0x80)
    {
        hdr.header_size = headerBytesCompressed;

        // not enough bytes to parse the header
        if (size < hdr.header_size)
        {
            ec = make_error_code(boost::system::errc::success);
            return std::nullopt;
        }

        if (*iter & 0x0C)
        {
            ec = make_error_code(boost::system::errc::protocol_error);
            return std::nullopt;
        }

        hdr.algorithm = static_cast<compression::Algorithm>(*iter & 0xF0);

        if (hdr.algorithm != compression::Algorithm::LZ4)
        {
            ec = make_error_code(boost::system::errc::protocol_error);
            return std::nullopt;
        }

        for (int i = 0; i != 4; ++i)
            hdr.payload_wire_size = (hdr.payload_wire_size << 8) + *iter++;

        // clear the top four bits (the compression bits).
        hdr.payload_wire_size &= 0x0FFFFFFF;

        hdr.total_wire_size = hdr.header_size + hdr.payload_wire_size;

        for (int i = 0; i != 2; ++i)
            hdr.message_type = (hdr.message_type << 8) + *iter++;

        for (int i = 0; i != 4; ++i)
            hdr.uncompressed_size = (hdr.uncompressed_size << 8) + *iter++;

        return hdr;
    }

    // Check valid header uncompressed message:
    // - 6 bits are set to 0
    // - 26 bits are the payload size
    if ((*iter & 0xFC) == 0)
    {
        hdr.header_size = headerBytes;

        if (size < hdr.header_size)
        {
            ec = make_error_code(boost::system::errc::success);
            return std::nullopt;
        }

        hdr.algorithm = Algorithm::None;

        for (int i = 0; i != 4; ++i)
            hdr.payload_wire_size = (hdr.payload_wire_size << 8) + *iter++;

        hdr.uncompressed_size = hdr.payload_wire_size;
        hdr.total_wire_size = hdr.header_size + hdr.payload_wire_size;

        for (int i = 0; i != 2; ++i)
            hdr.message_type = (hdr.message_type << 8) + *iter++;

        return hdr;
    }

    ec = make_error_code(boost::system::errc::no_message);
    return std::nullopt;
}

template <
    class T,
    class Buffers,
    class = std::enable_if_t<
        std::is_base_of<::google::protobuf::Message, T>::value>>
std::optional<T>
parseMessageContent(MessageHeader const& header, Buffers const& buffers)
{
    auto m = T{};

    ZeroCopyInputStream<Buffers> stream(buffers);
    stream.Skip(header.header_size);

    if (header.algorithm != compression::Algorithm::None)
    {
        std::vector<std::uint8_t> payload;
        payload.resize(header.uncompressed_size);

        auto const payloadSize = ripple::compression::decompress(
            stream,
            header.payload_wire_size,
            payload.data(),
            header.uncompressed_size,
            header.algorithm);

        if (payloadSize == 0 || !m.ParseFromArray(payload.data(), payloadSize))
            return {};
    }
    else if (!m.ParseFromZeroCopyStream(&stream))
        return {};

    return m;
}

template <
    class T,
    class Buffers,
    class Handler,
    class = std::enable_if_t<
        std::is_base_of<::google::protobuf::Message, T>::value>>
bool
invoke(MessageHeader const& header, Buffers const& buffers, Handler& handler)
{
    // don't parse/handle if don't need to log unless it's ping or manifest
    // which have to be processed but might not be logged
    if (!handler.shouldLog(header.message_type) &&
        header.message_type != protocol::mtPING &&
        header.message_type != protocol::mtMANIFESTS)
        return true;
    auto m = parseMessageContent<T>(header, buffers);
    if (!m)
        return false;
    if (handler.shouldLog(header.message_type))
        handler.onMessageBegin(header);
    handler.onMessage(*m);
    if (handler.shouldLog(header.message_type))
        handler.onMessageEnd();

    return true;
}

/** Calls the handler for up to one protocol message in the passed buffers.

    If there is insufficient data to produce a complete protocol
    message, zero is returned for the number of bytes consumed.

    @param buffers The buffer that contains the data we've received
    @param handler The handler that will be used to process the message
    @param hint If possible, a hint as to the amount of data to read next. The
                returned value MAY be zero, which means "no hint"

    @return The number of bytes consumed, or the error code if any.
*/
template <class Buffers, class Handler>
std::pair<std::size_t, boost::system::error_code>
invokeProtocolMessage(
    Buffers const& buffers,
    Handler& handler,
    std::size_t& hint)
{
    std::pair<std::size_t, boost::system::error_code> result = {0, {}};

    auto const size = boost::asio::buffer_size(buffers);

    if (size == 0)
        return result;

    auto header = parseMessageHeader(result.second, buffers, size);

    // If we can't parse the header then it may be that we don't have enough
    // bytes yet, or because the message was cut off (if error_code is success).
    // Otherwise we failed to match the header's marker (error_code is set to
    // no_message) or the compression algorithm is invalid (error_code is
    // protocol_error) and signal an error.
    if (!header)
        return result;

    // We implement a maximum size for protocol messages. Sending a message
    // whose size exceeds this may result in the connection being dropped. A
    // larger message size may be supported in the future or negotiated as
    // part of a protocol upgrade.
    if (header->payload_wire_size > maximiumMessageSize ||
        header->uncompressed_size > maximiumMessageSize)
    {
        result.second = make_error_code(boost::system::errc::message_size);
        return result;
    }

    // We requested uncompressed messages from the peer but received compressed.
    if (header->algorithm != compression::Algorithm::None)
    {
        result.second = make_error_code(boost::system::errc::protocol_error);
        return result;
    }

    // We don't have the whole message yet. This isn't an error but we have
    // nothing to do.
    if (header->total_wire_size > size)
    {
        hint = header->total_wire_size - size;
        return result;
    }

    bool success;

    switch (header->message_type)
    {
        case protocol::mtMANIFESTS:
            success = invoke<protocol::TMManifests>(*header, buffers, handler);
            break;
        case protocol::mtPING:
            success = invoke<protocol::TMPing>(*header, buffers, handler);
            break;
        case protocol::mtCLUSTER:
            success = invoke<protocol::TMCluster>(*header, buffers, handler);
            break;
        case protocol::mtENDPOINTS:
            success = invoke<protocol::TMEndpoints>(*header, buffers, handler);
            break;
        case protocol::mtTRANSACTION:
            success =
                invoke<protocol::TMTransaction>(*header, buffers, handler);
            break;
        case protocol::mtGET_LEDGER:
            success = invoke<protocol::TMGetLedger>(*header, buffers, handler);
            break;
        case protocol::mtLEDGER_DATA:
            success = invoke<protocol::TMLedgerData>(*header, buffers, handler);
            break;
        case protocol::mtPROPOSE_LEDGER:
            success = invoke<protocol::TMProposeSet>(*header, buffers, handler);
            break;
        case protocol::mtSTATUS_CHANGE:
            success =
                invoke<protocol::TMStatusChange>(*header, buffers, handler);
            break;
        case protocol::mtHAVE_SET:
            success = invoke<protocol::TMHaveTransactionSet>(
                *header, buffers, handler);
            break;
        case protocol::mtVALIDATION:
            success = invoke<protocol::TMValidation>(*header, buffers, handler);
            break;
        case protocol::mtGET_PEER_SHARD_INFO:
            success =
                invoke<protocol::TMGetPeerShardInfo>(*header, buffers, handler);
            break;
        case protocol::mtPEER_SHARD_INFO:
            success =
                invoke<protocol::TMPeerShardInfo>(*header, buffers, handler);
            break;
        case protocol::mtVALIDATORLIST:
            success =
                invoke<protocol::TMValidatorList>(*header, buffers, handler);
            break;
        case protocol::mtVALIDATORLISTCOLLECTION:
            success = invoke<protocol::TMValidatorListCollection>(
                *header, buffers, handler);
            break;
        case protocol::mtGET_OBJECTS:
            success =
                invoke<protocol::TMGetObjectByHash>(*header, buffers, handler);
            break;
        case protocol::mtHAVE_TRANSACTIONS:
            success =
                invoke<protocol::TMHaveTransactions>(*header, buffers, handler);
            break;
        case protocol::mtTRANSACTIONS:
            success =
                invoke<protocol::TMTransactions>(*header, buffers, handler);
            break;
        case protocol::mtSQUELCH:
            success = invoke<protocol::TMSquelch>(*header, buffers, handler);
            break;
        case protocol::mtPROOF_PATH_REQ:
            success =
                invoke<protocol::TMProofPathRequest>(*header, buffers, handler);
            break;
        case protocol::mtPROOF_PATH_RESPONSE:
            success = invoke<protocol::TMProofPathResponse>(
                *header, buffers, handler);
            break;
        case protocol::mtREPLAY_DELTA_REQ:
            success = invoke<protocol::TMReplayDeltaRequest>(
                *header, buffers, handler);
            break;
        case protocol::mtREPLAY_DELTA_RESPONSE:
            success = invoke<protocol::TMReplayDeltaResponse>(
                *header, buffers, handler);
            break;
        case protocol::mtGET_PEER_SHARD_INFO_V2:
            success = invoke<protocol::TMGetPeerShardInfoV2>(
                *header, buffers, handler);
            break;
        case protocol::mtPEER_SHARD_INFO_V2:
            success =
                invoke<protocol::TMPeerShardInfoV2>(*header, buffers, handler);
            break;
        default:
            success = true;
            break;
    }

    result.first = header->total_wire_size;

    if (!success)
        result.second = make_error_code(boost::system::errc::bad_message);

    return result;
}

}  // namespace ripple

#endif
