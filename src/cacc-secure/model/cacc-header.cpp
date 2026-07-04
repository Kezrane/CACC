#include "cacc-header.hpp"
#include <ndn-cxx/encoding/tlv.hpp>

namespace ns3 {
namespace ndn {

CaccHeader::CaccHeader()
    : m_ph(0), m_ohc(0), m_seq(0), m_hmac(0) {}

CaccHeader::CaccHeader(uint8_t ph, uint8_t ohc, uint8_t seq, uint32_t hmacSignature)
    : m_ph(ph), m_ohc(ohc), m_seq(seq), m_hmac(hmacSignature & 0xFFFFFF) {}

template<ndn::encoding::EncoderTag TAG>
size_t CaccHeader::wireEncode(ndn::EncodingImpl<TAG>& encoder) const {
    size_t totalLength = 0;

    // Encode backwards due to ndn-cxx hardware vector optimizations
    // Encode Truncated HMAC (3 bytes)
    totalLength += encoder.prependByte(static_cast<uint8_t>(m_hmac & 0xFF));
    totalLength += encoder.prependByte(static_cast<uint8_t>((m_hmac >> 8) & 0xFF));
    totalLength += encoder.prependByte(static_cast<uint8_t>((m_hmac >> 16) & 0xFF));

    // Encode Single Byte Metadatas
    totalLength += encoder.prependByte(m_seq);
    totalLength += encoder.prependByte(m_ohc);
    totalLength += encoder.prependByte(m_ph);

    // Prepend total block type and length metadata descriptors
    totalLength += encoder.prependVarNumber(totalLength);
    totalLength += encoder.prependVarNumber(TLV_CACC_HEADER);

    return totalLength;
}

// Instantiate target templates explicitly for compilation
template size_t CaccHeader::wireEncode<ndn::encoding::EncoderTag::Estimator>(ndn::EncodingImpl<ndn::encoding::EncoderTag::Estimator>&) const;
template size_t CaccHeader::wireEncode<ndn::encoding::EncoderTag::Repository>(ndn::EncodingImpl<ndn::encoding::EncoderTag::Repository>&) const;

const ndn::Block& CaccHeader::wireEncode() const {
    if (m_wire.hasWire()) {
        return m_wire;
    }

    ndn::EncodingEstimator estimator;
    size_t estimatedSize = wireEncode(estimator);

    ndn::EncodingBuffer buffer(estimatedSize, 0);
    wireEncode(buffer);

    m_wire = buffer.block();
    return m_wire;
}

void CaccHeader::wireDecode(const ndn::Block& wire) {
    if (wire.type() != TLV_CACC_HEADER) {
        throw ndn::tlv::Error("Unexpected TLV Type encountered during CaccHeader parsing");
    }

    m_wire = wire;
    m_wire.parse();

    const uint8_t* valBuffer = m_wire.value();
    size_t valLength = m_wire.value_size();

    if (valLength != 6) {
        throw ndn::tlv::Error("Malformed block length: CaccHeader stream must occupy exactly 6 bytes");
    }

    // Unpack fields explicitly using direct byte alignment
    m_ph  = valBuffer[0];
    m_ohc = valBuffer[1];
    m_seq = valBuffer[2];
    
    // Reconstruct 3-byte integer
    m_hmac = (static_cast<uint32_t>(valBuffer[3]) << 16) |
             (static_cast<uint32_t>(valBuffer[4]) << 8)  |
             (static_cast<uint32_t>(valBuffer[5]));
}

} // namespace ndn
} // namespace ns3