#ifndef NDN_SIM_CACC_HEADER_HPP
#define NDN_SIM_CACC_HEADER_HPP

#include <ndn-cxx/encoding/block.hpp>
#include <ndn-cxx/encoding/encoding-buffer.hpp>
#include <cstdint>

namespace ns3 {
namespace ndn {

/**
 * @brief Custom 6-byte Type-Length-Value (TLV) Header for CACC-Secure metadata.
 * 
 * Layout:
 * - Popularity Hint (PH): 1 Byte
 * - Origin Hop-Count (OHC): 1 Byte
 * - Sequence Number (SEQ): 1 Byte
 * - Truncated HMAC: 3 Bytes (Derived from a 4-byte signature boundary optimized for alignment)
 */
class CaccHeader {
public:
    CaccHeader();
    CaccHeader(uint8_t ph, uint8_t ohc, uint8_t seq, uint32_t hmacSignature);

    // Getters
    uint8_t getPh() const { return m_ph; }
    uint8_t getOhc() const { return m_ohc; }
    uint8_t getSeq() const { return m_seq; }
    uint32_t getHmac() const { return m_hmac; }

    // Setters
    void setPh(uint8_t ph) { m_ph = ph; m_wire.reset(); }
    void setOhc(uint8_t ohc) { m_ohc = ohc; m_wire.reset(); }
    void setSeq(uint8_t seq) { m_seq = seq; m_wire.reset(); }
    void setHmac(uint32_t hmacSignature) { m_hmac = hmacSignature & 0xFFFFFF; m_wire.reset(); } // Clamped to 3 bytes

    // Serialization / Deserialization matching ndn-cxx standards
    template<ndn::encoding::EncoderTag TAG>
    size_t wireEncode(ndn::EncodingImpl<TAG>& encoder) const;

    const ndn::Block& wireEncode() const;
    void wireDecode(const ndn::Block& wire);

private:
    uint8_t m_ph;
    uint8_t m_ohc;
    uint8_t m_seq;
    uint32_t m_hmac; // Stored as 3-byte payload internally

    mutable ndn::Block m_wire;
    
    // Custom TLV Type assignment for CACC (Avoids conflicts with standardized NDN fields)
    static const uint32_t TLV_CACC_HEADER = 240; 
};

} // namespace ndn
} // namespace ns3

#endif // NDN_SIM_CACC_HEADER_HPP