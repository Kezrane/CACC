#include "cacc-header.hpp"
#include <ns3/test.h>
#include <ndn-cxx/encoding/block.hpp>

using namespace ns3;
using namespace ns3::ndn;

/**
 * @brief Test suite verifying CACC-Secure custom 6-byte header operations.
 */
class TestCaccHeaderSuite : public TestCase {
public:
    TestCaccHeaderSuite() : TestCase("CACC-Secure Custom TLV Header Test Case") {}

private:
    virtual void DoRun() override {
        // 1. Initialize custom configuration boundaries
        uint8_t originalPh = 45;
        uint8_t originalOhc = 4;
        uint8_t originalSeq = 12;
        uint32_t originalHmac = 0xAABBCC; // 3-byte signature pattern

        CaccHeader encoderHeader(originalPh, originalOhc, originalSeq, originalHmac);

        // 2. Serialize structural variables into an ndn-cxx wire Block
        Block wireBlock;
        NS_TEST_ASSERT_MSG_NO_THROW(wireBlock = encoderHeader.wireEncode(), 
                                    "Serialization routine threw an unexpected error.");

        // Verify total byte footprint conforms exactly to 6 payload bytes + TLV wrapper overhead
        NS_TEST_EXPECT_MSG_EQ(wireBlock.value_size(), 6, "Payload array footprint must occupy exactly 6 bytes.");

        // 3. Deserialize byte stream into a fresh header container instance
        CaccHeader decoderHeader;
        NS_TEST_ASSERT_MSG_NO_THROW(decoderHeader.wireDecode(wireBlock), 
                                    "Deserialization routine threw an unexpected error.");

        // 4. Validate output matches the original inputs exactly
        NS_TEST_EXPECT_MSG_EQ(decoderHeader.getPh(), originalPh, "Decoded Popularity Hint value has mutated.");
        NS_TEST_EXPECT_MSG_EQ(decoderHeader.getOhc(), originalOhc, "Decoded Origin Hop-Count has mutated.");
        NS_TEST_EXPECT_MSG_EQ(decoderHeader.getSeq(), originalSeq, "Decoded Sequence index value has mutated.");
        NS_TEST_EXPECT_MSG_EQ(decoderHeader.getHmac(), originalHmac, "Decoded Truncated HMAC signature has mutated.");
    }
};

// Register the test suite instance within the global ns-3 validation framework
static TestCaccHeaderSuite g_testCaccHeaderSuiteInstance;