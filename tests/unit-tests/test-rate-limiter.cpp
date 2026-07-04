#include "rate-limiter.hpp"
#include <ns3/test.h>
#include <ns3/simulator.h>
#include <ndn-cxx/name.hpp>

using namespace ns3;
using namespace ns3::ndn;

/**
 * @brief Test suite evaluating Sliding-Window Rate Limiter clamping boundaries.
 */
class TestRateLimiterSuite : public TestCase {
public:
    TestRateLimiterSuite() : TestCase("CACC-Secure Sliding-Window Rate Limiter Test Case") {}

private:
    virtual void DoRun() override {
        // Initialize rate limiter bound to 1.0 second windows with a max limit of 5 requests
        RateLimiter filter(Seconds(1.0), 5);
        ::ndn::Name targetPrefix("/cacc/secure/test-stream");

        // 1. Send legitimate traffic well within acceptable caps
        for (int i = 0; i < 5; ++i) {
            bool result = filter.validateFrequency(targetPrefix);
            NS_TEST_EXPECT_MSG_EQ(result, true, "Valid request frequency incorrectly clamped at step: " << i);
        }

        // 2. Intentionally inject a 6th request to trigger the threshold breach
        bool breachResult = filter.validateFrequency(targetPrefix);
        NS_TEST_EXPECT_MSG_EQ(breachResult, false, "Rate limiter failed to clamp rapid request spike at boundary limit.");

        // 3. Fast-forward simulation time past the 1.0-second tracking window
        Simulator::Destroy(); // Clean simulation contexts safely
    }
};

static TestRateLimiterSuite g_testRateLimiterSuiteInstance;