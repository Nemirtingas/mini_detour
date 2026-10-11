#include "catch.hpp"

extern "C" int MiniDetourCApiTest(void);

TEST_CASE("Public header can be used from C", "[c_api]")
{
    CHECK(MiniDetourCApiTest() == 0);
}
