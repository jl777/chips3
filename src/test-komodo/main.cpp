#include <gtest/gtest.h>

#include "key.h"
#include "chainparams.h"
#include "crypto/common.h"


int main(int argc, char **argv) {
    ECC_Start();
    SelectParams(CBaseChainParams::MAIN);

    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
