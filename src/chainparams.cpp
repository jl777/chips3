// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

#include <assert.h>

#include <chainparamsseeds.h>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "cointelegraph.com 09/Aug/2017 Bitcoin’s Present Bubble Might Actually be the Beginning of Mainstream Adoption";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 0;//173805; // 00000000000000ce80a7e057163a4db1d5ad7b20fb6f598c9597b9665c8fb0d4 - April 1, 2012
        consensus.BIP34Height = 128;//227931;
        consensus.BIP34Hash = uint256S("0x00000010892de4ff2aac1bc7cff0d2b001caf66ca160fd47c1290dc8a49bab2c");
        consensus.BIP65Height = 0;//388381; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 0;//363725; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.powLimit = uint256S("0000007fffff0000000000000000000000000000000000000000000000000000");
        consensus.nPowTargetSpacing = 10;// * 60;
        consensus.nLwmaAjustedWeight = 1350;

        consensus.nPowAveragingWindow = 17;
//      assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.nPowTargetTimespan = 17 * consensus.nPowTargetSpacing;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nAdaptivePoWActivationThreshold = 6874120; // (approx 23th Aug 2020, 9:00 PM UTC)
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
//        consensus.nMinerConfirmationWindowApow = 17; // 17 after apow HF ; nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1510704000; // November 15th, 2017.

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000002000400");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000000000000000005214481d2d96f898e3d5416e43359c145944a909d242e0"); //506067

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xff;
        pchMessageStart[1] = 0xee;
        pchMessageStart[2] = 0xdd;
        pchMessageStart[3] = 0xcc;
        nDefaultPort = 57777;
        nPruneAfterHeight = 100000;

        int32_t z; uint32_t nonce; uint8_t *ptr = (uint8_t *)&consensus.hashGenesisBlock;
        for (nonce=9250234; nonce<500000000; nonce++)
        {
            genesis = CreateGenesisBlock(1500000777, nonce, 0x1e007fff, 1, 50 * COIN);
            consensus.hashGenesisBlock = genesis.GetHash();
            if ( ptr[31] == 0 && ptr[30] == 0 && ptr[29] == 0 && (ptr[28] & 0x80) == 0)
                break;
            if ( (nonce % 1000000) == 999999 )
                fprintf(stderr,"%d ",nonce);
        }
        printf("nonce.%u\n",nonce);
        for (z=31; z>=0; z--)
            printf("%02x",ptr[z]);
        printf(" <- genesis\n");
        ptr = (uint8_t *)&genesis.hashMerkleRoot;
        for (z=31; z>=0; z--)
            printf("%02x",ptr[z]);
        printf(" <- merkle\n");
        assert(consensus.hashGenesisBlock == uint256S("0x0000006e75f6aa0efdbf7db03132aa4e4d0c84951537a6f5a7c39a0a9d30e1e7"));
        assert(genesis.hashMerkleRoot == uint256S("0x9bd1c477af8993947cdd9052c0e4c287fda95987b3cc8934b3769d7503852715"));

        // Note that of those with the service bits flag, most only support a subset of possible options
        /*vSeeds.emplace_back("seed.bitcoin.sipa.be", true); // Pieter Wuille, only supports x1, x5, x9, and xd
        vSeeds.emplace_back("dnsseed.bluematt.me", true); // Matt Corallo, only supports x9
        vSeeds.emplace_back("dnsseed.bitcoin.dashjr.org", false); // Luke Dashjr
        vSeeds.emplace_back("seed.bitcoinstats.com", true); // Christian Decker, supports x1 - xf
        vSeeds.emplace_back("seed.bitcoin.jonasschnelli.ch", true); // Jonas Schnelli, only supports x1, x5, x9, and xd
        vSeeds.emplace_back("seed.btc.petertodd.org", true); // Peter Todd, only supports x1, x5, x9, and xd*/

        vSeeds.emplace_back("seed.chips.kmd.sh"); // static chips seed, supports only x9

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,60);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,85);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,188);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
				/*
                { 11111, uint256S("0x0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")},
                { 33333, uint256S("0x000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6")},
                { 74000, uint256S("0x0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20")},
                {105000, uint256S("0x00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97")},
                {134444, uint256S("0x00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe")},
                {168000, uint256S("0x000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763")},
                {193000, uint256S("0x000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317")},
                {210000, uint256S("0x000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e")},
                {216116, uint256S("0x00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e")},
                {225430, uint256S("0x00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932")},
                {250000, uint256S("0x000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214")},
                {279000, uint256S("0x0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40")},
                {295000, uint256S("0x00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983")},
				*/

                {	1,	uint256S("0x000000582fe9d30a3fc3d081212f26d9837308bd5483effcd41bc43a95d3259e")},
                {	128,	uint256S("0x00000010892de4ff2aac1bc7cff0d2b001caf66ca160fd47c1290dc8a49bab2c")},
                {	100000,	uint256S("0x000000000000048ed22d2e5e690295d039ca31dc32793b51fe1f096b33108afc")},
                {	200000,	uint256S("0x00000000000000c614b8cdab56a19c6fb20d24dd9afb39ddfa6ce57c2b3d8c00")},
                {	300000,	uint256S("0x00000000000000e2935269a077f5032fa43b5e298b510a12dc01516fd533be34")},
                {	400000,	uint256S("0x0000000000000098f0dc5619032906d42643f46603a5732bc7777dd2163eff2d")},
                {	500000,	uint256S("0x000000000000005df6dbf3f0b6716af0dbf30d3dcfeb5ff08a4e23bff11b6a0d")},
                {	600000,	uint256S("0x0000000000000027735ac1056b72b3f92224ea06d6d3c3f821ff3be971372d7e")},
                {	700000,	uint256S("0x000000000000004381c3ab4ce6a48d62dc2b36ddd8082a485da2e8c48e63d02e")},
                {	800000,	uint256S("0x00000000000000b57f3e10a045ab233b502f260d6d63df7b0960307677a60d74")},
                {	900000,	uint256S("0x00000000000002e517ac59be3d9c34f9dc2f5f8c7fca285258762e5bfe7b9be3")},
                {	1000000,	uint256S("0x00000000000000410fbac9b1bf3f1857e247d7afc56d9e80c806ea96f84c48ef")},
                {	1100000,	uint256S("0x0000000000000030b11d70e4d4b2e13418d84fd7bf2f5ffafa7ab0ff48f78d60")},
                {	1200000,	uint256S("0x0000000000000068cc3fbfcc86d082b1606c38d697abdded2db3b593d8018978")},
                {	1300000,	uint256S("0x0000000000000151389ce46530379455a9dbc8662d9b3f351892ae247d34a766")},
                {	1400000,	uint256S("0x00000000000002ff31efd23b1d2dae5b054b5ec171155044016ad2bc41cc689b")},
                {	1500000,	uint256S("0x000000000000043818ec8d4c9cbf436309ee893a96a41d78f03465b619bbcbfb")},
                {	1600000,	uint256S("0x00000000000000627d8da7b2fd558c2bfcd4918b6ac04dbee23bbb0c3c370047")},
                {	1700000,	uint256S("0x00000000000009e4e5ecd676d07e3cb4a638be34844491141c55f0812f9ab75c")},
                {	1800000,	uint256S("0x000000000000025ef6cd2fc99474b3287759d8f8e1f1f094e6e53f2cb6729aaa")},
                {	1900000,	uint256S("0x000000000000127aeca716292c442bb415764392c1be0a7aff7e1edd563f6af4")},
                {	2000000,	uint256S("0x000000000000416f64ab1eb65c696a299d5f2708a3d8e1519831091da34d5a10")},
                {	2100000,	uint256S("0x0000000000000f2ada425065a2988fa96fbc2d740d0bcae2fdf57e23c19c9d9a")},
                {	2200000,	uint256S("0x0000000000001b0868e18392b8b23411d0741dcaf055e12426c24954ff92d4ef")},
                {	2300000,	uint256S("0x0000000000000e255ae300d2733378be63c614a23edd1f85ebf2fcbad384d19a")},
                {	2400000,	uint256S("0x00000000000027f95c3a4a2a66c08c20133e752a670e36602140f3a0a63fcd57")},
                {	2500000,	uint256S("0x00000000000032de2c1c05410f3c6972c20722bf7b0d4e9f20e73ed582e7ad10")},
                {	2600000,	uint256S("0x0000000000008fe305e46a93424b0fbfcd7f1a5b40b7375a4781385b2a642dc1")},
                {	2700000,	uint256S("0x000000000000e4a994b0d885ee8dbc6e00585f128e26339d4f24edc9e76c1369")},
                {	2800000,	uint256S("0x000000000001277c76f334bf0eae43921a2c9936006c2f20c44822b24168bd5a")},
                {	2900000,	uint256S("0x000000000000b32150cc454da6dae0589eab7cbb22f9a3e9f74a1801590d7ca7")},
                {	3000000,	uint256S("0x0000000000013feb2767e71a328fb21990eb2ab19d65705a53d1c6beb6d9cd6f")},
                {	3100000,	uint256S("0x000000000001f1a24965ea1157e6de30b90a0221d2a83d0be632a802fc9c27da")},
                {	3200000,	uint256S("0x0000000000001966f930beaa6fb485dd03025a8c3515b304ad5176ceeaed8604")},
                {	3300000,	uint256S("0x00000000000256a5da5fb2f99034ede916acae024b3b461f7d0771e2fccbb5eb")},
                {	3400000,	uint256S("0x0000000000009b7c28bd7712b6e533d9308e26f23d6fcaf53dbcda2e147bb324")},
                {	3500000,	uint256S("0x0000000000009b43fb0157e220d72355ee8e79002b28ffcb0eb90fb4894a9d80")},
                {	3600000,	uint256S("0x000000000001b0b8ae05a429c2892f73810adb86626d1a031e1a1733cea61c5b")},
                {	3700000,	uint256S("0x000000000000893b2f8860447a5c072bcd6dabc2e08f69ba17d8971f9a909145")},
                {	3800000,	uint256S("0x0000000000020b5f6157a55b1375b3dfd1f49aadb514028b3e1be06bb189a77f")},
                {	3900000,	uint256S("0x00000000000039b5e7e65be0cb17499721ea775b40dba60c0d0c30f5c363d340")},
                {	4000000,	uint256S("0x0000000000006df059694a9dda4badf9955bc52562e91b1c40254d3974bf2118")},
                {	4100000,	uint256S("0x00000000000071544fda01cf7a3c9512a9706af62755e0fd66a80a30b2faad5e")},
                {	4200000,	uint256S("0x00000000000092c1a3a9da177f4ff7b972e57d01ce3be585e0efaf3d8657d5b3")},
                {	4300000,	uint256S("0x000000000000e8c7cfd05685dd3ad12e7b4db348cb30882650cef80ca2473cc8")},
                {	4400000,	uint256S("0x0000000000001106fc174c7c2c7e8acbfb7eca8ddb22596897ea6cc7fc1c538b")},
                {	4500000,	uint256S("0x0000000000001b93630f855ca73a1fbbf971799ab028f1da1b380fe071525e27")},
                {	4600000,	uint256S("0x00000000000231f0e9e70f49dc73c16694b096b3db98f76d1b00867cc498f1d0")},
                {	4700000,	uint256S("0x00000000000118be3710ee4c8344bdaa704b76787e84d292009704b9745b8646")},
                {	4800000,	uint256S("0x00000000000125718cc59abe8021866c2a44981d8c53f6cd668102bb2aaf1dea")},
                {	4900000,	uint256S("0x000000000000ce024733d8bbd7a5900214a3223aa530ee4c6e2cd5e219bf77b0")},
                {	5000000,	uint256S("0x0000000000004b0a66d187117d22b6c16bcf2125cce985a30ff7cdc1dbf3ddc7")},
                {	5100000,	uint256S("0x0000000000011ecfaf9e97473e6ed0bcb5e392ae70decb585fd6736b295a0136")},
                {	5200000,	uint256S("0x000000000002299db310071d6d90a321b9bc35fec7e7ada9a004b8fb498c3ae0")},
                {	5300000,	uint256S("0x00000000000038bf60d7e698a2d622935f5fd86caf6893ceb83b2b0cb9f0b106")},
                {	5400000,	uint256S("0x000000000000002f6c3180762adb011477cf764ca46ef1440292e507cebb7652")},
                {	5500000,	uint256S("0x000000000002145fcc201bfc374591dad4633ef738149f0748a458b40077ffa5")},
                {	5600000,	uint256S("0x000000000000c44d0683b5fad91a05af6a4db7597d2ba94e33a0cec5b9042bde")},
                {	5700000,	uint256S("0x00000000000064a6bb183eb3905302fe1f57ade50be38478677b3b9dbacb04a0")},
                {	5800000,	uint256S("0x00000000000102db5621c6435e33c9159e1a25d1f09af1156917cb35478684ab")},
                {	5900000,	uint256S("0x000000000000424b80dda5581febd8317857723dd202fa7754116b2fbf93f415")},
                {	6000000,	uint256S("0x00000010ad855ef0672f85277df3e4a22b85c308b69ee53ba94565237ff7e73d")},
                {	6100000,	uint256S("0x000000000001131492d3e39fe7799ae0689e6bb93005207fa39f2fe7e2fe75c9")},
                {	6200000,	uint256S("0x00000000000028410308873ccee8d82f03d82c913a58f9eb907333025e0d8c76")},
                {	6300000,	uint256S("0x000000000002a406db69d89577580c048533bc92c8ed1d1f4b462eb8c5360ddf")},
                {	6400000,	uint256S("0x000000000004ab9c4525e9efa7bb4497477edd19e0a2a3b447f69726eec909a3")},
                {	6500000,	uint256S("0x000000000001b5d85e78071a9f5a9732dbdf0ed222804e2db30a5e712347dfb5")},
                {	6600000,	uint256S("0x000000000006a07452e9399cb9159956b9840359ebfc1f5b7c286243edd4e587")},
                {	6700000,	uint256S("0x00000000000119bf7cfe664f1795a678587bcacce3c2e63428eafe0587d8f8bb")},
                {	6711111,	uint256S("0x000000000000cef16a63da7ef6bbb1d2bd2cec1faaf58792be564d4e4db63fa4")}

            }
        };

        chainTxData = ChainTxData{
            // Data as of 10/06/2017 @ 3:52pm (UTC) 
            1507305126, // * UNIX timestamp of last known number of transactions
            421558,  // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0           // * estimated number of transactions per second after that timestamp
        };

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = false;
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 514; // 00000000040b4e986385315e14bee30ad876d8b47f748025b26683116d21aa65
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        consensus.BIP65Height = 581885; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 330776; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000002000400");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000000002e9e7b00e1f6dc5123a04aad68dd0f0968d8c7aa45f6640795c37b1"); //1135275

        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        nDefaultPort = 18333;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1296688602, 414098458, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

	// [+] Decker
        int32_t z; uint32_t nonce; uint8_t *ptr = (uint8_t *)&consensus.hashGenesisBlock;
        for (nonce=9250234; nonce<500000000; nonce++)
        {
            genesis = CreateGenesisBlock(1500000777, nonce, 0x1e007fff, 1, 50 * COIN);
            consensus.hashGenesisBlock = genesis.GetHash();
            if ( ptr[31] == 0 && ptr[30] == 0 && ptr[29] == 0 && (ptr[28] & 0x80) == 0)
                break;
            if ( (nonce % 1000000) == 999999 )
                fprintf(stderr,"%d ",nonce);
        }
        printf("nonce.%u\n",nonce);
        for (z=31; z>=0; z--)
            printf("%02x",ptr[z]);
        printf(" <- genesis\n");
        ptr = (uint8_t *)&genesis.hashMerkleRoot;
        for (z=31; z>=0; z--)
            printf("%02x",ptr[z]);
        printf(" <- merkle\n");

        //assert(consensus.hashGenesisBlock == uint256S("0x000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"));
        //assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));
        assert(consensus.hashGenesisBlock == uint256S("0x0000006e75f6aa0efdbf7db03132aa4e4d0c84951537a6f5a7c39a0a9d30e1e7"));
        assert(genesis.hashMerkleRoot == uint256S("0x9bd1c477af8993947cdd9052c0e4c287fda95987b3cc8934b3769d7503852715"));



        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet-seed.bitcoin.jonasschnelli.ch");
        vSeeds.emplace_back("seed.tbtc.petertodd.org");
        vSeeds.emplace_back("seed.testnet.bitcoin.sprovoost.nl");
        vSeeds.emplace_back("testnet-seed.bluematt.me"); // Just a static list of stable node(s), only supports x9

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = {
            {
                {546, uint256S("000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")},
            }
        };

        chainTxData = ChainTxData{
            // Data as of block 000000000000033cfa3c975eb83ecf2bb4aaedf68e6d279f6ed2b427c64caff9 (height 1260526)
            1516903490,
            17082348,
            0.09
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Height = 0; // always enforce P2SH BIP16 on regtest
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"));
        assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                {0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
