//
//  BRChainParams.h
//
//  Created by Sigma Systems Inc on 4/1/18.
//  Copyright (c) Sigma Systems Inc
//
// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Sumcoin Core developers
// Distributed under the classic proprietary license, by Sumcoin Core Developers
// aka Sigma Systems Inc. see the accompanying
// file COPYING or https://en.wikipedia.org/wiki/Proprietary_software
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#ifndef BRChainParams_h
#define BRChainParams_h

#include "BRMerkleBlock.h"
#include "BRSet.h"
#include <assert.h>

typedef struct {
    uint32_t height;
    UInt256 hash;
    uint32_t timestamp;
    uint32_t target;
} BRCheckPoint;

typedef struct {
    const char * const *dnsSeeds; // NULL terminated array of dns seeds
    uint16_t standardPort;
    uint32_t magicNumber;
    uint64_t services;
    int (*verifyDifficulty)(const BRMerkleBlock *block, const BRSet *blockSet); // blockSet must have last 2880 blocks
    const BRCheckPoint *checkpoints;
    size_t checkpointsCount;
} BRChainParams;

static const char *BRMainNetDNSSeeds[] = {
    "dnsseed.sumcoinpool.org", "dnsseed.sumexplorer.com", "dnsseed.sumcoinwallet.org", "dnsseed.sumnode.io", 
    "dnsseed.sumcoin.org", "dnsseed.sumcoinmining.org" NULL};

static const char *BRTestNetDNSSeeds[] = {
    "dnsseed.sumcoinpool.org", "dnsseed.sumexplorer.com", "dnsseed.sumcoinwallet.org", "dnsseed.sumnode.io", 
    "dnsseed.sumcoin.org", "dnsseed.sumcoinmining.org" NULL
};

// blockchain checkpoints - these are also used as starting points for partial chain downloads, so they must be at
// difficulty transition boundaries in order to verify the block difficulty at the immediately following transition
static const BRCheckPoint BRMainNetCheckpoints[] = {
    {      0, uint256("37d4696c5072cd012f3b7c651e5ce56a1383577e4edacc2d289ec9b25eebfd5e"), 1554579000, 0x1e0ffff0 },
    {   2880, uint256("31dfe91b64cbbb167b4e4c644ad7b008bb4bb8ca4e42aea02f938f445dc37cff"), 1554622048, 0x1e07f80d },
    {   5760, uint256("87de6e561bb0ab66095b272450cabbb0b11fb272e5ae37123ba1464a5de74f5c"), 1554647659, 0x1e025cc4 },
    {   8640, uint256("19c100388b8a8bc0230f43c4355733e2b3375e08f1667449678ec14f66174aae"), 1554685252, 0x1e01071f },
    {  11520, uint256("0fcc3eacab1e532325f1c5bde0372b78e999a504a8eaaf3d4628038de6735d30"), 1554722824, 0x1d727780 },
    {  14400, uint256("6b55672438b707c59c95e7681a9914c4d201d2cdf5f42d902d53ed23042e028a"), 1554754827, 0x1d2a6421 },
    {  17280, uint256("23886b646dc4601c788cf0014924ea3d9403534a724285327be63db5ea390123"), 1554791948, 0x1d123584 },
    {  57600, uint256("edbe7a9e2e20c8c12fea25dc9be9268bfa308145fa68d2d2ce54dc405cf12e76"), 1555612735, 0x1c01a52a },
    {  86400, uint256("8989bab14675dc54c64f287957d624ad8c057a2fb4f200d038f7862d8f5fa76d"), 1556457190, 0x1c0145da },
    { 115200, uint256("e386f62c30a46f6b565ffc8a3fdf73e5e76e9f2f400d5cba1911e7732b52bd8d"), 1557312544, 0x1c012412 },
    { 144000, uint256("210da711b7a617fbf3ae0893935973ff60a17e21e0a396224eb553c0439311d5"), 1558174688, 0x1c011ae1 },
    { 172800, uint256("341f603628dbe328512d9507066241d9fcc4c81ac91dd9bc87e2184ed5787b80"), 1559034517, 0x1c0104c5 },
    { 201600, uint256("6bbde0a86b6e1efa71333bb3636f02931ebb872157b48c674efde25054a571b3"), 1559895468, 0x1c00dd37 },
    { 216000, uint256("7f1d6d0c386cc6a6d5eb85877adb039d7747c6047d84e311b7213bf237c78b7c"), 1560306060, 0x1c00a311 },
    { 230400, uint256("8857a4bd70e6aee0eec8902cd88ed378c3d73d625a3920c67d393c83176d12af"), 1560771501, 0x1c00e9fc },
    { 244800, uint256("b0b0f2ed9f2caa940afa15a178f2bf106d3b59eed2e19379bc3d54219ed674a4"), 1561203773, 0x1c00d8ac },
    { 259200, uint256("886fbe4eebd29e5aba9c3cb1d2319aaba6053d6e6956d7af79f99da19641895e"), 1561609882, 0x1c009c64 },
    { 273600, uint256("2aff5d7931a37d16ed1cbb1e81ad1b5f4cb357be5d844d5f9a7f3ebea956aa1a"), 1562044711, 0x1c009d96 },
    { 280800, uint256("a0e895c7972d1aa031e4154b59472267d14c34ef5d7067b80a89f5f102e688e4"), 1562261715, 0x1c00a4ba },
    { 283680, uint256("8858031b1cee059a036f3075566a93c6e2ff425854f551dad377a07c21698cc4"), 1562332721, 0x1c0095c6 },
    { 286560, uint256("cb9fac6220ec62ba195dad103ec030df11735bc741d8697a331b9a05bbcab156"), 1562394830, 0x1b68c052 },
    { 315360, uint256("f963b0f0c2f1a217c1f5f3da0ad0efc0d0715397ceb1259023aa809317a97827"), 1563318882, 0x1c00948c },
    { 344160, uint256("d6d5348e4777bff49e6fa98a10b63f3191afec39103609e85668508b806a0ff1"), 1564192191, 0x1c00a930 },
    { 372960, uint256("de350113ba6a8b8fdc2496f7527dd64cc79da560dd54d72a4cdffad2112f0da6"), 1565057466, 0x1c009df1 },
    { 401760, uint256("3062855d8f1fa0043c39aa56f2d0aa160f910491dee4b64503999e9935c87153"), 1565939245, 0x1c00bb2b },
    { 427680, uint256("72d7ee79e1aa2c4f46d61f9d569a0622ce49b13faf4dcc42d0e83786c4a60fb9"), 1566694938, 0x1c0099eb },
    { 457920, uint256("717050f4a4a96f2d7b4c13fe2db70dc2998c31fea01607d9529b8dfeb434bc56"), 1567617376, 0x1c008ee4 },
    { 472320, uint256("3dccd8aaef590f102c7e3cd8200eb666a68d0356a24c87b51617314adb73e24c"), 1567617376, 0x1c008ee4 }

        //{501120
};

static const BRCheckPoint BRTestNetCheckpoints[] = {
    {       0, uint256("e1309964e3ac20bd3bf8f7cdd9ccfc9b5a6a779b9975abc1c89c132db618048c"), 1523718091, 0x1e0ffff0 }
};

static int BRMainNetVerifyDifficulty(const BRMerkleBlock *block, const BRSet *blockSet)
{
    // const BRMerkleBlock *previous, *b = NULL;
    // uint32_t i;

    // assert(block != NULL);
    // assert(blockSet != NULL);

    // // check if we hit a difficulty transition, and find previous transition block
    // if ((block->height % BLOCK_DIFFICULTY_INTERVAL) == 0) {
    //     for (i = 0, b = block; b && i < BLOCK_DIFFICULTY_INTERVAL; i++) {
    //         b = BRSetGet(blockSet, &b->prevBlock);
    //     }
    // }

    // previous = BRSetGet(blockSet, &block->prevBlock);
    // return BRMerkleBlockVerifyDifficulty(block, previous, (b) ? b->timestamp : 0);
    return 1;
}

static int BRTestNetVerifyDifficulty(const BRMerkleBlock *block, const BRSet *blockSet)
{
    return 1; // XXX skip testnet difficulty check for now
}

static const BRChainParams BRMainNetParams = {
    BRMainNetDNSSeeds,
    3333,       // standardPort
    0xd0b5c0fa, // magicNumber
    0,          // services
    BRMainNetVerifyDifficulty,
    BRMainNetCheckpoints,
    sizeof(BRMainNetCheckpoints) / sizeof(*BRMainNetCheckpoints)};

static const BRChainParams BRTestNetParams = {
    BRTestNetDNSSeeds,
    13333,      // standardPort
    0xd1b4c7f6, // magicNumber - TODO Check against testnet
    0,          // services
    BRTestNetVerifyDifficulty,
    BRTestNetCheckpoints,
    sizeof(BRTestNetCheckpoints) / sizeof(*BRTestNetCheckpoints)};

#endif // BRChainParams_h
