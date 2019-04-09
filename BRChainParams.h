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
    int (*verifyDifficulty)(const BRMerkleBlock *block, const BRSet *blockSet); // blockSet must have last 2016 blocks
    const BRCheckPoint *checkpoints;
    size_t checkpointsCount;
} BRChainParams;

static const char *BRMainNetDNSSeeds[] = {
    "dnsseed.sumcoinpool.org", "dnsseed.sumcoinwallet.org", NULL};

static const char *BRTestNetDNSSeeds[] = {
    "dnsseed.sumcoinpool.org", "dnsseed.sumcoinwallet.org", NULL
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
    {  17280, uint256("23886b646dc4601c788cf0014924ea3d9403534a724285327be63db5ea390123"), 1554791948, 0x1d123584 }


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
