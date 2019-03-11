//
//  BRChainParams.h
//
//  Created by Aaron Voisine on 1/10/18.
//  Copyright (c) 2019 breadwallet LLC
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
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
    {      0, uint256("8f4af36aa0bdb9ae5a34d191bcbd80748569e4ef2e47587f0a3f5749dde17eea"), 1523718257, 0x1e0ffff0 },
    {  25333, uint256("50c468441ba3f9c52bb150d5f003f4e7681c5e81dbe95be6467a54da34366c56"), 1524886718, 0x1d0d342d },
    {  50666, uint256("7d79eb15730d115dc3e0677654b7c7a7436b5d881a198d0407c085aa00616adc"), 1526493746, 0x1c1503e5 },
    {  75999, uint256("fd98ddb372b9248a5685d5e77131fc1f5e14074c727549917068e91ca5d65d67"), 1532015023, 0x1d00a675 },
    { 101332, uint256("628d0da596ca299bb354dbe717f1755a34c9b800b997b4eccfc8791a5e926726"), 1534137488, 0x1c145140 },
    { 126665, uint256("04676601e0ae731b8289fb91244ae4507e10d17aa8e6e8141579451de21241bd"), 1536007335, 0x1c0f65ab }
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
    0xfdc2b7d3, // magicNumber
    0,          // services
    BRMainNetVerifyDifficulty,
    BRMainNetCheckpoints,
    sizeof(BRMainNetCheckpoints) / sizeof(*BRMainNetCheckpoints)};

static const BRChainParams BRTestNetParams = {
    BRTestNetDNSSeeds,
    13333,      // standardPort
    0xf6c7b4d1, // magicNumber
    0,          // services
    BRTestNetVerifyDifficulty,
    BRTestNetCheckpoints,
    sizeof(BRTestNetCheckpoints) / sizeof(*BRTestNetCheckpoints)};

#endif // BRChainParams_h
