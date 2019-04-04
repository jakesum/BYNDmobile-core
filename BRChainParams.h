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
    {      0, uint256("fd302ca6c079b832f2a340940e819e827aed8ea67f81daf292b67968038da552"); 1522540800, 0x1e0ffff0 },
    {    500, uint256("62f81fffe505d491b214a3aa9c1e956b4e0e7db233f1bf3ba6ed300e72cf0202"), 1554268809, 0x1e0ffff0 },
    {   1000, uint256("e65e8b53fbdb1ad8f5821f8b581046568052b21b36c3bbb73c8a26753ae15d93"), 1554280622, 0x1e0ffff0 },
    {   1500, uint256("6d247b8d44522040d00affe8320800a99df304bbe42ff695d825966e545cc6be"), 1554292607, 0x1e0ffff0 },
    {   2000, uint256("2e450c7651c118be38f1024038dd0bff89125c28108b0503517284f53c953093"), 1554303806, 0x1e0ffff0 },
    {   2500, uint256("321b59b1a9a2b2db12f174651ca922c120f6f925de59ecc62b5afbdc5509e041"), 1554315515, 0x1e0ffff0 },
    {   3000, uint256("63e4af44705f444b88d23118ff3f5e7a8073c768eba29c28664338f73f9e7d01"), 1554327789, 0x1e0fffff },
    {   3500, uint256("810406510ef747a3527c8d4882158eb720676963efea20ae37d17beabb4720b1"), 1554339518, 0x1e0fffff },
    {   4000, uint256("b22b2b14a4922bf221b433643eb0351a213fc8edb934709c12172307e848928a"), 1554350706, 0x1e0fffff },
    {   4500, uint256("d77fa14454335a298905ffd25dfaf708c8fdb8f7314d0cc540e603fa9178c502"), 1554363240, 0x1e0fffff }

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
    0xd4b7c2fd, // magicNumber
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
