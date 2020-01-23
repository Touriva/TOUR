// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include <chainparams.h>
#include <consensus/params.h>
#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"

#include "crypto/Lyra2Z/Lyra2Z.h"
#include "crypto/Lyra2Z/Lyra2.h"

bool CBlockHeader::IsEquihash() const {
    bool result;
    printf("without params\n");
    return false;
}

bool CBlockHeader::IsEquihash(const Consensus::Params& params) const {
    bool result = nTime >= params.nEquihashStartTime;
    if (result)
    {
        printf("Equihash\n");
    }
    else
    {
        printf ("Lyra2Z\n");
    }
    return result;
}

uint256 CBlockHeader::GetHash(const Consensus::Params& params) const
{
    if (IsEquihash(params))
    {
        // Equihash epoch, new block format
       return SerializeHash(*this);
    }
    else
    {
        // legacy block format
        uint256 thash;
        lyra2z_hash(BEGIN(nVersion), BEGIN(thash));
        return thash;
    }
}

uint256 CBlockHeader::GetHash() const
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
    return GetHash(consensusParams);
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i].ToString() << "\n";
    }
    return s.str();
}
