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
	const Consensus::Params& consensusParams = Params().GetConsensus();
	return IsEquihash(consensusParams);
}

bool CBlockHeader::IsEquihash(const Consensus::Params& params) const {
    bool result = nTime >= params.nEquihashStartTime;
    return result;
}

uint256 CBlockHeader::GetHash(const Consensus::Params& params) const
{
	uint256 thash;
    
    if (IsEquihash(params))
    {
        // Equihash epoch, new block format
        thash = SerializeHash(*this);
    }
    else
    {
        // legacy block format
        unsigned char legacy_header[80];
		memcpy(&legacy_header[0], BEGIN(nVersion), 4);
		memcpy(&legacy_header[4], BEGIN(hashPrevBlock), 32);
		memcpy(&legacy_header[36], BEGIN(hashMerkleRoot), 32);
		memcpy(&legacy_header[68], BEGIN(nTime), 4);
		memcpy(&legacy_header[72], BEGIN(nBits), 4);
		memcpy(&legacy_header[76], BEGIN(nNonce), 4);
        lyra2z_hash(BEGIN(legacy_header), BEGIN(thash));
    }
    
    return thash;
}

uint256 CBlockHeader::GetHash() const
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
    return GetHash(consensusParams);
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    
    if (IsEquihash())
    {
		s << strprintf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%s, vtx=%u)\n",
			GetHash().ToString(),
			nVersion,
			hashPrevBlock.ToString(),
			hashMerkleRoot.ToString(),
			nTime, nBits, nNonceNew.ToString(),
			vtx.size());
	}
	else
	{
		s << strprintf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
			GetHash().ToString(),
			nVersion,
			hashPrevBlock.ToString(),
			hashMerkleRoot.ToString(),
			nTime, nBits, nNonce,
			vtx.size());		
	}
	
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i].ToString() << "\n";
    }
    return s.str();
}
