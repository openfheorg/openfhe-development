/***
 * © 2020 Duality Technologies, Inc. All rights reserved.
 * This is a proprietary software product of Duality Technologies, Inc.
 *protected under copyright laws and international copyright treaties, patent
 *law, trade secret law and other intellectual property rights of general
 *applicability. Any use of this software is strictly prohibited absent a
 *written agreement executed by Duality Technologies, Inc., which provides
 *certain limited rights to use this software. You may not copy, distribute,
 *make publicly available, publicly perform, disassemble, de-compile or reverse
 *engineer any part of this software, breach its security, or circumvent,
 *manipulate, impair or disrupt its operation.
 ***/

#ifndef LBCRYPTO_CRYPTO_METADATASER_H
#define LBCRYPTO_CRYPTO_METADATASER_H

#include "palisade.h"
#include "utils/serial.h"

CEREAL_CLASS_VERSION(lbcrypto::Metadata,
                     lbcrypto::Metadata::SerializedVersion());
CEREAL_REGISTER_TYPE(lbcrypto::Metadata);

CEREAL_REGISTER_TYPE(lbcrypto::MetadataTest);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::Metadata, lbcrypto::MetadataTest)

#endif
