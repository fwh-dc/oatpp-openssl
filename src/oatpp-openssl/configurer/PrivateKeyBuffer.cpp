/***************************************************************************
 *
 * Project         _____    __   ____   _      _
 *                (  _  )  /__\ (_  _)_| |_  _| |_
 *                 )(_)(  /(__)\  )( (_   _)(_   _)
 *                (_____)(__)(__)(__)  |_|    |_|
 *
 *
 * Copyright 2018-present, Leonid Stryzhevskyi <lganzzzo@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************************/

#include "PrivateKeyBuffer.hpp"

#include "openssl/err.h"

namespace oatpp { namespace openssl { namespace configurer {

PrivateKeyBuffer::PrivateKeyBuffer(const void *privateKeyBuffer, int privateKeyBufferLength)
{
  m_buffer = std::shared_ptr<BIO>(BIO_new_mem_buf(privateKeyBuffer, privateKeyBufferLength), BIO_free);
  if (m_buffer == nullptr) {
    throw std::runtime_error("[oatpp::openssl::configurer::PrivateKeyBuffer::PrivateKeyBuffer()]: Error. "
                             "'m_privateKey' == nullptr.");
  }
}

void PrivateKeyBuffer::configure(SSL_CTX *ctx) {
  if (BIO_pending(m_buffer.get()) == 0) {
    return;
  }
  auto m_privateKey = std::shared_ptr<RSA>(PEM_read_bio_RSAPrivateKey(m_buffer.get(), nullptr, nullptr, nullptr), RSA_free);
  if (!SSL_CTX_use_RSAPrivateKey(ctx, m_privateKey.get())) {
    throw std::runtime_error("[oatpp::openssl::configurer::PrivateKeyBuffer::configure()]: Error. "
                             "Call to 'SSL_CTX_use_PrivateKey' failed: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
  }
}

}}}

