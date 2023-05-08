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

#include "CertificateBuffer.hpp"

namespace oatpp { namespace openssl { namespace configurer {

CertificateBuffer::CertificateBuffer(const void *certificateBuffer, int certificateBufferLength)
{
  m_buffer = std::shared_ptr<BIO>(BIO_new_mem_buf(certificateBuffer, certificateBufferLength), BIO_free);
  if (m_buffer == nullptr) {
    throw std::runtime_error("[oatpp::openssl::configurer::CertificateBuffer::CertificateBuffer()]: Error. "
                             "'m_buffer' == nullptr.");
  }
}

void CertificateBuffer::configure(SSL_CTX *ctx) {
  if (BIO_pending(m_buffer.get()) == 0) {
    return;
  }
  auto m_certificate = std::shared_ptr<X509>(PEM_read_bio_X509(m_buffer.get(), nullptr, nullptr, nullptr), X509_free);
  if (!SSL_CTX_use_certificate(ctx, m_certificate.get())) {
    throw std::runtime_error("[oatpp::openssl::configurer::CertificateBuffer::configure()]: Error. "
                             "Call to 'SSL_CTX_use_certificate' failed.");
  }
}

}}}
