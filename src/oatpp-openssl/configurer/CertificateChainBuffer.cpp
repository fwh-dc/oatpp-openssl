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

#include "CertificateChainBuffer.hpp"

#include <openssl/x509_vfy.h>

namespace oatpp { namespace openssl { namespace configurer {

CertificateChainBuffer::CertificateChainBuffer(const void *certificateChainBuffer, int certificateChainBufferLength)
{
  m_buffer = std::shared_ptr<BIO>(BIO_new_mem_buf(certificateChainBuffer, certificateChainBufferLength), BIO_free);
  if (m_buffer == nullptr) {
    throw std::runtime_error("[oatpp::openssl::configurer::CertificateChainBuffer::CertificateChainBuffer()]: Error. "
                             "'m_chainOfCertificates' == nullptr.");
  }
}
static int always_true_callback(X509_STORE_CTX *ctx, void *arg)
{
    return 1;
}

void CertificateChainBuffer::configure(SSL_CTX *ctx) {
  if (BIO_pending(m_buffer.get()) == 0) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_cert_verify_callback(ctx, always_true_callback, NULL);
    return;
  }
    X509_STORE* cert_store = SSL_CTX_get_cert_store(ctx);

    if(cert_store == NULL) {
        throw std::runtime_error("[oatpp::openssl::configurer::CertificateChainBuffer::CertificateChainBuffer()]: Error. Could not get certificate store.");
    }

  auto chainOfCertificates = std::shared_ptr<X509>(PEM_read_bio_X509_AUX(m_buffer.get(), nullptr, nullptr, nullptr), X509_free);

    //if (chainOfCertificates.get() == NULL) {
    //    throw std::runtime_error("[oatpp::openssl::configurer::CertificateChainBuffer::configure()]: Error. "
    //                             "Call to 'X509_STORE_add_cert' failed.");
    //}

  if (!X509_STORE_add_cert(cert_store, chainOfCertificates.get())) {
    throw std::runtime_error("[oatpp::openssl::configurer::CertificateChainBuffer::configure()]: Error. "
                             "Call to 'X509_STORE_add_cert' failed.");
  }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}

}}}
