# frozen_string_literal: true

require 'rails_helper'

RSpec.describe ExternalSigner do
  let(:base_url) { 'https://signing.example.com' }
  let(:secret) { 'test-secret-token' }
  let(:auth_header) { { 'Authorization' => "Bearer #{secret}" } }

  before do
    stub_const('Docuseal::EXTERNAL_SIGNER_URL', base_url)
    stub_const('Docuseal::EXTERNAL_SIGNER_SECRET', secret)
    stub_const('Docuseal::EXTERNAL_SIGNER_TIMEOUT', 15)
    # Reset certificate cache between tests
    described_class.instance_variable_set(:@certificate_cache, nil)
  end

  describe '.load_certificate' do
    let(:cert) { OpenSSL::X509::Certificate.new(generate_self_signed_cert) }
    let(:cert_b64) { Base64.strict_encode64(cert.to_der) }

    it 'fetches and returns the certificate from the proxy' do
      stub_request(:get, "#{base_url}/certificate")
        .with(headers: auth_header)
        .to_return(
          status: 200,
          body: { certificate: cert_b64, subject: cert.subject.to_s }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      result = described_class.load_certificate

      expect(result).to be_a(OpenSSL::X509::Certificate)
      expect(result.to_der).to eq(cert.to_der)
    end

    it 'caches the certificate and does not make a second HTTP call' do
      stub = stub_request(:get, "#{base_url}/certificate")
        .to_return(
          status: 200,
          body: { certificate: cert_b64 }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      described_class.load_certificate
      described_class.load_certificate

      expect(stub).to have_been_requested.once
    end

    it 'raises on non-200 response' do
      stub_request(:get, "#{base_url}/certificate")
        .to_return(status: 401, body: { error: 'Unauthorized' }.to_json)

      expect { described_class.load_certificate }.to raise_error(RuntimeError, /401/)
    end

    it 'raises on network error' do
      stub_request(:get, "#{base_url}/certificate").to_raise(Net::OpenTimeout)

      expect { described_class.load_certificate }.to raise_error(Net::OpenTimeout)
    end
  end

  describe '.sign_hash' do
    let(:hash_bytes) { Digest::SHA256.digest('test content') }
    let(:fake_signature) { SecureRandom.bytes(256) }
    let(:signature_b64) { Base64.strict_encode64(fake_signature) }

    it 'posts the hash and returns raw signature bytes' do
      stub_request(:post, "#{base_url}/sign-hash")
        .with(
          headers: auth_header.merge('Content-Type' => 'application/json'),
          body: { algorithm: 'SHA256', hash: Base64.strict_encode64(hash_bytes) }.to_json
        )
        .to_return(
          status: 200,
          body: { signature: signature_b64 }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      result = described_class.sign_hash('SHA256', hash_bytes)

      expect(result).to eq(fake_signature)
    end

    it 'upcases the algorithm before sending' do
      stub = stub_request(:post, "#{base_url}/sign-hash")
        .with(body: hash_including('algorithm' => 'SHA256'))
        .to_return(
          status: 200,
          body: { signature: signature_b64 }.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )

      described_class.sign_hash('sha256', hash_bytes)

      expect(stub).to have_been_requested
    end

    it 'raises on non-200 response' do
      stub_request(:post, "#{base_url}/sign-hash")
        .to_return(status: 500, body: { error: 'Token not found' }.to_json)

      expect { described_class.sign_hash('SHA256', hash_bytes) }.to raise_error(RuntimeError, /500/)
    end
  end

  private

  def generate_self_signed_cert
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse('/CN=Test Signer/O=Test')
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now
    cert.not_after = Time.now + 3600
    cert.sign(key, OpenSSL::Digest::SHA256.new)
    cert.to_der
  end
end
