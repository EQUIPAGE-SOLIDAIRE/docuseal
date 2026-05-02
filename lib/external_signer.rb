# frozen_string_literal: true

require 'net/http'
require 'json'
require 'base64'

module ExternalSigner
  CERTIFICATE_CACHE_TTL = 3600

  module_function

  def load_certificate
    cached = certificate_cache
    return cached[:cert] if cached && (Time.now.to_i - cached[:fetched_at]) < CERTIFICATE_CACHE_TTL

    uri = URI("#{Docuseal::EXTERNAL_SIGNER_URL}/certificate")
    request = Net::HTTP::Get.new(uri, headers)

    response = http_call(uri, request)
    data = JSON.parse(response.body)

    cert = OpenSSL::X509::Certificate.new(Base64.strict_decode64(data['certificate']))

    @certificate_cache = { cert:, fetched_at: Time.now.to_i }

    cert
  rescue => e
    Rails.logger.error("ExternalSigner#load_certificate failed: #{e.message}")
    raise
  end

  def sign_hash(digest_algorithm, hash)
    uri = URI("#{Docuseal::EXTERNAL_SIGNER_URL}/sign-hash")
    request = Net::HTTP::Post.new(uri, headers.merge('Content-Type' => 'application/json'))
    request.body = { algorithm: digest_algorithm.upcase, hash: Base64.strict_encode64(hash) }.to_json

    response = http_call(uri, request)
    data = JSON.parse(response.body)

    Base64.strict_decode64(data['signature'])
  rescue => e
    Rails.logger.error("ExternalSigner#sign_hash failed: #{e.message}")
    raise
  end

  def certificate_cache
    @certificate_cache
  end

  private_class_method

  def headers
    { 'Authorization' => "Bearer #{Docuseal::EXTERNAL_SIGNER_SECRET}" }
  end

  def http_call(uri, request)
    response = Net::HTTP.start(uri.hostname, uri.port,
                               use_ssl: uri.scheme == 'https',
                               read_timeout: Docuseal::EXTERNAL_SIGNER_TIMEOUT,
                               open_timeout: 5) do |http|
      http.request(request)
    end

    unless response.is_a?(Net::HTTPSuccess)
      raise "External signer returned #{response.code}: #{response.body}"
    end

    response
  end
end
