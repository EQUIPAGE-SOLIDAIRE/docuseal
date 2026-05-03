# frozen_string_literal: true

require 'net/http'
require 'json'
require 'base64'

module ExternalSigner
  CERTIFICATE_CACHE_TTL = 3600

  module_function

  def clear_certificate_cache!(account = nil)
    cache_store.delete(cache_key(account))
  end

  def load_certificate(account = nil)
    key = cache_key(account)
    cached = cache_store[key]
    return cached[:cert] if cached && (Time.now.to_i - cached[:fetched_at]) < CERTIFICATE_CACHE_TTL

    uri = URI("#{Docuseal.external_signer_url(account)}/certificate")
    request = Net::HTTP::Get.new(uri, headers(account))

    response = http_call(uri, request)
    data = JSON.parse(response.body)

    cert = OpenSSL::X509::Certificate.new(Base64.strict_decode64(data['certificate']))

    cache_store[key] = { cert:, fetched_at: Time.now.to_i }

    cert
  rescue => e
    Rails.logger.error("ExternalSigner#load_certificate failed: #{e.message}")
    raise
  end

  def sign_hash(digest_algorithm, hash, account = nil)
    uri = URI("#{Docuseal.external_signer_url(account)}/sign-hash")
    request = Net::HTTP::Post.new(uri, headers(account).merge('Content-Type' => 'application/json'))
    request.body = { algorithm: digest_algorithm.upcase, hash: Base64.strict_encode64(hash) }.to_json

    response = http_call(uri, request)
    data = JSON.parse(response.body)

    Base64.strict_decode64(data['signature'])
  rescue => e
    Rails.logger.error("ExternalSigner#sign_hash failed: #{e.message}")
    raise
  end

  def cache_store
    @cache_store ||= {}
  end

  private_class_method

  def cache_key(account)
    account ? "account_#{account.id}" : 'default'
  end

  def headers(account = nil)
    { 'Authorization' => "Bearer #{Docuseal.external_signer_secret(account)}" }
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
