# frozen_string_literal: true

module Docuseal
  PRODUCT_URL = 'https://www.docuseal.com'
  PRODUCT_EMAIL_URL = ENV.fetch('PRODUCT_EMAIL_URL', PRODUCT_URL)
  NEWSLETTER_URL = "#{PRODUCT_URL}/newsletters".freeze
  ENQUIRIES_URL = "#{PRODUCT_URL}/enquiries".freeze
  PRODUCT_NAME = 'DocuSeal'
  DEFAULT_APP_URL = ENV.fetch('APP_URL', 'http://localhost:3000')
  GITHUB_URL = 'https://github.com/docusealco/docuseal'
  DISCORD_URL = 'https://discord.gg/qygYCDGck9'
  TWITTER_URL = 'https://twitter.com/docusealco'
  TWITTER_HANDLE = '@docusealco'
  CHATGPT_URL = "#{PRODUCT_URL}/chat".freeze
  SUPPORT_EMAIL = 'support@docuseal.com'
  HOST = ENV.fetch('HOST', 'localhost')
  AATL_CERT_NAME = 'docuseal_aatl'
  CONSOLE_URL = if Rails.env.development?
                  'http://console.localhost.io:3001'
                elsif ENV['MULTITENANT'] == 'true'
                  "https://console.#{HOST}"
                else
                  'https://console.docuseal.com'
                end
  CLOUD_URL = if Rails.env.development?
                'http://localhost:3000'
              else
                'https://docuseal.com'
              end
  CDN_URL = if Rails.env.development?
              'http://localhost:3000'
            elsif ENV['MULTITENANT'] == 'true'
              "https://cdn.#{HOST}"
            else
              'https://cdn.docuseal.com'
            end

  CERTS = JSON.parse(ENV.fetch('CERTS', '{}'))
  TIMESERVER_URL = ENV.fetch('TIMESERVER_URL', nil)

  EXTERNAL_SIGNER_URL_ENV = ENV.fetch('EXTERNAL_SIGNER_URL', nil).freeze
  EXTERNAL_SIGNER_SECRET_ENV = ENV.fetch('EXTERNAL_SIGNER_SECRET', nil).freeze
  EXTERNAL_SIGNER_TIMEOUT = ENV.fetch('EXTERNAL_SIGNER_TIMEOUT', '15').to_i.freeze
  VERSION_FILE_PATH = Rails.root.join('.version')
  VERSION_FILE2_PATH = Rails.public_path.join('version')

  DEFAULT_URL_OPTIONS = {
    host: HOST,
    protocol: ENV['FORCE_SSL'].present? ? 'https' : 'http'
  }.freeze

  module_function

  def version
    @version ||=
      if VERSION_FILE_PATH.exist?
        VERSION_FILE_PATH.read.strip
      elsif VERSION_FILE2_PATH.exist?
        VERSION_FILE2_PATH.each_line.first.to_s.strip
      end
  end

  def multitenant?
    ENV['MULTITENANT'] == 'true'
  end

  def advanced_formats?
    multitenant?
  end

  def demo?
    ENV['DEMO'] == 'true'
  end

  def active_storage_public?
    ENV['ACTIVE_STORAGE_PUBLIC'] == 'true'
  end

  def external_signer_config(account = nil)
    db = EncryptedConfig.find_by(account:, key: EncryptedConfig::EXTERNAL_SIGNER_KEY)&.value || {}
    {
      'url' => db['url'].presence || EXTERNAL_SIGNER_URL_ENV,
      'secret' => db['secret'].presence || EXTERNAL_SIGNER_SECRET_ENV,
      'enabled' => db.key?('enabled') ? db['enabled'] : EXTERNAL_SIGNER_URL_ENV.present?
    }
  end

  def external_signer?(account = nil)
    config = external_signer_config(account)
    config['enabled'] && config['url'].present?
  end

  def external_signer_url(account = nil)
    external_signer_config(account)['url']
  end

  def external_signer_secret(account = nil)
    external_signer_config(account)['secret']
  end

  def default_pkcs
    return if Docuseal::CERTS['enabled'] == false

    @default_pkcs ||= GenerateCertificate.load_pkcs(Docuseal::CERTS)
  end

  def fulltext_search?
    return @fulltext_search unless @fulltext_search.nil?

    @fulltext_search =
      if SearchEntry.table_exists?
        Docuseal.multitenant? || AccountConfig.exists?(key: :fulltext_search, value: true)
      else
        false
      end
  end

  def enable_pwa?
    true
  end

  def pdf_format
    @pdf_format ||= ENV['PDF_FORMAT'].to_s.downcase
  end

  def trusted_certs
    @trusted_certs ||=
      ENV['TRUSTED_CERTS'].to_s.gsub('\\n', "\n").split("\n\n").map do |base64|
        OpenSSL::X509::Certificate.new(base64)
      end
  end

  def default_url_options
    return DEFAULT_URL_OPTIONS if multitenant?

    @default_url_options ||= begin
      value = EncryptedConfig.find_by(key: EncryptedConfig::APP_URL_KEY)&.value if ENV['APP_URL'].blank?
      value ||= DEFAULT_APP_URL
      url = Addressable::URI.parse(value)
      { host: url.host, port: url.port, protocol: url.scheme }
    end
  end

  def product_name
    PRODUCT_NAME
  end

  def refresh_default_url_options!
    @default_url_options = nil
  end
end
