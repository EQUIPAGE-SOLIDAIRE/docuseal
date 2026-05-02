# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Submissions::GenerateResultAttachments do
  describe '.build_signing_params' do
    let(:tsa_url) { nil }
    let(:submitter) { instance_double('Submitter') }
    let(:pkcs) do
      instance_double('OpenSSL::PKCS12',
                      certificate: double('cert'),
                      key: double('key'),
                      ca_certs: [])
    end

    context 'when external signer is not configured' do
      before { allow(Docuseal).to receive(:external_signer?).and_return(false) }

      it 'uses the local pkcs certificate and key' do
        params = described_class.build_signing_params(submitter, pkcs, tsa_url)

        expect(params[:certificate]).to eq(pkcs.certificate)
        expect(params[:key]).to eq(pkcs.key)
        expect(params[:certificate_chain]).to eq([])
        expect(params).not_to have_key(:external_signing)
      end

      it 'adds timestamp handler when tsa_url is present' do
        params = described_class.build_signing_params(submitter, pkcs, 'https://tsa.example.com')

        expect(params[:timestamp_handler]).to be_a(Submissions::TimestampHandler)
        expect(params[:signature_size]).to eq(20_000)
      end
    end

    context 'when external signer is configured' do
      let(:cert) { instance_double('OpenSSL::X509::Certificate') }

      before do
        allow(Docuseal).to receive(:external_signer?).and_return(true)
        allow(ExternalSigner).to receive(:load_certificate).and_return(cert)
        allow(ExternalSigner).to receive(:sign_hash).and_return('fake-signature')
      end

      it 'uses the external certificate' do
        params = described_class.build_signing_params(submitter, nil, tsa_url)

        expect(params[:certificate]).to eq(cert)
      end

      it 'provides an external_signing lambda' do
        params = described_class.build_signing_params(submitter, nil, tsa_url)

        expect(params[:external_signing]).to be_a(Proc)
      end

      it 'does not use the local key' do
        params = described_class.build_signing_params(submitter, nil, tsa_url)

        expect(params).not_to have_key(:key)
      end

      it 'reserves 32KB for the signature' do
        params = described_class.build_signing_params(submitter, nil, tsa_url)

        expect(params[:signature_size]).to eq(32_768)
      end

      it 'external_signing lambda calls ExternalSigner.sign_hash' do
        hash = Digest::SHA256.digest('content')
        params = described_class.build_signing_params(submitter, nil, tsa_url)

        params[:external_signing].call('SHA256', hash)

        expect(ExternalSigner).to have_received(:sign_hash).with('SHA256', hash)
      end
    end
  end
end
