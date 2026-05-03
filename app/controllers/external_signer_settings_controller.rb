# frozen_string_literal: true

class ExternalSignerSettingsController < ApplicationController
  before_action :load_encrypted_config
  authorize_resource :encrypted_config, parent: false

  def show
    @config = Docuseal.external_signer_config
  end

  def create
    value = external_signer_params

    @encrypted_config.value = {
      'url' => value[:url].to_s.strip.presence,
      'secret' => value[:secret].to_s.strip.presence,
      'enabled' => value[:enabled] == '1'
    }

    if @encrypted_config.save
      ExternalSigner.clear_certificate_cache!(current_account)
      redirect_to settings_external_signer_path, notice: I18n.t('changes_have_been_saved')
    else
      render :show, status: :unprocessable_content
    end
  end

  private

  def load_encrypted_config
    @encrypted_config = EncryptedConfig.find_or_initialize_by(
      account: current_account,
      key: EncryptedConfig::EXTERNAL_SIGNER_KEY
    )
  end

  def external_signer_params
    params.require(:external_signer).permit(:url, :secret, :enabled)
  end
end
