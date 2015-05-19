require 'cgi'
require 'base64'
require 'openssl'

# The Azure module is strictly a namespace.
module Azure

  # The SASToken class abstractly represents a Shared Access Signature token.
  class SasToken

    # The string token generated.
    attr_reader :token

    # Generate and return an SasToken object.
    #
    # token = SasToken.new('http://yourexamplenamespace', 'some-policy', 'xxxyyyzzz')
    #
    # Parameters:
    #
    # * url         - The resource identifier you're accessing.
    # * key_name    - The policy/authorization rule for the given access_key.
    # * access_key  - The policy's secret key.
    # * lifetime    - The lifetime (expire) of the token in minutes. The default is 1 hour.
    # * digest_type - The type of OpenSSL::Digest to use. The default is sha256.
    #
    def initialize(url, key_name, access_key, lifetime = 10, digest_type = 'sha256')
      target_uri = CGI.escape(url.downcase).gsub('+', '%20').downcase
      expires = Time.now.to_i + lifetime
      to_sign = "#{target_uri}\n#{expires}"

      signature = CGI.escape(
        Base64.strict_encode64(
          OpenSSL::HMAC.digest(
            OpenSSL::Digest.new(digest_type), access_key, to_sign
          )
        )
      ).gsub('+', '%20')

      @token = "SharedAccessSignature sr=#{target_uri}&sig=#{signature}&se=#{expires}&skn=#{key_name}"
    end

    # Returns the SasToken object as a string.
    def to_s
      @token
    end

    # Returns the SasToken object as a string.
    def to_str
      @token
    end
  end # SasToken

end # Azure
