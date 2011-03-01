require 'base64'
require 'digest/md5'
require 'time'
require 'zlib'

module Rack
  class Shibboleth

    ##
    # Represents a request to be made to a Shibboleth IdP. This request is
    # serialized and sent to the IdP via a URL parameter to begin authorization.
    class Request

      # The full url of where the IdP's authentication point is located.
      # Currently only Shibboleth 2's HTTP-POST method is supported, so this
      # url should be similar to:
      #
      #   https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO
      #
      # The exact location may be different, but the SAML2/Redirect/SSO should
      # probably be there
      #
      # @return [String] The URL the IdP is located at
      attr_accessor :idp_url

      # Where the IdP will redirect to once the user has successfully
      # authenticated with them. This is normally specified in the metadata
      # given to the IdP and cannot be different from what's listed there
      #
      # @return [String] The URL the IdP should redirect back to
      attr_accessor :assertion_url

      # The name of the issuing application of the request for authentication.
      # Otherwise, the SP. This name is registered with your IdP in the metadata
      # file provided to them
      #
      # @return [String] The issuer of the request
      attr_accessor :issuer

      # Creates a new request
      # 
      # @param [Hash] opts a hash where if the symbols :issuer, :idp_url,
      #               or :assertion_url are set, the corresponding attributes
      #               will be set in the created request
      def initialize opts = {}
        @issuer        = opts[:issuer]
        @assertion_url = opts[:assertion_url]
        @idp_url       = opts[:idp_url]
      end

      # Encodes this request so it's ready to be sent to the IdP
      #
      # @return [String] this request's saml encoded properly so it may be sent
      #                  in URL parameters or whatever
      def encode
        # Not really sure why we only take part of the defalated saml, but
        # the IdP seems to take it...
        deflated_request = Zlib::Deflate.deflate(saml, 9)[2..-5]
        Base64.encode64(deflated_request)
      end

      # Generates the actual SAML request as XML. This is unencoded, so it
      # should go through the encoding process before being sent to the Idp
      #
      # @return [String] the saml request to send to the IdP
      def saml
        validate_specified_attributes!

        issued = Time.now.utc.iso8601

        # This request template was captured in a request to an IdP from a
        # known working Shibboleth SP
        %Q{<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="#{assertion_url}" Destination="#{idp_url}" ID="_#{id}" IssueInstant="#{issued}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0">
        <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">#{issuer}</saml:Issuer><samlp:NameIDPolicy AllowCreate="1"/>
        </samlp:AuthnRequest>}
      end

      # The unique ID for this request. This ID is present in the request to
      # the Idp
      #
      # @return [String] a 32 character ID for this request
      def id
        @id ||= Digest::MD5.hexdigest rand.to_s
      end

      private

      def validate_specified_attributes!
        if idp_url.nil? || assertion_url.nil? || issuer.nil?
          raise ArgumentError, "You need to specify all of :idp_url, :assertion_url, and :issuer"
        end
      end

    end
  end
end
