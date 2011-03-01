require 'base64'

module Rack
  class Shibboleth
    class Resolver

      # Creates a new Resolver from the IdP's response, using the given private
      # key to decrypt the response.
      # 
      # @param [String] resp the raw response from the IdP
      # @param [OpenSSL::PKey::RSA] private_key the private key which will be
      #        used to decrypt the response
      def self.from_response resp, private_key
        xml = Rack::Utils.parse_query(resp)
        xml = Base64.decode64 xml['SAMLResponse']
        shib_response = Shibboleth::Response.new xml

        assertion = shib_response.decode private_key

        assertion ? Resolver.new(assertion) : assertion
      end

      # Creates a new resolver for the specified assertion document which was
      # decoded from a response to the IdP
      # 
      # @param [Nokogiri::XML::Document] assertion the parsed version of the
      #        xml received from the IdP
      def initialize assertion
        @doc = assertion
      end

      # The exact time that the response was issued at
      # 
      # @return [Time] the time this response was issued at
      def issued
        Time.parse @doc.xpath('//saml2:Assertion').first['IssueInstant']
      end

      # The entity name of the IdP who issued the response
      # 
      # @return [String] the entity name of the Idp
      def issuer
        @doc.xpath('//saml2:Issuer').text
      end

      # Extracts the conditions under which this response is valid.
      # 
      # @return [Hash] with the following keys:
      #           :after  - [Time] the response is only valid after this time
      #           :before - [Time] the response is only valid before this time
      #           :audience - [String] the response is only meant for this
      #                       audience specified by their entity name
      def conditions
        conditions = @doc.xpath('//saml2:Conditions').first
        audience = conditions.xpath('.//saml2:Audience').first
        {
          :after => Time.parse(conditions['NotBefore']),
          :before => Time.parse(conditions['NotOnOrAfter']),
          :audience => audience.text
        }
      end

      # Extracts the attributes from the response.
      #
      # @return [Hash] the key values are the FriendlyNames of each of the
      #         attributes as strings and the value is the value listed as a
      #         string
      def attributes
        attributes = @doc.xpath('//saml2:Attribute')
        hash = {}

        attributes.each do |el|
          hash[el['FriendlyName']] =
            el.xpath('.//saml2:AttributeValue').first.text
        end

        hash
      end

    end
  end
end