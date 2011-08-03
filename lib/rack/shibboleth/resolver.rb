require 'base64'

module Rack
  class Shibboleth
    class Resolver

      # Creates a new Resolver from the IdP's response, using the given private
      # key to decrypt the response.
      #
      # @param [String] resp the 'SAMLResponse' value from the IdP
      # @param [OpenSSL::PKey::RSA] private_key the private key which will be
      #        used to decrypt the response
      #
      # @return [Rack::Shibboleth::Resolver, false] either the resolver object
      #         for the specified response or false if the response could not
      #         be decode and/or verified
      def self.from_response resp, private_key, opts
        return nil if resp.nil?
        xml = Base64.decode64 resp
        shib_response = Shibboleth::Response.new xml

        assertion = shib_response.decode private_key
        if assertion
          resolver = Resolver.new assertion, opts
          resolver.valid? ? resolver : nil
        end
      end

      # Creates a new resolver for the specified assertion document which was
      # decoded from a response to the IdP
      #
      # @param [LibXML::XML::Document] assertion the parsed version of the
      #        xml received from the IdP
      # @param [Hash] opts options specified to {Rack::Shibboleth}
      def initialize assertion, opts
        @doc  = assertion
        @opts = opts
      end

      # Tests whether this response from the IdP is valid based on the
      # conditions specified.
      #
      # @return [Boolean] true if the resolver has valid attributes.
      def valid?
        conds = conditions
        conds[:after] <= Time.now && Time.now <= conds[:before] &&
          conds[:audience] == @opts[:issuer]
      end

      # The exact time that the response was issued at
      #
      # @return [Time] the time this response was issued at
      def issued
        Time.parse @doc.find_first('//saml2:Assertion')['IssueInstant']
      end

      # The entity name of the IdP who issued the response
      #
      # @return [String] the entity name of the Idp
      def issuer
        @doc.find_first('//saml2:Issuer').content
      end

      # Extracts the conditions under which this response is valid.
      #
      # @return [Hash] with the following keys:
      #           :after  - [Time] the response is only valid after this time
      #           :before - [Time] the response is only valid before this time
      #           :audience - [String] the response is only meant for this
      #                       audience specified by their entity name
      def conditions
        conditions = @doc.find_first('//saml2:Conditions')
        audience = conditions.find_first('.//saml2:Audience')
        {
          :after => Time.parse(conditions['NotBefore']),
          :before => Time.parse(conditions['NotOnOrAfter']),
          :audience => audience.content
        }
      end

      # Extracts the attributes from the response.
      #
      # @return [Hash] the key values are the FriendlyNames of each of the
      #         attributes as strings and the value is the value listed as a
      #         string
      def attributes
        attributes = @doc.find('//saml2:Attribute')
        hash = {}

        attributes.each do |el|
          hash[el['FriendlyName']] =
            el.find_first('.//saml2:AttributeValue').content
        end

        hash
      end

    end
  end
end
