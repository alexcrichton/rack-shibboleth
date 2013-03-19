require 'openssl'
require 'rack'

module Rack
  class Shibboleth
    autoload :Request,  'rack/shibboleth/request'
    autoload :Resolver, 'rack/shibboleth/resolver'
    autoload :Response, 'rack/shibboleth/response'
    autoload :VERSION,  'rack/shibboleth/version'

    DS   = 'ds:http://www.w3.org/2000/09/xmldsig#'
    XENC = 'xenc:http://www.w3.org/2001/04/xmlenc#'
    SAML2 = 'saml2:urn:oasis:names:tc:SAML:2.0:assertion'

    # Creates a new instance of this middleware to be used.
    # Required options are:
    # * private_key   - path to the private key file which is the pair of
    #                    the public key registered with your IdP
    # * idp_url       - see {Request#idp_url}
    # * assertion_url - see {Request#assertion_url}
    # * issuer        - see {Request#issuer}
    #
    # Using this middleware, a client will attempt authentication if the
    # +/auth/shibboleth+ path is visited. Upon successful authentication, the
    # application will be called on the +assertion_url+ path with the
    # {Resolver} object located in:
    #  env['shibboleth.resolver']
    #
    # This object can be either +nil+ or a {Resolver}
    #
    # @param app the application to proxy requests to
    # @param [Hash] opts a hash of options to this shibboleth instance.
    def initialize app, opts
      @app = app
      @opts = opts

      if @opts[:private_key].nil? || !::File.exists?(@opts[:private_key])
        raise ArgumentError, 'need valid :private_key option'
      end
      raise ArgumentError, 'need :idp_url option' if @opts[:idp_url].nil?
      raise ArgumentError, 'need :issuer option' if @opts[:issuer].nil?
      raise ArgumentError, 'need :assertion_url option' if @opts[:assertion_url].nil?
      @private_key = OpenSSL::PKey::RSA.new(::File.read(@opts[:private_key]))
    end

    def call env
      request = Rack::Request.new env
      if request.path_info == '/auth/shibboleth'
        query = {
          :SAMLRequest => Shibboleth::Request.new(@opts).encode,
          :RelayState  => @opts[:issuer]
        }

        arr = query.map{ |k, v| "#{k}=#{Rack::Utils.escape v}" }

        return Rack::Response.new.tap{ |r|
          r.redirect @opts[:idp_url] + '?' + arr.join('&')
        }.finish
      elsif request.path_info == '/Shibboleth.sso/SAML2/POST'
        env['shibboleth.resolver'] = Shibboleth::Resolver.from_response(
          request.params['SAMLResponse'], @private_key, @opts)
      end

      @app.call env
    end

  end
end
