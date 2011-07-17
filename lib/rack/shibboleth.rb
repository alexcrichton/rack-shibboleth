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

    def initialize app, opts = {}
      @app = app
      @opts = opts

      if @opts[:private_key].nil? || !::File.exists?(@opts[:private_key])
        raise ArgumentError, 'need valid :private_key option'
      end
      @private_key = OpenSSL::PKey::RSA.new(::File.read(@opts[:private_key]))
    end

    def call env
      req = Rack::Request.new env

      if req.path == '/auth/shibboleth'
        response = Rack::Response.new
        shib_request = Shibboleth::Request.new @opts

        query = {
          :SAMLRequest => shib_request.encode,
          :RelayState => "#{req.referer}/auth/shibboleth/callback"
        }

        arr = query.map{ |k, v| "#{k}=#{Rack::Utils.escape v}" }

        response.redirect @opts[:idp_url] + '?' + arr.join('&')
        response.finish
      elsif req.path == '/Shibboleth.sso/SAML2/POST'
        response = Rack::Response.new

        resolver = Shibboleth::Resolver.from_response env['rack.input'].read,
          @private_key

        [200, {'Content-Type' => 'text/plain'},
          [resolver.attributes.inspect]]
      else
        @app.call env
      end
    end

  end
end