require 'bundler'
Bundler.require :default, :development

require 'rspec/core'
require 'rack/test'
require 'openssl'

RSpec.configure do |c|
  c.color_enabled = true
end

module Rack
  module Test

    def self.sample_cert
      OpenSSL::X509::Certificate.new ::File.read(fixture_file('sp-cert.pem'))
    end

    def self.sample_key
      OpenSSL::PKey::RSA.new ::File.read(fixture_file('sp-key.pem'))
    end

    def self.fixture_path
      ::File.expand_path('../fixtures', __FILE__)
    end

    def self.fixture_file file
      ::File.join(fixture_path, file)
    end

    def self.read_fixture file
      ::File.read fixture_file(file)
    end

  end
end
