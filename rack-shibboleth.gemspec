# -*- encoding: utf-8 -*-
$:.push File.expand_path('../lib', __FILE__)
require 'rack/shibboleth/version'

Gem::Specification.new do |s|
  s.name        = 'rack-shibboleth'
  s.version     = Rack::Shibboleth::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ['Alex Crichton']
  s.email       = ['alex@alexcrichton.com']
  s.homepage    = 'https://github.com/alexcrichton/rack-shibboleth'
  s.summary     = 'Shibboleth meets Ruby and Rack'
  s.description = %Q{
    Why use an Apache module when you could use a nice and simple rack
    middleware to get Shibboleth authentication? This gem supplies ruby bindings
    for the Shibboleth protocol.

    It's not as fully featured as the published Shibboleth implementation, but
    it gets the job done in most circumstances.
  }

  s.files         = `git ls-files lib README.md`.split("\n")
  s.test_files    = `git ls-files -- {spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ['lib']

  s.add_dependency 'rack'
  s.add_dependency 'rsa'
  s.add_dependency 'libxml-ruby'

  s.add_development_dependency 'rake'
  s.add_development_dependency 'guard'
  s.add_development_dependency 'guard-rspec'
  s.add_development_dependency 'guard-bundler'
  s.add_development_dependency 'rspec'
  s.add_development_dependency 'rack-test'
end
