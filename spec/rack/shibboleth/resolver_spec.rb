require 'spec_helper'

describe Rack::Shibboleth::Resolver do

  context 'parsing a sample response' do

    before do
      Time.stub(:now).and_return Time.utc(2011, 3, 1, 15, 55)
    end

    let(:response) { Rack::Test.read_fixture 'sample-response' }
    subject{
      Rack::Shibboleth::Resolver.from_response response, Rack::Test.sample_key,
        {:issuer => 'https://mirror.alexcrichton.com/shibboleth-sp'}
    }

    its(:issued) { should be_an_instance_of(Time) }
    its(:issuer) { should == 'https://idp.testshib.org/idp/shibboleth' }

    it 'parses the conditions specified in the docuent' do
      subject.conditions[:after].should be_an_instance_of(Time)
      subject.conditions[:before].should be_an_instance_of(Time)
      subject.conditions[:audience].should ==
        'https://mirror.alexcrichton.com/shibboleth-sp'
    end

    it "extracts all of the attributes listed" do
      subject.attributes.should == {
        'eduPersonScopedAffiliation' => 'Member@testshib.org',
        'title'                      => 'Right Honourable',
        'uid'                        => 'alterego',
        'eduPersonEntitlement'       => 'urn:mace:dir:entitlement:common-lib-terms',
        'sn'                         => 'Half',
        'cn'                         => 'Theother Half',
        'eduPersonTargetedID'        => 'v0h5HX5fOxJ7FV3cO7uEYXEUIDY=',
        'eduPersonPrincipalName'     => 'alterego@testshib.org',
        'telephoneNumber'            => '555-5555',
        'givenName'                  => 'Theother',
        'eduPersonAffiliation'       => 'Member'
      }
    end

  end

end
