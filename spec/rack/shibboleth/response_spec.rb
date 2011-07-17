require 'spec_helper'

describe Rack::Shibboleth::Response do

  let(:xml) { Rack::Test.read_fixture('sample-xml') }
  subject{ Rack::Shibboleth::Response.new xml }

  it { should be_valid }

  it "decodes correctly without error" do
    decoded = subject.decode Rack::Test.sample_key

    decoded.should be_a(LibXML::XML::Document)
    decoded.canonicalize.should == Rack::Test.read_fixture('sample-decoded.xml')
  end

  context "an invalid file" do
    let(:xml) { 'not an xml string' }

    it { should_not be_valid }

    it "returns false for a decoding" do
      decoded = subject.decode Rack::Test.sample_key
      decoded.should be_false
    end
  end
end
