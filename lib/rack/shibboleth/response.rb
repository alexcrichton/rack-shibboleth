require 'base64'
require 'digest/sha1'
require 'libxml'
require 'openssl'
require 'rack/shibboleth/rsa_ext'

module Rack
  class Shibboleth

    ##
    # Encapsulates the logic for parsing the response of an IdP to the
    # application. The XML of the response has already been extracted and is
    # the parameter for the construction of this class
    class Response

      # Initializes a new response with the given XML from the IdP
      #
      # @param [String] xml the response from the IdP
      def initialize xml
        begin
          @doc = LibXML::XML::Document.string(xml)
        rescue LibXML::XML::Error
          @doc = nil
        end
      end

      # Decodes the response of the IdP and retuns the decrypted XML
      #
      # @param [OpenSSL::PKey::RSA] private_key the corresponding key to the
      #        public key which was used to encrypt the response.
      #
      # @return [LibXML::XML::Document] The XML document which was
      #         decrypted, or if decryption failed, nil is returned.
      def decode private_key
        # This is the public key which encrypted the first CipherValue
        cert   = @doc.find_first(
            '//xenc:EncryptedData//ds:X509Certificate', [DS, XENC]).content
        c1, c2 = @doc.find('//xenc:CipherValue', XENC).map(&:content)

        cert = OpenSSL::X509::Certificate.new(Base64.decode64(cert))
        return nil unless cert.check_private_key(private_key)

        # Generate the key used for the cipher below via the RSA::OAEP algo
        rsak = RSA::Key.new private_key.n, private_key.d
        v1s  = Base64.decode64(c1)

        begin
          cipherkey = RSA::OAEP.decode rsak, v1s
        rescue RSA::OAEP::DecodeError
          return nil
        end

        # The aes-128-cbc cipher has a 128 bit initialization vector (16 bytes)
        # and this is the first 16 bytes of the raw string.
        bytes  = Base64.decode64(c2).unpack('C*')
        iv     = bytes.pack('c16')
        others = bytes.pack('c16X16c*')

        cipher = OpenSSL::Cipher.new('aes-128-cbc')
        cipher.decrypt
        cipher.iv  = iv
        cipher.key = cipherkey

        out = cipher.update(others)

        # The encrypted string's length might not be a multiple of the block
        # length of aes-128-cbc (16), so add in another block and then trim
        # off the padding. More info about padding is available at
        # http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html in
        # Section 5.2
        out << cipher.update("\x00" * 16)
        padding = out.bytes.to_a.last

        dec = LibXML::XML::Document.string(out[0..-(padding + 1)])

        # Must check that there is a signature listed and that the signature is
        # valid for the enclosing document.
        sig = dec.find_first('//ds:Signature', DS)
        if sig && valid_hashes?(sig) && valid_signature?(sig)
          dec
        end
      end

      private

      # Validates the elements which the given signature has hashes for.
      # Each element must be canonicalized before digestion.
      #
      # @param [LibXML::XML::Node] signature the signature of the document
      def valid_hashes? signature
        refs = signature.find('.//ds:Reference', DS).map{ |r| r['URI'][1..-1] }

        without_signature = LibXML::XML::Document.document(signature.doc)
        without_signature.find_first('//ds:Signature', DS).remove!
        # The XML digested must be canonicalized as per the W3's specification
        # at http://www.w3.org/TR/xml-c14n
        c14n = without_signature.canonicalize
        digest = Base64.encode64(Digest::SHA1.digest(c14n)).chomp

        refs.all? do |ref|
          hashed_element = @doc.find_first("//*[ID='#{ref}']")
          digest_listed  = signature.find_first('.//ds:DigestValue', DS).content

          digest == digest_listed
        end
      end

      # Validates that the signature for a given document is valid by verifying
      # it against the public key listed.
      #
      # @param [LibXML::XML::Node] signature the signature of the document
      def valid_signature? signature
        # We create a new XML document in Nokogiri to canonicalize the
        # signature. Nokogiri needs the xmlns:ds tag on the root element to
        # preserve the 'ds:' namespace on all the elements. Not exactly sure
        # why this is needed, but it works if we do it.
        info = signature.find_first('.//ds:SignedInfo', DS)

        canon = LibXML::XML::Document.new
        canon.root = canon.import info
        canonicalized = canon.canonicalize

        b64_sig = signature.find_first('.//ds:SignatureValue', DS).content
        dec_sig = Base64.decode64 b64_sig

        b64_cert = signature.find_first('.//ds:X509Certificate', DS).content
        cert = OpenSSL::X509::Certificate.new(Base64.decode64(b64_cert))

        digest = OpenSSL::Digest::SHA1.new
        cert.public_key.verify(digest, dec_sig, canonicalized)
      end

    end
  end
end
