require 'digest/sha1'
require 'nokogiri'
require 'openssl'
require 'rsa'

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
        @doc = Nokogiri::XML(xml)
      end

      # Tests whether the response from the IdP is a valid response. A call to
      # this function removes the ds:Signature element to perform the
      # verification.
      # 
      # @return [Boolean] true if the document is signed/hashed correctly or
      #         false otherwise.
      def valid?
        signature = @doc.xpath('//ds:Signature', 'ds' => DS).first
        return false if signature.nil?

        signature.remove

        valid_hashes?(signature) && valid_signature?(signature)
      end

      # Decodes the response of the IdP and retuns the decrypted XML
      # 
      # @param [OpenSSL::PKey::RSA] private_key the corresponding key to the
      #        public key which was used to encrypt the response.
      # 
      # @return [Nokogiri::XML::Document, false] The XML document which was
      #         decrypted, or if decryption failed, false is returned.
      def decode private_key
        return false unless valid?

        # This is the public key which encrypted the first CipherValue
        cert   = @doc.xpath('//ds:X509Certificate', 'ds' => DS)
        c1, c2 = @doc.xpath('//xenc:CipherValue', 'xenc' => XENC)

        cert = OpenSSL::X509::Certificate.new(Base64.decode64(cert.text))
        return false unless cert.check_private_key(private_key)

        # Generate the key used for the cipher below via the RSA::OAEP algo
        rsak      = RSA::Key.new private_key.n, private_key.d
        v1s       = Base64.decode64(c1.text)
        puts 'here'
        begin
          cipherkey = RSA::OAEP.decode rsak, v1s
        rescue
          # TODO: rescue specific errors
          return false
        end

        # The aes-128-cbc cipher has a 128 bit initialization vector (16 bytes)
        # and this is the first 16 bytes of the raw string.
        bytes  = Base64.decode64(c2.text).bytes.to_a
        iv     = bytes[0...16].pack('c*')
        others = bytes[16..-1].pack('c*')

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
        Nokogiri::XML(out[0..-(padding + 1)])
      end

      private
      
      # Validates the elements which the given signature has hashes for.
      # Each element must be canonicalized before digestion.
      # 
      # @param [Nokogiri::XML::Node] signature the signature of the document
      def valid_hashes? signature
        signature.xpath('.//ds:Reference', 'ds' => DS).all? do |ref|
          hashed_element = @doc.css("[ID='#{ref['URI'][1..-1]}']")

          # The XML digested must be canonicalized as per the W3's specification
          # at http://www.w3.org/TR/xml-c14n
          c14n = hashed_element.document.canonicalize
          digest = Base64.encode64(Digest::SHA1.digest(c14n)).chomp

          digest_listed = signature.xpath('.//ds:DigestValue', 'ds' => DS).text

          digest == digest_listed
        end
      end

      # Validates that the signature for a given document is valid by verifying
      # it against the public key listed.
      # 
      # @param [Nokogiri::XML::Node] signature the signature of the document
      def valid_signature? signature
        # We create a new XML document in Nokogiri to canonicalize the
        # signature. Nokogiri needs the xmlns:ds tag on the root element to
        # preserve the 'ds:' namespace on all the elements. Not exactly sure
        # why this is needed, but it works if we do it.
        info = signature.xpath('.//ds:SignedInfo', 'ds' => DS).first
        info['xmlns:ds'] = DS

        canonicalized = Nokogiri::XML(info.to_s).canonicalize

        b64_sig = signature.xpath('.//ds:SignatureValue', 'ds' => DS).text
        dec_sig = Base64.decode64 b64_sig

        b64_cert = signature.xpath('.//ds:X509Certificate', 'ds' => DS).text
        cert = OpenSSL::X509::Certificate.new(Base64.decode64(b64_cert))

        digest = OpenSSL::Digest::SHA1.new
        cert.public_key.verify(digest, dec_sig, canonicalized)
      end

    end
  end
end

module RSA
  module OAEP
    extend self

    # The algorithms below need the HLEN variable. This is the length of the
    # hashes generated by the hashing function. For now, this only supports SHA1
    # as the hashing function, and this has a hash length of 20
    HLEN = 20

    # Performs the rsa-oaep-mgf1 decrypt algorithm. This is specified on page
    # 14 of http://www.ietf.org/rfc/rfc2437.txt.
    # 
    # This implementation assumes that the sha1 hashing algorithm was used.
    # 
    # @param [RSA::Key] k the private key whose public key was used to
    #        encrypt the data
    # @param [String] c a string of raw bytes representing the text to be
    #        decoded
    # @param [String] p the options which were used in the original encoding of
    #        the string. By default this is the empty string.
    def decode k, c, p = ''
      # First, generate how many bytes the key's modulus is
      n = k.modulus
      bytes = 0
      while n > 0
        bytes += 1
        n /= 2
      end
      bytes /= 8

      raise 'wrong length!' unless c.length == bytes

      enc = RSA::PKCS1.os2ip c
      m   = RSA::PKCS1.rsadp k, enc
      em  = RSA::PKCS1.i2osp m, bytes - 1

      eme_decode em, p
    end

    # Decodes the encrypted message as specified by the algorithm listed on
    # http://www.ietf.org/rfc/rfc2437.txt in page 22
    # 
    # @param [String] em the encoded message that needs to be decoded
    # @param 
    def eme_decode em, p
      raise 'asdf' if em.length < HLEN * 2 + 1

      maskedSeed = em[0...HLEN]
      maskedDB   = em[HLEN..-1]
      seedMask   = mgf1 maskedDB, HLEN
      seed       = xor maskedSeed, seedMask
      dbMask     = mgf1 seed, em.size - HLEN
      db         = xor maskedDB, dbMask
      pHash      = Digest::SHA1.digest p

      ind = db.index("\x01", HLEN)
      raise 'nil!' if ind.nil?

      pHash2 = db[0...HLEN]
      ps     = db[HLEN...ind]
      m      = db[(ind + 1)..-1]

      raise 'nonzero!' unless ps.bytes.all?(&:zero?)
      raise 'Hashes are not the same' unless pHash2 == pHash

      m
    end

    # Defined in seciton 10.2.1 of http://www.ietf.org/rfc/rfc2437.txt, this
    # is the mask generation function used in the eme_decode function
    # 
    # @param [String] z this is the seed which the mask function runs off of
    # @param [Integer] l the desired length of the resultant hash
    # @return [String] the mask generated
    def mgf1 z, l
      t = ''

      (0..(l / HLEN)).each{ |i|
        t += Digest::SHA1.digest(z + RSA::PKCS1.i2osp(i, 4))
      }

      t[0...l]
    end

    private

    def xor s1, s2
      raise 'wtf' if s1.length != s2.length

      s1.bytes.to_a.zip(s2.bytes.to_a).map{ |a, b| a ^ b }.pack('c*')
    end

  end
end
