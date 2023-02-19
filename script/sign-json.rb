#!/usr/bin/env ruby
require "base64"
require "json"
require "openssl"
require "pathname"

ROOT = Pathname(__dir__).parent.freeze
KEY_ID = ENV.fetch("JWS_SIGNING_KEY_ID").freeze
PRIVATE_KEY = OpenSSL::PKey::RSA.new(ENV.fetch("JWS_SIGNING_KEY")).freeze

[
  ROOT/"_site/api/formula.json",
  ROOT/"_site/api/cask.json",
].each do |path|
  data_string = path.read

  # References:
  # - RFC7515 [JSON Web Signature (JWS)]
  # - RFC7797 [JWS Unencoded Payload Option]

  header = {
    "alg": "PS512",
    "b64": false,
    "crit": ["b64"],
  }
  header_base64 = Base64.urlsafe_encode64(header.to_json)

  signing_input = "#{header_base64}.#{data_string}"

  signature = {
    "protected": header_base64,
    "header": {
      "kid": KEY_ID,
    },
    "signature": Base64.urlsafe_encode64(PRIVATE_KEY.sign_pss("SHA512", signing_input, salt_length: :digest, mgf1_hash: "SHA512")),
  }

  File.write(path.dirname/"#{path.basename(".json")}-jws.json", {
    "payload": data_string,
    "signatures": [
      signature,
      # Multiple signatures could be supplied here
      # should we need to roll a new key at some point
      # and provide a transition path.
    ],
  }.to_json)
end
