# frozen_string_literal: true

RSpec.describe SshTresor::Vault do
  FakeKey = Struct.new(:fingerprint_bytes, :security_key?, keyword_init: true)

  class FakeAgent
    attr_reader :keys, :signed_data

    def initialize(keys)
      @keys = keys
      @signatures = {}
      @signed_data = []
    end

    def first_key
      keys.first
    end

    def find_key(fingerprint)
      normalized = fingerprint.delete_prefix("SHA256:")
      keys.find do |key|
        Base64.strict_encode64(key.fingerprint_bytes).delete("=").start_with?(normalized)
      end || raise(SshTresor::KeyNotFound, "Key not found: #{fingerprint}")
    end

    def list_keys
      keys
    end

    def sign(key, challenge)
      signed_data << challenge
      @signatures[[key.fingerprint_bytes, challenge]] ||= Digest::SHA256.digest(key.fingerprint_bytes + challenge)
    end
  end

  let(:key) { FakeKey.new(fingerprint_bytes: "k" * 32, security_key?: false) }
  let(:agent) { FakeAgent.new([key]) }
  let(:vault) { described_class.new(agent: agent) }

  it "encrypts and decrypts through public class calls" do
    encrypted = vault.encrypt("secret", armor: true)

    expect(encrypted).to include("BEGIN SSH TRESOR")
    expect(vault.decrypt(encrypted)).to eq("secret")
  end

  it "lists slots from encrypted content" do
    encrypted = vault.encrypt("secret")

    expect(vault.list_slots(encrypted)).to eq([key.fingerprint_bytes])
  end

  it "signs domain-separated slot challenges for new tresors" do
    encrypted = vault.encrypt("secret")
    blob = SshTresor::TresorBlob.from_bytes(encrypted)
    slot = blob.slots.first

    expect(blob.version).to eq(SshTresor::TresorBlob::VERSION)
    expect(agent.signed_data).to include(SshTresor::Crypto.slot_signing_payload(slot.challenge))
    expect(agent.signed_data).not_to include(slot.challenge)
  end

end
