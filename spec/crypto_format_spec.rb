# frozen_string_literal: true

RSpec.describe "crypto and format" do
  it "encrypts and decrypts with AES-256-GCM" do
    key = "k" * 32
    nonce = "n" * 12
    plaintext = "secret"

    ciphertext = SshTresor::Crypto.encrypt(key, nonce, plaintext)

    expect(SshTresor::Crypto.decrypt(key, nonce, ciphertext)).to eq(plaintext)
  end

  it "rejects decryption with the wrong key" do
    ciphertext = SshTresor::Crypto.encrypt("k" * 32, "n" * 12, "secret")

    expect do
      SshTresor::Crypto.decrypt("x" * 32, "n" * 12, ciphertext)
    end.to raise_error(SshTresor::DecryptionError)
  end

  it "round-trips the binary tresor format" do
    slot = SshTresor::Slot.new(
      fingerprint: "f" * 32,
      challenge: "c" * 32,
      nonce: "n" * 12,
      encrypted_key: "e" * 48
    )
    blob = SshTresor::TresorBlob.new(
      slots: [slot],
      data_nonce: "d" * 12,
      ciphertext: "payload" + ("t" * 16)
    )

    parsed = SshTresor::TresorBlob.from_bytes(blob.to_bytes)

    expect(parsed.slots.length).to eq(1)
    expect(parsed.slots.first.fingerprint).to eq(slot.fingerprint)
    expect(parsed.data_nonce).to eq(blob.data_nonce)
    expect(parsed.ciphertext).to eq(blob.ciphertext)
  end

  it "round-trips the armored tresor format" do
    slot = SshTresor::Slot.new(
      fingerprint: "f" * 32,
      challenge: "c" * 32,
      nonce: "n" * 12,
      encrypted_key: "e" * 48
    )
    blob = SshTresor::TresorBlob.new(
      slots: [slot],
      data_nonce: "d" * 12,
      ciphertext: "payload" + ("t" * 16)
    )

    parsed = SshTresor::TresorBlob.from_bytes(blob.to_armored)

    expect(parsed.to_bytes).to eq(blob.to_bytes)
  end
end

