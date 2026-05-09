# ssh-tresor-ruby

`ssh-tresor` provides SSH-agent-mediated encryption at rest: secrets are
stored encrypted on disk and can be decrypted only while a matching SSH agent
signing capability is available.

The private key never leaves the SSH agent. Encryption creates a random master
key, asks the agent to sign random per-key challenges, derives slot keys with
HKDF-SHA256, and stores an AES-256-GCM encrypted master key slot for each SSH
key. Decryption works when one matching SSH key is loaded locally or forwarded
with `ssh -A`.

The live capability is agent signing, not possession of the public key. Public
key fingerprints are stored in the tresor metadata so the right slot can be
found, but the file cannot be unlocked unless the agent can sign the stored
challenge for that slot.

For a detailed cryptographic analysis of the construction, see the
[ssh-tresor-ruby white paper](white_paper/ssh_tresor_white_paper.pdf).

It is freely inspired by the [`ssh-tresor`][1] project but doesn't depend
on it.

[1]: https://github.com/haraldh/ssh-tresor

## Usage

```
gem install ssh-tresor
```

```sh
ssh-tresor list-keys
echo -n "secret" | ssh-tresor encrypt -a > secret.tresor
ssh-tresor decrypt secret.tresor
ssh-tresor list-slots secret.tresor
ssh-tresor add-key -k SHA256:abc < secret.tresor > updated.tresor
ssh-tresor remove-key -k SHA256:abc < updated.tresor > reduced.tresor
```

## Library API

```
bundle add ssh-tresor
```

Your application or other gems can depend on `ssh-tresor-ruby`
and call it directly:

```ruby
require "ssh_tresor"

vault = SshTresor::Vault.new

encrypted = vault.encrypt("secret", armor: true)
plaintext = vault.decrypt(encrypted)

updated = vault.add_key(encrypted, fingerprint: "SHA256:abc", armor: true)
slots = vault.list_slots(updated)
keys = vault.list_keys
```

The `Vault` instance connects to `SSH_AUTH_SOCK` by default. You can inject a
custom agent object for tests or alternate transports:

```ruby
vault = SshTresor::Vault.new(agent: my_agent)
```

The lower-level `SshTresor::TresorBlob` parser and `SshTresor::Tresor` module
remain available if you need direct access to parsed slots.

## Wire Format

The implementation writes and reads the `SSHTRESR` v3 format:

```text
Header:  SSHTRESR (8) + version (1) + slot_count (1)
Slot:    fingerprint (32) + challenge (32) + nonce (12) + encrypted_key (48)
Data:    nonce (12) + ciphertext including 16-byte AES-GCM auth tag
```
