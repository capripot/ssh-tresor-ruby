# ssh-tresor-ruby

`ssh-tresor` encrypts and decrypts secrets using keys available through
`ssh-agent`.

The private key never leaves the SSH agent. Encryption creates a random master
key, asks the agent to sign random per-key challenges, derives slot keys with
HKDF-SHA256, and stores an AES-256-GCM encrypted master key slot for each SSH
key. Decryption works when one matching SSH key is loaded locally or forwarded
with `ssh -A`.

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
