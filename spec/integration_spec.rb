# frozen_string_literal: true

require "fileutils"
require "open3"
require "shellwords"
require "tmpdir"

RSpec.describe "ssh-tresor CLI integration" do
  around do |example|
    @tmpdir = File.realpath(Dir.mktmpdir("ssh-tresor-ruby-", "/private/tmp"))
    old_auth_sock = ENV["SSH_AUTH_SOCK"]
    old_agent_pid = ENV["SSH_AGENT_PID"]

    agent_socket = File.join(@tmpdir, "agent.sock")
    stdout, status = Open3.capture2("ssh-agent", "-a", agent_socket, "-s")
    expect(status).to be_success

    ENV["SSH_AUTH_SOCK"] = stdout[/SSH_AUTH_SOCK=([^;]+)/, 1]
    ENV["SSH_AGENT_PID"] = stdout[/SSH_AGENT_PID=([^;]+)/, 1]

    begin
      example.run
    ensure
      system("ssh-agent", "-k", out: File::NULL, err: File::NULL) if ENV["SSH_AGENT_PID"]
      ENV["SSH_AUTH_SOCK"] = old_auth_sock
      ENV["SSH_AGENT_PID"] = old_agent_pid
      FileUtils.rm_rf(@tmpdir) if @tmpdir
    end
  end

  before do
    @key1 = File.join(@tmpdir, "key1")
    @key2 = File.join(@tmpdir, "key2")

    system("ssh-keygen", "-t", "ed25519", "-f", @key1, "-N", "", "-C", "test-key-1", "-q", exception: true)
    system("ssh-keygen", "-t", "ed25519", "-f", @key2, "-N", "", "-C", "test-key-2", "-q", exception: true)
    system("ssh-add", @key1, exception: true, out: File::NULL, err: File::NULL)
    system("ssh-add", @key2, exception: true, out: File::NULL, err: File::NULL)
  end

  it "lists keys loaded in the SSH agent" do
    output = run_cli!("list-keys")

    expect(output).to include("test-key-1")
    expect(output).to include("test-key-2")
  end

  it "encrypts and decrypts through the CLI" do
    encrypted = run_cli!("encrypt", stdin_data: "secret")
    decrypted = run_cli!("decrypt", stdin_data: encrypted)

    expect(decrypted).to eq("secret")
  end

  it "supports armored output" do
    encrypted = run_cli!("encrypt", "-a", stdin_data: "secret")

    expect(encrypted).to include("BEGIN SSH TRESOR")
    expect(run_cli!("decrypt", stdin_data: encrypted)).to eq("secret")
  end

  it "adds and removes key slots" do
    key1_fp = fingerprint(@key1)
    key2_fp = fingerprint(@key2)

    encrypted = run_cli!("encrypt", "-k", key1_fp, stdin_data: "secret")
    added = run_cli!("add-key", "-k", key2_fp, stdin_data: encrypted)

    expect(run_cli!("list-slots", stdin_data: added)).to include("2 key slot")

    removed = run_cli!("remove-key", "-k", key1_fp, stdin_data: added)

    expect(run_cli!("list-slots", stdin_data: removed)).to include("1 key slot")
    expect(run_cli!("decrypt", stdin_data: removed)).to eq("secret")
  end

  def run_cli!(*args, stdin_data: "")
    command = [Gem.ruby, File.expand_path("../exe/ssh-tresor", __dir__), *args]
    stdout, stderr, status = Open3.capture3(*command, stdin_data: stdin_data)
    expect(status).to be_success, "command failed: #{command.shelljoin}\nstdout:\n#{stdout}\nstderr:\n#{stderr}"
    stdout
  end

  def fingerprint(path)
    stdout, status = Open3.capture2("ssh-keygen", "-lf", "#{path}.pub")
    expect(status).to be_success
    stdout.split[1]
  end
end
