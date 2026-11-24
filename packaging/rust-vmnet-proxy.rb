# frozen_string_literal: true

# Formula for the alecuba16 homebrew tap. Points at the GitHub release
# tarballs produced by .github/workflows/release.yml. When the first
# tagged release exists, regenerate this file from the release sha256
# files (scripts/update-formula.sh in the tap).
class RustVmnetProxy < Formula
  desc "Rootless macOS proxy: direct SOCKS5 via bridged socket_vmnet plus supervised SSH tunnels"
  homepage "https://github.com/alecuba16/rust-vmnet-proxy"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/alecuba16/rust-vmnet-proxy/releases/download/v0.1.0/rust-vmnet-proxy-macos-aarch64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"

      def install
        bin.install "rust-vmnet-proxy"
      end
    end
    on_intel do
      url "https://github.com/alecuba16/rust-vmnet-proxy/releases/download/v0.1.0/rust-vmnet-proxy-macos-x86_64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"

      def install
        bin.install "rust-vmnet-proxy"
      end
    end
  end

  def caveats
    <<~EOS
      After install, register the launchd service:
        rust-vmnet-proxy install-mac
      Config: ~/.config/rust-vmnet-proxy/config.yaml
      Example: example/config.example.yaml in the repository.
    EOS
  end

  service do
    run [opt_bin/"rust-vmnet-proxy", "--config", "#{Dir.home}/.config/rust-vmnet-proxy/config.yaml"]
    keep_alive true
    log_path "#{Dir.home}/Library/Logs/rust-vmnet-proxy/rust-vmnet-proxy.log"
    error_log_path "#{Dir.home}/Library/Logs/rust-vmnet-proxy/rust-vmnet-proxy.log"
    environment_variables RUST_LOG: "info"
    process_type :background
  end
end