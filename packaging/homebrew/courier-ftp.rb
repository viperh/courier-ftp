# Homebrew formula for the `viperh/homebrew-courier-ftp` tap.
#
#   brew install viperh/courier-ftp/courier-ftp
#
# It installs the prebuilt release archives (macOS universal, Linux static musl).
# `scripts/update-packaging.py` sets the version and checksums on every release and the
# release workflow pushes the result to the tap repository as Formula/courier-ftp.rb.
class CourierFtp < Formula
  desc "Terminal FTP, FTPS and SFTP client with an encrypted site vault"
  homepage "https://github.com/viperh/courier-ftp"
  version "0.1.0"
  license "MIT"

  on_macos do
    url "https://github.com/viperh/courier-ftp/releases/download/v0.1.0/courier-ftp-0.1.0-macos-universal.tar.gz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  on_linux do
    on_intel do
      url "https://github.com/viperh/courier-ftp/releases/download/v0.1.0/courier-ftp-0.1.0-linux-x86_64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_arm do
      url "https://github.com/viperh/courier-ftp/releases/download/v0.1.0/courier-ftp-0.1.0-linux-aarch64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "courier-ftp"
    man1.install "man/courier-ftp.1"
    bash_completion.install "completions/courier-ftp.bash" => "courier-ftp"
    zsh_completion.install "completions/_courier-ftp"
    fish_completion.install "completions/courier-ftp.fish"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/courier-ftp --version")
  end
end
