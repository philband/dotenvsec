class Dotenvsec < Formula
  desc "Fail-closed SOPS environment loader"
  homepage "https://github.com/philband/dotenvsec"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/philband/dotenvsec/releases/download/v#{version}/dotenvsec_#{version}_darwin_arm64.tar.gz"
      sha256 "REPLACE_FROM_RELEASE_CHECKSUMS"
    end
  end

  def install
    bin.install "dotenvsec"
    bin.install "dotenvsec-provider-sops"
  end

  test do
    assert_match "dotenvsec", shell_output("#{bin}/dotenvsec --help")
  end
end
