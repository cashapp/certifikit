# Homebrew formula to install onto a local development mac
# TODO publish in a square github homebrew tap like https://github.com/yschimke/homebrew-tap
# TODO deploy a signed published tar file linked to a release
# https://www.rubydoc.info/github/Homebrew/brew/Formula
class Cft < Formula
  desc "Certifikit CLI"
  homepage "https://github.com/cashapp/certifikit"
  version "0.1"
  url "file://#{Dir.pwd}/build/cft.tar"

  depends_on :java

  def install
    libexec.install Dir["*"]
    bin.install_symlink "#{libexec}/build/graal/cft"
    zsh_completion.install "#{libexec}/src/main/zsh/_cft"
  end
end

