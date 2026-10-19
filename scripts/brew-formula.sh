#!/usr/bin/env bash
# Usage: scripts/brew-formula.sh VERSION CHECKSUMS_FILE > renewhunt.rb
# Renders the Homebrew formula for a renewhunt release from GoReleaser's checksums.txt.
set -euo pipefail
v="${1#v}"; sums="$2"
sha() { awk -v f="renewhunt_${v}_$1.tar.gz" '$2==f{print $1}' "$sums" | grep -E '^[0-9a-f]{64}$'; }
base="https://github.com/Blackman99/renewhunt/releases/download/v${v}"
cat <<RB
class Renewhunt < Formula
  desc "Hunt ACME renewal windows that break with 64-day certificates"
  homepage "https://blackman99.github.io/renewhunt/"
  version "${v}"
  license "MIT"

  on_macos do
    on_arm do
      url "${base}/renewhunt_${v}_darwin_arm64.tar.gz"
      sha256 "$(sha darwin_arm64)"
    end
    on_intel do
      url "${base}/renewhunt_${v}_darwin_amd64.tar.gz"
      sha256 "$(sha darwin_amd64)"
    end
  end

  on_linux do
    on_arm do
      url "${base}/renewhunt_${v}_linux_arm64.tar.gz"
      sha256 "$(sha linux_arm64)"
    end
    on_intel do
      url "${base}/renewhunt_${v}_linux_amd64.tar.gz"
      sha256 "$(sha linux_amd64)"
    end
  end

  def install
    bin.install "renewhunt"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/renewhunt -version")
  end
end
RB
