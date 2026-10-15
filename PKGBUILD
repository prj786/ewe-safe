# Maintainer: scubba
#
# ewe-safe — Safe, ewe's password manager (RFC-008): the daemon that holds the
# unlocked safe (ewe-safed), the CLI (ewe-safe) and the window (ewe-safe-app).
# Tauri v2 has no pacman bundler, so this PKGBUILD is the packaging, like
# ewe-sync's. The release workflow rewrites _tag/pkgver and attaches the
# built package for ewe-repo's publish.

pkgname=ewe-safe
# The git TAG and the pacman pkgver are different strings (a tag may carry
# -alpha/-beta, an Arch pkgver may not hold a hyphen; 0.1.0alpha sorts below
# 0.1.0 under vercmp). The archive is addressed by the TAG, so the source URL
# and the directory follow _tag, never pkgver.
_tag=v0.2.0-beta
pkgver=0.2.0beta
pkgrel=1
pkgdesc="Safe — ewe's password manager: one KeePass file in a place you choose, filled with Super+P"
arch=('x86_64' 'aarch64')
url="https://github.com/prj786/ewe-safe"
license=('MIT')
depends=(
  'gcc-libs'
  'glibc'
  'webkit2gtk-4.1'   # the window
  'gtk3'
  'wl-clipboard'     # copy: the daemon runs wl-copy, past the clipboard history
)
optdepends=(
  'ewe: the desktop — ewe-conf ([safe] settings), ewe-cloud (your Nextcloud), the Super+P picker (plugin ewe.passwords)'
  '1password-cli: import straight from the 1Password app (op)'
  'kitty: the unlock prompt when the window is not installed'
)
makedepends=('rust' 'cargo' 'nodejs' 'npm')
install=ewe-safe.install
# Arch's makepkg LTO breaks linking the `ring` crate's assembly (see Komble's
# PKGBUILD); Rust-level LTO stays on in Cargo.toml.
options=(!lto !debug)

source=("$pkgname-$pkgver.tar.gz::$url/archive/refs/tags/$_tag.tar.gz")
sha256sums=('SKIP')

build() {
  cd "$srcdir/$pkgname-${_tag#v}"
  # the daemon and the CLI (the root workspace)
  cargo build --release --locked
  # the window: through the Tauri CLI, never a bare cargo build (tauri-build
  # decides dev-vs-production at compile time). --no-bundle: this is the
  # packaging.
  cd app
  npm ci
  npm run tauri build -- --no-bundle
}

check() {
  cd "$srcdir/$pkgname-${_tag#v}"
  # the fidelity corpus is third-party files fetched by CI only; its tests
  # skip without it
  cargo test --release --locked
}

package() {
  cd "$srcdir/$pkgname-${_tag#v}"
  install -Dm755 target/release/ewe-safed "$pkgdir/usr/bin/ewe-safed"
  install -Dm755 target/release/ewe-safe "$pkgdir/usr/bin/ewe-safe"
  install -Dm755 app/src-tauri/target/release/ewe-safe-app "$pkgdir/usr/bin/ewe-safe-app"

  install -Dm644 packaging/ewe-safe.socket "$pkgdir/usr/lib/systemd/user/ewe-safe.socket"
  install -Dm644 packaging/ewe-safe.service "$pkgdir/usr/lib/systemd/user/ewe-safe.service"

  install -Dm644 packaging/ewe-safe.desktop "$pkgdir/usr/share/applications/ewe-safe.desktop"
  for s in 32 64 128 256; do
    install -Dm644 "app/src-tauri/icons/${s}x${s}.png" \
      "$pkgdir/usr/share/icons/hicolor/${s}x${s}/apps/ewe-safe.png"
  done
  install -Dm644 packaging/ewe-safe.svg "$pkgdir/usr/share/icons/hicolor/scalable/apps/ewe-safe.svg"

  install -Dm644 docs/PROTOCOL.md "$pkgdir/usr/share/doc/$pkgname/PROTOCOL.md"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
  install -Dm644 NOTICE "$pkgdir/usr/share/licenses/$pkgname/NOTICE"
}
