#!/bin/sh
# build.sh VERSION ARCH BINARY OUTDIR builds the Debian package of limen
# from a binary already built for ARCH (amd64, arm64). VERSION may carry
# the tag's leading v. Used by the release workflow; needs dpkg-deb.
set -eu

if [ $# -ne 4 ]; then
    echo "usage: $0 VERSION ARCH BINARY OUTDIR" >&2
    exit 2
fi
version=${1#v}
arch=$2
bin=$3
out=$4

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
chmod 0755 "$root"

install -D -m 0755 "$bin" "$root/usr/sbin/limen"
install -D -m 0644 "$repo/internal/bootstrap/limen.service" "$root/usr/lib/systemd/system/limen.service"
install -D -m 0644 "$repo/internal/bootstrap/skel/etc/logrotate.d/limen" "$root/etc/logrotate.d/limen"
install -D -m 0644 "$repo/README.md" "$root/usr/share/doc/limen/README.md"
install -D -m 0644 "$repo/CHANGELOG.md" "$root/usr/share/doc/limen/CHANGELOG.md"
install -D -m 0644 "$repo/LICENSE" "$root/usr/share/doc/limen/copyright"

install -d "$root/DEBIAN"
for script in postinst prerm postrm; do
    install -m 0755 "$here/$script" "$root/DEBIAN/$script"
done
echo /etc/logrotate.d/limen >"$root/DEBIAN/conffiles"
size=$(du -sk "$root" | cut -f1)
sed -e "s/@VERSION@/$version/" -e "s/@ARCH@/$arch/" -e "s/@SIZE@/$size/" \
    "$here/control" >"$root/DEBIAN/control"

mkdir -p "$out"
deb="$out/limen_${version}_${arch}.deb"
dpkg-deb --root-owner-group -Zxz --build "$root" "$deb" >/dev/null
echo "$deb"
