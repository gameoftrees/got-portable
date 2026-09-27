#!/usr/bin/env bash

# Prepare, verify and tag a local got-portable release.
set -euo pipefail

usage()
{
	cat <<'USAGE'
Usage: mk-portable-release.sh --version VERSION [options]

  --version VERSION       Release version, e.g. 0.130 or 0.130.1 (required)
  --since TAG             Previous release tag (default: nearest release tag)
  --no-portable-changes   Use the standard no-portable-changes entry
  --output-dir DIRECTORY  Tarball and SHA256 file destination (default: repo root)
  --next-version VERSION  Also commit the next development version after tagging
  -h, --help              Show this help

Run on the portable branch with a clean index and no tracked source edits.
Untracked files are not packaged. A failed build leaves the two release edits
in place; rerun with the same version to review and retry them. Release notes
open in $VISUAL, $EDITOR, or vi. Nothing is pushed or uploaded.
USAGE
}

die()
{
	echo "mk-portable-release: $*" >&2
	exit 1
}

version=
since=
output_dir=
next_version=
no_changes=no
while [ "$#" -gt 0 ]; do
	case "$1" in
	--version|--since|--output-dir|--next-version)
		[ "$#" -ge 2 ] && [ -n "$2" ] || die "Missing value for $1"
		case "$1" in
		--version) version=$2 ;;
		--since) since=$2 ;;
		--output-dir) output_dir=$2 ;;
		--next-version) next_version=$2 ;;
		esac
		shift 2 ;;
	--no-portable-changes) no_changes=yes; shift ;;
	-h|--help) usage; exit 0 ;;
	*) die "Unknown argument: $1" ;;
	esac
done

valid_version()
{
	[[ $1 =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]
}

valid_version "$version" || die "Supply --version MAJOR.MINOR[.PATCH]"
if [ -n "$next_version" ]; then
	valid_version "$next_version" || die "Invalid next version: $next_version"
	[ "$next_version" != "$version" ] || die "Next version must differ from release"
fi

root=$(git rev-parse --show-toplevel) || die "Not in a Git checkout"
cd "$root"
[ "$(git symbolic-ref --quiet --short HEAD)" = portable ] || \
	die "Run from the portable branch"
base=$(git rev-parse HEAD)
version_file=util/got-portable-ver.sh

git diff --cached --quiet || die "The index must be clean"
git diff --quiet -- . ':!CHANGELOG' ":!$version_file" || \
	die "Tracked source files have outstanding changes"
if git show-ref --verify --quiet "refs/tags/$version"; then
	die "Tag $version already exists"
fi
if [ -n "$next_version" ] && git show-ref --verify --quiet "refs/tags/$next_version"; then
	die "Next version $next_version is already tagged"
fi

if [ -z "$since" ]; then
	since=$(git describe --tags --abbrev=0 --match '[0-9]*' HEAD) || \
		die "No previous release tag; supply --since TAG"
fi
valid_version "$since" || die "Previous tag must be a release version"
previous=$(git rev-parse --verify "refs/tags/$since^{commit}") || \
	die "No such release tag: $since"
git merge-base --is-ancestor "$previous" "$base" || \
	die "$since is not an ancestor of HEAD"

output_dir=${output_dir:-$root}
mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)
tarball="got-portable-$version.tar.gz"
for name in "$tarball" "$tarball.sha256"; do
	[ ! -e "$output_dir/$name" ] && [ ! -L "$output_dir/$name" ] || \
		die "Refusing to overwrite $output_dir/$name"
done

for cmd in git tar autoreconf make; do
	command -v "$cmd" >/dev/null || die "Required command not found: $cmd"
done
if command -v sha256sum >/dev/null; then
	checksum=sha256sum
elif command -v sha256 >/dev/null; then
	checksum=sha256
elif command -v shasum >/dev/null; then
	checksum=shasum
else
	die "Install sha256sum, sha256 or shasum to generate the checksum"
fi
jobs=${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)}
[[ $jobs =~ ^[1-9][0-9]*$ ]] || die "JOBS must be a positive integer"

work=$(mktemp -d "${TMPDIR:-/tmp}/got-portable-release.XXXXXXXX")
success=no
cleanup()
{
	if [ "$success" = yes ]; then
		rm -rf -- "$work"
	else
		echo "Release stopped. Work files and build.log (if created): $work" >&2
	fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Keep originals to detect edits made while the editor or build is running.
cp CHANGELOG "$work/original-changelog"
cp "$version_file" "$work/original-version"
heading=$(sed -n '/^# got-portable /{p;q;}' CHANGELOG)
retry=no
if [[ $heading == "# got-portable $version ("* ]]; then
	retry=yes
fi
if [ "$retry" = no ]; then
	git diff --quiet -- CHANGELOG "$version_file" || \
		die "Commit existing release-file edits before preparing a new version"
	git log --reverse --format='%s' --regexp-ignore-case --grep=portable \
		"$previous..$base" > "$work/subjects"
	# Exclude the conventional release/version bookkeeping subjects.
	awk 'tolower($0) !~ /^portable: (release [0-9]+\.[0-9]+(\.[0-9]+)?|set next version)$/ {
		print "* " $0
	}' "$work/subjects" > "$work/notes"
	if [ "$no_changes" = yes ] || [ ! -s "$work/notes" ]; then
		printf '  No -portable changes.  See GoT\047s changelog.\n' > "$work/notes"
	fi
	{
		printf '# got-portable %s (%s)\n\n' "$version" "$(date +%Y-%m-%d)"
		cat "$work/notes"
		printf '\n'
	} > "$work/entry"
	awk -v entry="$work/entry" '
		!inserted && /^# got-portable / {
			while ((getline line < entry) > 0) print line
			close(entry)
			inserted = 1
		}
		{ print }
		END { if (!inserted) exit 1 }
	' CHANGELOG > "$work/CHANGELOG" || die "Cannot find changelog insertion point"
else
	cp CHANGELOG "$work/CHANGELOG"
fi

printf 'Release %s; portable changes since %s. Review the changelog.\n' "$version" "$since"
editor=${VISUAL:-${EDITOR:-vi}}
bash -c "$editor \"\$@\"" release-editor "$work/CHANGELOG"
heading=$(sed -n '/^# got-portable /{p;q;}' "$work/CHANGELOG")
[[ $heading == "# got-portable $version ("* ]] && \
	[[ ${heading##* (} =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}\)$ ]] || \
	die "Keep the new version and date heading at the top of the changelog"
[ "$(grep -Fc "# got-portable $version (" "$work/CHANGELOG")" -eq 1 ] || \
	die "Duplicate changelog entry for $version"
awk '
	/^# got-portable / { section++; next }
	section == 1 && NF { notes = 1 }
	END { exit !notes }
' "$work/CHANGELOG" || die "Release notes are empty"

set_version()
{
	sed -e "s/^GOT_RELEASE=.*/GOT_RELEASE=$1/" \
	    -e "s/^GOT_PORTABLE_VER=.*/GOT_PORTABLE_VER=$2/" "$3" > "$4"
}
set_version yes "$version" "$version_file" "$work/version"
grep -qx 'GOT_RELEASE=yes' "$work/version" && \
	grep -Fxq "GOT_PORTABLE_VER=$version" "$work/version" || die "Invalid version script"
cmp -s CHANGELOG "$work/original-changelog" && \
	cmp -s "$version_file" "$work/original-version" || die "Release files changed during review"
cp "$work/CHANGELOG" CHANGELOG
cat "$work/version" > "$version_file"

# Build only committed source plus the exact release edits being verified.
mkdir "$work/source"
git archive "$base" | tar -x -C "$work/source"
cp CHANGELOG "$work/source/CHANGELOG"
cat "$version_file" > "$work/source/$version_file"
echo "Building and running distcheck; log: $work/build.log"
if ! (
	cd "$work/source" &&
	./autogen.sh &&
	./configure --enable-cvg &&
	make -j "$jobs" distcheck
) > "$work/build.log" 2>&1; then
	die "Build failed; see $work/build.log. Fix the problem and rerun."
fi
[ -s "$work/source/$tarball" ] || die "Build did not produce $tarball"
(
	cd "$work/source"
	case "$checksum" in
	sha256sum) sha256sum "$tarball" ;;
	sha256)
		digest=$(sha256 -q "$tarball")
		printf '%s  %s\n' "$digest" "$tarball" ;;
	shasum) shasum -a 256 "$tarball" ;;
	esac
) > "$work/$tarball.sha256"

[ "$(git symbolic-ref --quiet --short HEAD)" = portable ] && \
	[ "$(git rev-parse HEAD)" = "$base" ] || die "Branch changed during build"
git diff --cached --quiet || die "Index changed during build"
git diff --quiet -- . ':!CHANGELOG' ":!$version_file" || die "Source changed during build"
cmp -s CHANGELOG "$work/CHANGELOG" && cmp -s "$version_file" "$work/version" || \
	die "Release files changed during build"

echo "Verification passed. Creating release commit and annotated tag."
git add -- CHANGELOG "$version_file"
expected_tree=$(git write-tree)
git -c core.quotePath=false diff --cached --stat
git commit -m "portable: release $version"
release_commit=$(git rev-parse HEAD)
[ "$(git rev-parse 'HEAD^{tree}')" = "$expected_tree" ] || \
	die "Commit hooks changed the verified tree; inspect the commit before tagging"
git tag -a "$version" "$release_commit" -m "Release $version"

# Hard-link temporary destination files to avoid overwriting existing output.
# Both paths are on the destination filesystem; publication is exclusive.
for name in "$tarball" "$tarball.sha256"; do
	case "$name" in
	"$tarball") source_file="$work/source/$name" ;;
	*) source_file="$work/$name" ;;
	esac
	staged=$(mktemp "$output_dir/.got-release.XXXXXXXX")
	cp "$source_file" "$staged"
	chmod 644 "$staged"
	if ! ln "$staged" "$output_dir/$name"; then
		rm -f -- "$staged"
		die "Commit and tag created, but could not publish $name; recover it from $work"
	fi
	rm -f -- "$staged"
done

if [ -n "$next_version" ]; then
	set_version no "$next_version" "$version_file" "$work/next-version"
	cat "$work/next-version" > "$version_file"
	git add -- "$version_file"
	git commit -m 'portable: set next version'
fi
success=yes
printf '\nRelease %s: %s\nTarball: %s/%s\nChecksum: %s/%s.sha256\n' \
	"$version" "$release_commit" "$output_dir" "$tarball" "$output_dir" "$tarball"
echo 'Release is local. Push the branch/tag and publish the files when ready.'
