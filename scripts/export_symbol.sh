#!/bin/sh
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_dir="$(cd "$script_dir/.." && pwd)"
symbol_dir="$repo_dir/symbol"
out_dir="$repo_dir/symbol-offsets"

# Auto-discover .so files in symbol/ if no args given
if [ "$#" -eq 0 ]; then
    set -- "$symbol_dir"/*.so*
fi

mkdir -p "$out_dir"

found=0
for elf in "$@"; do
    if [ ! -f "$elf" ]; then
        echo "WARNING: not found, skipping: $elf" >&2
        continue
    fi

    base="$(basename "$elf")"
    raw_out="$out_dir/${base}.offsets.tsv"
    demangled_out="$out_dir/${base}.offsets.demangled.tsv"

    echo "Processing: $base"

    # Generate raw (mangled) offsets table
    perl - "$elf" > "$raw_out" <<'PERL'
use strict;
use warnings;

my $elf = shift @ARGV or die "missing elf\n";

# Parse section headers: index, addr, offset
open my $sh, '-|', 'readelf', '-SW', $elf or die "readelf -SW: $!\n";
my (%sec_addr, %sec_off);
while (<$sh>) {
    if (/^\s*\[\s*(\d+)\]\s+(\S+)\s+\S+\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)/) {
        $sec_addr{$1} = hex($3);
        $sec_off{$1}  = hex($4);
    }
}
close $sh;

# Parse symbols, compute file offset
open my $sy, '-|', 'readelf', '-WsW', $elf or die "readelf -WsW: $!\n";
print join("\t", qw(FILE_OFFSET VALUE SIZE TYPE BIND NDX NAME)), "\n";
while (<$sy>) {
    next unless /^\s*\d+:\s+([0-9A-Fa-f]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+\S+\s+(\S+)\s+(.+)$/;
    my ($value_hex, $size, $type, $bind, $ndx, $name) = ($1, $2, $3, $4, $5, $6);
    next unless $type eq 'FUNC';
    next unless $ndx =~ /^\d+$/;
    next unless exists $sec_addr{$ndx};

    chomp $name;
    my $value = hex($value_hex);
    my $file_offset = $value - $sec_addr{$ndx} + $sec_off{$ndx};

    printf "0x%016x\t0x%016x\t%s\t%s\t%s\t%s\t%s\n",
        $file_offset, $value, $size, $type, $bind, $ndx, $name;
}
close $sy;
PERL

    # Generate demangled version: demangle only the NAME column (7th field)
    if command -v c++filt >/dev/null 2>&1; then
        tmp_raw="/tmp/$$_raw_cols"
        tmp_dem="/tmp/$$_dem_names"
        # Extract first 6 columns (FILE_OFFSET through NDX)
        tail -n +2 "$raw_out" | cut -f1-6 > "$tmp_raw"
        # Extract NAME column and demangle
        tail -n +2 "$raw_out" | cut -f7 | c++filt -n > "$tmp_dem"
        # Reassemble: header + first 6 cols + demangled name
        head -1 "$raw_out" > "$demangled_out"
        paste "$tmp_raw" "$tmp_dem" >> "$demangled_out"
        rm -f "$tmp_raw" "$tmp_dem"
    else
        cp "$raw_out" "$demangled_out"
        echo "WARNING: c++filt not found, demangled output same as raw" >&2
    fi

    count=$(wc -l < "$raw_out")
    echo "  -> $count symbols"
    found=1
done

if [ "$found" -eq 1 ]; then
    echo ""
    echo "Done. Offset tables written to: $out_dir"
    ls -lh "$out_dir"/*.tsv 2>/dev/null
else
    echo "ERROR: No ELF files processed" >&2
    exit 1
fi
