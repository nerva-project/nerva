#!/bin/sh
# Measure one core of each type on a heterogeneous CPU.
#
#   sh contrib/powbench/pin-runs.sh
#
# Why this exists: on a big.LITTLE phone the scheduler moves a single-threaded
# benchmark between core types mid-run, so the "single thread" mean is a blend
# of two or three different CPUs rather than a measurement of any one of them.
# The first Pixel 7a run showed it plainly: 0.6153 ms minimum against a 2.9760
# ms maximum at 1 MB, a 4.8x range on one machine, and two runs of the same
# binary that disagreed by 16%. Pinning separates the cores so each number means
# something on its own.
#
# Reads the per-core maximum frequency, groups cores by it, and runs the
# benchmark pinned to the lowest-numbered core of each distinct group. On a
# uniform CPU that is one group and one run, which is the correct behaviour
# there too.
set -e

cd "$(dirname "$0")/../.." || exit 1

BENCH=${BENCH:-./v8bench}
if [ ! -x "$BENCH" ]; then
    echo "no $BENCH; build it first:" >&2
    echo "  sh contrib/powbench/build-v8bench.sh" >&2
    exit 1
fi

if ! command -v taskset >/dev/null 2>&1; then
    echo "taskset not found. On Termux: pkg install util-linux" >&2
    exit 1
fi

# Group cores by max frequency. If the frequency nodes are unreadable, which
# SELinux does on some Android builds, fall back to every core so the run still
# produces something rather than nothing.
seen=""
cores=""
for d in /sys/devices/system/cpu/cpu[0-9]*; do
    n=${d#/sys/devices/system/cpu/cpu}
    f=$(cat "$d/cpufreq/cpuinfo_max_freq" 2>/dev/null || echo "")
    [ -z "$f" ] && continue
    case " $seen " in
        *" $f "*) ;;
        *) seen="$seen $f"; cores="$cores $n:$f" ;;
    esac
done

if [ -z "$cores" ]; then
    echo "could not read per-core frequencies; running every core instead"
    for d in /sys/devices/system/cpu/cpu[0-9]*; do
        n=${d#/sys/devices/system/cpu/cpu}
        cores="$cores $n:?"
    done
fi

echo "core groups:$cores"
echo

first=1
for entry in $cores; do
    n=${entry%:*}
    f=${entry#*:}
    [ $first -eq 1 ] || { echo "cooling down 60 s"; sleep 60; }
    first=0
    echo "=== cpu$n (max ${f} kHz) ==="
    taskset -c "$n" "$BENCH" 2000 600 1 2>&1 |
        grep -E "^CPU:|AES path|SWEEP|1MB=|4MB=|v8 vs v5|negative|PASS"
    echo
done

echo "Send the whole output. One block per core type."
