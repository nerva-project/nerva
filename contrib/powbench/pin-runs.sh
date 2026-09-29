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
# binary that disagreed by 16%.
#
# Pinning can fail silently. Android confines apps to a cpuset, so an affinity
# request may be rejected or overridden, and a pinned run that was not really
# pinned is worse than none: the numbers look like core-type measurements and
# are not. So this checks that the affinity took before running, and the
# benchmark reports the core it actually ran on. If those disagree, ignore the
# numbers rather than reading them.
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

# Output goes to a pipe or a file as often as to a terminal, and the benchmark
# cannot detect the width through those, so say it outright.
V8BENCH_NARROW=${V8BENCH_NARROW:-1}
export V8BENCH_NARROW

# Group cores by max frequency, keeping the lowest-numbered core of each group.
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
echo "this machine allows: $(grep Cpus_allowed_list /proc/self/status 2>/dev/null | awk '{print $2}')"
echo

first=1
for entry in $cores; do
    n=${entry%:*}
    f=${entry#*:}

    # Confirm the pin takes before spending three minutes on a number that would
    # be attributed to the wrong core.
    got=$(taskset -c "$n" sh -c 'grep Cpus_allowed_list /proc/self/status' 2>/dev/null | awk '{print $2}')
    if [ "$got" != "$n" ]; then
        echo "=== cpu$n: SKIPPED, pin did not take (allowed: ${got:-none}) ==="
        echo
        continue
    fi

    [ $first -eq 1 ] || { echo "cooling down 60 s"; sleep 60; }
    first=0
    echo "=== cpu$n (max ${f} kHz) ==="
    # Thread count 0 skips the scaling pass, which measures nothing on one core.
    # No grep: the narrow layout is short enough to read whole, and filtering
    # here is what dropped the hash-rate tables last time.
    taskset -c "$n" "$BENCH" 2000 600 0
    echo
done

echo "Send the whole output. One block per core type."
