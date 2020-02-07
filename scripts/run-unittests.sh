#!/bin/bash

main () {
    cd "$(dirname "$(realpath "$0")")/.."
    local os=$(uname -s)
    if [ -n "$FSARCHS" ]; then
        local archs=()
        IFS=, read -ra archs <<< "$FSARCHS"
        for arch in "${archs[@]}" ; do
            run-tests "$arch"
        done
    elif [ x$os = xLinux ]; then
        local cpu=$(uname -m)
        if [ "x$cpu" == xx86_64 ]; then
            run-tests linux64
        elif [ "x$cpu" == xi686 ]; then
            run-tests linux32
        else
            echo "$0: Unknown CPU: $cpu" >&2
            exit 1
        fi
    elif [ "x$os" = xDarwin ]; then
        run-tests darwin
    else
        echo "$0: Unknown OS architecture: $os" >&2
        exit 1
    fi
}

realpath () {
    # reimplementation of "readlink -fv" for OSX
    python -c "import os.path, sys; print os.path.realpath(sys.argv[1])" "$1"
}

run-tests () {
    local arch=$1
    echo &&
    echo Start Tests on $arch &&
    echo &&
    rm -rf stage/$arch/test/log &&
    rm -rf stage/$arch/test/gcov &&
    mkdir -p stage/$arch/test/gcov &&
    rm -f stage/$arch/test/lock &&
    FSCCFLAGS="-fprofile-arcs -ftest-coverage -O0" \
    FSLINKFLAGS="-fprofile-arcs" \
        ${SCONS:-scons} builddir=test &&
    stage/$arch/test/test/fstracetest &&
    test-coverage $arch
}

test-coverage () {
    local arch=$1
    echo &&
    echo Test Coverage &&
    echo ============= &&
    echo &&
    find src -name \*.c |
    while read src; do
        ${GCOV:-gcov} -p -o "stage/$arch/test/$(dirname "$src")" "$src" || exit
    done >stage/$arch/test/gcov/gcov.out 2>stage/$arch/test/gcov/gcov.err &&
    pretty-print-out <stage/$arch/test/gcov/gcov.out &&
    pretty-print-err <stage/$arch/test/gcov/gcov.err &&
    mv *.gcov stage/$arch/test/gcov/ &&
    echo
}

pretty-print-out () {
    while read line1; do
        read line2
        read line3
        read line4
        f=$(sed "s/^File .\\([^']*\\)'$/\\1/" <<<"$line1")
        if [[ "$f" =~ \.h$ ]]; then
            continue
        fi
        case "$line2" in
            "No executable lines")
                ;;
            "Lines executed:"*)
                p=$(sed 's/Lines executed:\([0-9.]*\)% .*$/\1/' <<<"$line2")
                printf "%6s%% %s\n" "$p" "$f"
                ;;
        esac
    done
}

pretty-print-err () {
    grep 'gcda:cannot open data file' |
    sed 's!^stage/[^/]*/test/\([^:]*\).gcda:cannot open data file.*!  0.00% \1.c!'
}

main
