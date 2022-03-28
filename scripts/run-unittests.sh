#!/usr/bin/env bash

main () {
    cd "$(dirname "$(realpath "$0")")/.."
    if [ -n "$FSARCHS" ]; then
        local archs=()
        IFS=, read -ra archs <<< "$FSARCHS"
        for arch in "${archs[@]}" ; do
            run-tests "$arch" "$@"
        done
    else
        local os=$(uname -m -s)
        case $os in
            "Darwin arm64")
                run-tests darwin "$@";;
            "Darwin x86_64")
                run-tests darwin "$@";;
            "FreeBSD amd64")
                run-tests freebsd_amd64 "$@";;
            "Linux i686")
                run-tests linux32 "$@";;
            "Linux x86_64")
                run-tests linux64 "$@";;
            "Linux aarch64")
                run-tests linux_arm64 "$@";;
            "OpenBSD amd64")
                run-tests openbsd_amd64 "$@";;
            *)
                echo "$0: Unknown OS architecture: $os" >&2
                exit 1
        esac
    fi
}

realpath () {
    if [ -x /bin/realpath ]; then
        /bin/realpath "$@"
    else
        # reimplementation of "readlink -fv" for OSX
        python -c "import os.path, sys; print(os.path.realpath(sys.argv[1]))" \
               "$1"
    fi
}

run-tests () {
    local arch=$1
    shift &&
    echo &&
    echo Start Tests on $arch &&
    echo &&
    rm -rf stage/$arch/workdir &&
    mkdir stage/$arch/workdir &&
    if [ "$arch" = openbsd_amd64 ]; then
        stage/$arch/build/test/fstracetest stage/$arch/workdir
        return
    fi
    # The generated .gcda and .gcno files are not rewritten on
    # rebuild, which leads to errors and/or bad stats. I don't know a
    # better way around the problem but to get rid of the whole target
    # directory each time:
    rm -rf stage/$arch/test &&
    mkdir -p stage/$arch/test/gcov &&
    if ! FSCCFLAGS="-fprofile-arcs -ftest-coverage -O0" \
         FSLINKFLAGS="-fprofile-arcs" \
         ${SCONS:-scons} builddir=test "$@"; then
        echo "Did you forget to specify prefix=<prefix> to $0?" >&2
        false
    fi &&
    stage/$arch/test/test/fstracetest stage/$arch/workdir &&
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

main "$@"
