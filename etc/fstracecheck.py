#!/usr/bin/env python

import os, sys, re, optparse, subprocess, shutil

DECL_PTN1 = re.compile(
    r"\bTRC\s*\.\s*(?P<entry>\w+)\s*=\s*fstrace_declare\s*\(\s*\w+\s*,"
    r'\s*"[^"]*"\s*,'
    r'(?P<descr>(\s*"[^"]*")+)'
    r"\s*\)"
)

DECL_PTN2 = re.compile(
    r"fstrace_specify\(&spec, &(?P<entry>\w+), name, "
    r'(?P<descr>(\s*"[^"]*")+)'
    r"\s*\)"
)

DESCR_PTN = re.compile(
    "|".join(
        [
            "%%",
            "%T",
            "%F",
            "%L",
            "%P",
            "%b",
            "%J",
            "%d",
            "%u",
            "%x",
            "%64d",
            "%64u",
            "%64x",
            "%z",
            "%f",
            "%s",
            "%S",
            "%I",
            "%A",
            "%B",
            "%e",
            "%E",
            "%p",
            "%a",
        ]
    )
)

LOG_PTN = re.compile(r"\bfstrace_log_2\s*\(\s*(TRC\s*.\s*)?(?P<entry>\w+)\b")


def main():
    parser = optparse.OptionParser(usage="Usage: %prog [ options ] C-file ...")
    parser.add_option(
        "-I", metavar="PATH", action="append", help="Add include path"
    )
    parser.add_option(
        "-D", metavar="SYMBOL=VALUE", action="append", help="Predefine symbol"
    )
    parser.add_option(
        "-m",
        metavar="MACH",
        action="store",
        help="specific machine architecture only",
    )
    parser.add_option(
        "--cc",
        metavar="PATH",
        action="store",
        default="gcc",
        help="Set the C compiler to use",
    )
    parser.add_option(
        "--cppopt",
        metavar="OPT",
        action="append",
        help="Additional option for the preprocessor",
    )
    parser.add_option(
        "--ccopt",
        metavar="OPT",
        action="append",
        help="Additional option for the C compiler and C preprocessor",
    )
    parser.add_option(
        "--cxx",
        metavar="PATH",
        action="store",
        default="g++",
        help="Set the C++ compiler to use",
    )
    parser.add_option(
        "--cxxopt",
        metavar="OPT",
        action="append",
        help="Additional option for the C++ compiler and C++ preprocessor",
    )
    options, sources = parser.parse_args()
    system, _, _, _, machine = os.uname()
    if options.m:
        if options.m == "32":
            if not do_architecture("-m32", printf32[system], options, sources):
                sys.exit(1)
        elif options.m == "64":
            if not do_architecture("-m64", printf64[system], options, sources):
                sys.exit(1)
        else:
            sys.stderr.write("fstracecheck: only -m32 and -m64 are supported\n")
            sys.exit(1)
    elif machine == "x86_64":
        if not do_architecture(
            "-m64", printf64[system], options, sources
        ) or not do_architecture("-m32", printf32[system], options, sources):
            sys.exit(1)
    elif not do_architecture("-m32", printf32[system], options, sources):
        sys.exit(1)


def create_source_infos(sources, workpath):
    def is_cpp_file(pathname):
        cpp_extensions = [".cpp", ".C", ".cc", ".cp", ".cxx", ".c++"]
        return os.path.splitext(pathname)[1] in cpp_extensions

    source_infos = []
    for i, pathname in enumerate(sources):
        source_info = {"path": pathname}
        if is_cpp_file(pathname):
            source_info["mode"] = "cxx"
            source_info["pp_file"] = os.path.join(workpath, "%s.ii" % i)
            source_info["tr_file"] = source_info["pp_file"] + ".x.ii"
            source_info["ch_file"] = source_info["pp_file"] + ".x.o"
        else:
            source_info["mode"] = "cc"
            source_info["pp_file"] = os.path.join(workpath, "%s.i" % i)
            source_info["tr_file"] = source_info["pp_file"] + ".x.i"
            source_info["ch_file"] = source_info["pp_file"] + ".x.o"
        source_infos.append(source_info)
    return source_infos


def do_architecture(archopt, printf_equivalent, options, sources):
    workpath = os.path.join("/tmp/fstracecheck.%s" % os.getpid())
    os.mkdir(workpath)
    passed = True
    try:
        source_infos = create_source_infos(sources, workpath)
        for source_info in source_infos:
            preprocess(archopt, source_info, options)

        translations = dict(
            (entry, "".join(map(printf_equivalent, directives(descr))))
            for source_info in source_infos
            for entry, descr in declarations(source_info["pp_file"])
        )
        for source_info in source_infos:
            transform(source_info, translations)
            if not check(archopt, options, source_info):
                passed = False
    finally:
        shutil.rmtree(workpath)
    return passed


def preprocess(archopt, source_info, options):
    if source_info["mode"] == "cc":
        compiler = options.cc
        user_opts = options.ccopt
    else:
        compiler = options.cxx
        user_opts = options.cxxopt
    cmd = [
        compiler,
        archopt,
        "-E",
        source_info["path"],
        "-o",
        source_info["pp_file"],
    ]
    if options.D is not None:
        for define in options.D:
            cmd.append("-D" + define)
    if options.I is not None:
        for include_path in options.I:
            cmd.append("-I" + include_path)
    if options.cppopt is not None:
        cmd.extend(options.cppopt)
    if user_opts is not None:
        cmd.extend(user_opts)
    status = subprocess.call(cmd)
    assert status == 0


def declarations(pathname):
    f_in = open(pathname)
    try:
        source = f_in.read()
    finally:
        f_in.close()
    for m in DECL_PTN1.finditer(source):
        yield m.group("entry"), m.group("descr")
    for m in DECL_PTN2.finditer(source):
        yield m.group("entry"), m.group("descr")


def directives(descr):
    return DESCR_PTN.findall(descr)


def printf64_linux(directive):
    return {
        "%b": "%d",
        "%d": "%d",
        "%u": "%u",
        "%x": "%x",
        "%64d": "%ld",
        "%64u": "%lu",
        "%64x": "%lx",
        "%z": "%zd",
        "%f": "%f",
        "%s": "%s",
        "%S": "%s%zd",
        "%I": "%p%p",
        "%J": "%p%p",
        "%A": "%p%zd",
        "%B": "%p%zd",
        "%p": "%p",
        "%E": "%d",
        "%a": "%p%u",
    }.get(directive, "")


def printf32_common(directive):
    return {
        "%b": "%d",
        "%d": "%d",
        "%u": "%u",
        "%x": "%x",
        "%64d": "%lld",
        "%64u": "%llu",
        "%64x": "%llx",
        "%z": "%zd",
        "%f": "%f",
        "%s": "%s",
        "%S": "%s%zd",
        "%I": "%p%p",
        "%J": "%p%p",
        "%A": "%p%zd",
        "%B": "%p%zd",
        "%p": "%p",
        "%E": "%d",
        "%a": "%p%u",
    }.get(directive, "")


printf64 = {
    "Darwin": printf32_common,  # sic!
    "Linux": printf64_linux,
}

printf32 = {
    "Darwin": printf32_common,
    "Linux": printf32_common,
}


def transform(source_info, translations):
    f_in = open(source_info["pp_file"])
    try:
        source = f_in.read()
    finally:
        f_in.close()
    cursor = 0
    f_out = open(source_info["tr_file"], "w")
    try:
        for m in LOG_PTN.finditer(source):
            try:
                translation = translations[m.group("entry")]
            except KeyError:
                f_out.write(source[cursor : m.end()])
                cursor = m.end()
                continue
            f_out.write(
                '%sprintf("%%s%%u%s"'
                % (source[cursor : m.start()], translation)
            )
            cursor = m.end()
        f_out.write(source[cursor:])
    finally:
        f_out.close()


def check(archopt, options, source_info):
    if source_info["mode"] == "cc":
        compiler = options.cc
        user_opts = options.ccopt
    else:
        compiler = options.cxx
        user_opts = options.cxxopt
    cmd = [
        compiler,
        archopt,
        "-Wformat",
        "-Werror",
        "-c",
        source_info["tr_file"],
        "-o",
        source_info["ch_file"],
    ]
    if user_opts is not None:
        cmd.extend(user_opts)
    return subprocess.call(cmd) == 0


if __name__ == "__main__":
    main()
