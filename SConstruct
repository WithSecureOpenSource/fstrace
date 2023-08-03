import os
import fsenv

DIRECTORIES = [
    'src',
    'test',
    'components/fstrace' ]

TARGET_DEFINES = {
    'freebsd_amd64': [],
    'linux32': ['_FILE_OFFSET_BITS=64'],
    'linux64': [],
    'linux_arm64': [],
    'openbsd_amd64': [],
    'darwin': []
}

TARGET_FLAGS = {
    'freebsd_amd64': '',
    'linux32': '-m32 ',
    'linux64': '',
    'linux_arm64': '',
    'openbsd_amd64': '',
    'darwin': '-mmacosx-version-min=10.13 '
}

def construct():
    ccflags = '-g -O2 -Wall -Werror'
    prefix = ARGUMENTS.get('prefix', '/usr/local')
    for target_arch in fsenv.target_architectures():
        arch_env = Environment(
            NAME='fstrace',
            ARCH=target_arch,
            PREFIX=prefix,
            PKG_CONFIG_LIBS=['fsdyn', 'rotatable'],
            CCFLAGS=TARGET_FLAGS[target_arch] + ccflags,
            CPPDEFINES=TARGET_DEFINES[target_arch],
            LINKFLAGS=TARGET_FLAGS[target_arch],
            tools=['default', 'textfile', 'fscomp', 'scons_compilation_db'])
        fsenv.consider_environment_variables(arch_env)
        build_dir = os.path.join(
            fsenv.STAGE,
            target_arch,
            ARGUMENTS.get('builddir', 'build'))
        arch_env.CompilationDB(
            os.path.join(build_dir, "compile_commands.json"))
        for directory in DIRECTORIES:
            env = arch_env.Clone()
            env.SetCompilationDB(arch_env.GetCompilationDB())
            SConscript(dirs=directory,
                       exports=['env'],
                       duplicate=False,
                       variant_dir=os.path.join(build_dir, directory))
        Clean('.', build_dir)

if __name__ == 'SCons.Script':
    construct()
