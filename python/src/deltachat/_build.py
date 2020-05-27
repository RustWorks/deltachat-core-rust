import distutils.ccompiler
import distutils.log
import distutils.sysconfig
import tempfile
import platform
import os
import cffi
import shutil
from os.path import dirname as dn
from os.path import abspath


def ffibuilder():
    projdir = os.environ.get('DCC_RS_DEV')
    if not projdir:
        p = dn(dn(dn(dn(abspath(__file__)))))
        projdir = os.environ["DCC_RS_DEV"] = p
    target = os.environ.get('DCC_RS_TARGET', 'release')
    if projdir:
        if platform.system() == 'Darwin':
            libs = ['resolv', 'dl']
            extra_link_args = [
                    '-framework', 'CoreFoundation',
                    '-framework', 'CoreServices',
                    '-framework', 'Security',
            ]
        elif platform.system() == 'Linux':
            libs = ['rt', 'dl', 'm']
            extra_link_args = []
        else:
            raise NotImplementedError("Compilation not supported yet on Windows, can you help?")
        target_dir = os.environ.get("CARGO_TARGET_DIR")
        if target_dir is None:
            target_dir = os.path.join(projdir, 'target')
        objs = [os.path.join(target_dir, target, 'libdeltachat.a')]
        assert os.path.exists(objs[0]), objs
        incs = [os.path.join(projdir, 'deltachat-ffi')]
    else:
        libs = ['deltachat']
        objs = []
        incs = []
        extra_link_args = []
    builder = cffi.FFI()
    builder.set_source(
        'deltachat.capi',
        """
            #include <deltachat.h>
            int dc_event_has_string_data(int e)
            {
                return DC_EVENT_DATA2_IS_STRING(e);
            }
        """,
        include_dirs=incs,
        libraries=libs,
        extra_objects=objs,
        extra_link_args=extra_link_args,
    )
    builder.cdef("""
        typedef int... time_t;
        void free(void *ptr);
        extern int dc_event_has_string_data(int);
    """)
    distutils.log.set_verbosity(distutils.log.INFO)
    cc = distutils.ccompiler.new_compiler(force=True)
    distutils.sysconfig.customize_compiler(cc)
    tmpdir = tempfile.mkdtemp()
    try:
        src_name = os.path.join(tmpdir, "include.h")
        dst_name = os.path.join(tmpdir, "expanded.h")
        with open(src_name, "w") as src_fp:
            src_fp.write('#include <deltachat.h>')
        cc.preprocess(source=src_name,
                      output_file=dst_name,
                      include_dirs=incs,
                      macros=[('PY_CFFI', '1')])
        with open(dst_name, "r") as dst_fp:
            builder.cdef(dst_fp.read())
    finally:
        shutil.rmtree(tmpdir)

    return builder


if __name__ == '__main__':
    import os.path
    pkgdir = os.path.join(os.path.dirname(__file__), '..')
    builder = ffibuilder()
    builder.compile(tmpdir=pkgdir, verbose=True)
