"""Helpers to build URMA shared libraries with correct DT_NEEDED (no CMake)."""

load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

_LINK_NO_AS_NEEDED = ["-Wl,--no-as-needed"]
_LINK_AS_NEEDED = ["-Wl,--as-needed"]
_URMA_LINKLIB_DIR = "-L$(GENDIR)/linklib"

def urma_dynamic_linkopts(lib_names, extra_dirs = None, extra_libs = None):
    """Build linkopts that record peer .so files and system libs in DT_NEEDED.

    Args:
        lib_names: Base names without ``lib`` prefix, e.g. ``["urma_common", "urma"]``.
        extra_dirs: Optional extra ``-L`` directories (e.g. external libummu linklib).
        extra_libs: Extra ``-l`` flags kept inside ``--no-as-needed`` (e.g. ``-lummu``).
    """
    opts = _LINK_NO_AS_NEEDED
    if lib_names:
        opts = opts + [_URMA_LINKLIB_DIR]
    if extra_dirs:
        opts = opts + extra_dirs
    for name in lib_names:
        opts = opts + ["-l" + name]
    if extra_libs:
        opts = opts + extra_libs
    return opts + _LINK_AS_NEEDED

def urma_linklib_inputs(lib_names):
    """Return additional_linker_inputs labels for urma_dynamic_linkopts."""
    return [":" + name + "_linklib" for name in lib_names]

def urma_shared_library(
        name,
        srcs,
        hdrs = [],
        includes = [],
        copts = [],
        cxxopts = [],
        compile_deps = [],
        linkopts = [],
        dynamic_lib_names = [],
        extra_link_dirs = None,
        soname = None,
        visibility = None):
    """Emit ``{name}_internal``, ``{name}`` (.so), and ``{name}_linklib``."""
    internal = name + "_internal"
    vis = visibility if visibility != None else ["//visibility:public"]

    cc_library(
        name = internal,
        srcs = srcs,
        hdrs = hdrs,
        includes = includes,
        copts = copts,
        cxxopts = cxxopts,
        deps = compile_deps,
        linkstatic = True,
        alwayslink = True,
        visibility = vis,
    )

    shared_linkopts = linkopts
    shared_inputs = []
    soname_linkopts = []
    if soname:
        soname_linkopts = ["-Wl,-soname," + soname]

    if dynamic_lib_names:
        shared_inputs = urma_linklib_inputs(dynamic_lib_names)
        shared_linkopts = urma_dynamic_linkopts(
            dynamic_lib_names,
            extra_dirs = extra_link_dirs,
            extra_libs = soname_linkopts + linkopts,
        )
    elif linkopts:
        shared_linkopts = _LINK_NO_AS_NEEDED + soname_linkopts + linkopts + _LINK_AS_NEEDED
    elif soname_linkopts:
        shared_linkopts = soname_linkopts

    cc_binary(
        name = name,
        linkshared = True,
        deps = [":" + internal],
        additional_linker_inputs = shared_inputs,
        linkopts = shared_linkopts,
        visibility = vis,
    )

    native.genrule(
        name = name + "_linklib",
        srcs = [":" + name],
        outs = ["linklib/lib" + name + ".so"],
        cmd = "mkdir -p $(@D) && cp $(location :" + name + ") $@",
        visibility = vis,
    )

def urma_shared_library_static_dep(
        name,
        srcs,
        hdrs = [],
        includes = [],
        copts = [],
        cxxopts = [],
        static_deps = [],
        linkopts = [],
        soname = None,
        visibility = None):
    """Shared library that statically links ``static_deps`` (e.g. tpsa + urma_common)."""
    internal = name + "_internal"
    vis = visibility if visibility != None else ["//visibility:public"]

    cc_library(
        name = internal,
        srcs = srcs,
        hdrs = hdrs,
        includes = includes,
        copts = copts,
        cxxopts = cxxopts,
        deps = static_deps,
        linkstatic = True,
        alwayslink = True,
        visibility = vis,
    )

    soname_linkopts = []
    if soname:
        soname_linkopts = ["-Wl,-soname," + soname]

    static_linkopts = soname_linkopts + linkopts
    if linkopts:
        static_linkopts = _LINK_NO_AS_NEEDED + soname_linkopts + linkopts + _LINK_AS_NEEDED

    cc_binary(
        name = name,
        linkshared = True,
        deps = [":" + internal],
        linkopts = static_linkopts,
        visibility = vis,
    )

    native.genrule(
        name = name + "_linklib",
        srcs = [":" + name],
        outs = ["linklib/lib" + name + ".so"],
        cmd = "mkdir -p $(@D) && cp $(location :" + name + ") $@",
        visibility = vis,
    )
