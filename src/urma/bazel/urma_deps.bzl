"""Versioned external dependency configuration for URMA Bazel builds."""

LIBUMMU_REMOTE = "https://gitcode.com/openeuler/libummu.git"
LIBUMMU_COMMIT = "d28a6b1096f1214f9d3185b41537cde06d5e6233"
LIBUMMU_VERSION = "1.0.3"
LIBUMMU_ABI_VERSION = "1"

# Keep runtime libraries explicit so libummu has the same direct dependencies
# when built through Bazel, without hard-coding an architecture-specific loader.
LIBUMMU_RUNTIME_LINKOPTS = [
    "-Wl,--no-as-needed",
    "-lstdc++",
    "-lm",
    "-lgcc_s",
    "-lc",
    "-Wl,--as-needed",
]
