"""Versioned external dependency configuration for URMA Bazel builds."""

LIBUMMU_REMOTE = "https://gitcode.com/openeuler/libummu.git"
LIBUMMU_COMMIT = "70de020f776d8def0d8a8941cc7cbc5928d66c10"
LIBUMMU_VERSION = "1.0.5"
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
