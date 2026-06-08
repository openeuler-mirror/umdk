"""Local libummu repository overlay for URMA Bazel builds."""

def _libummu_local_repository_impl(repository_ctx):
    build_file = repository_ctx.path(repository_ctx.attr.build_file)
    workspace_dir = build_file.dirname.dirname
    src = repository_ctx.path(str(workspace_dir) + "/" + repository_ctx.attr.path)

    if not src.exists:
        fail("libummu source path does not exist: {}".format(src))
    if not build_file.exists:
        fail("libummu BUILD overlay does not exist: {}".format(build_file))

    repository_ctx.file("WORKSPACE", 'workspace(name = "{}")\n'.format(repository_ctx.name))
    repository_ctx.symlink(build_file, "BUILD.bazel")

    result = repository_ctx.execute([
        "bash",
        "-c",
        "cd \"$1\" && find . -mindepth 1 -maxdepth 1 "
        + "! -name .git ! -name BUILD ! -name BUILD.bazel ! -name WORKSPACE -printf '%P\\n'",
        "find-libummu-files",
        str(src),
    ])
    if result.return_code != 0:
        fail("failed to enumerate libummu source files: {}".format(result.stderr))

    for rel in result.stdout.splitlines():
        if rel:
            repository_ctx.symlink(str(src) + "/" + rel, rel)

libummu_local_repository = repository_rule(
    implementation = _libummu_local_repository_impl,
    attrs = {
        "build_file": attr.label(allow_single_file = True, mandatory = True),
        "path": attr.string(mandatory = True),
    },
    local = True,
)
