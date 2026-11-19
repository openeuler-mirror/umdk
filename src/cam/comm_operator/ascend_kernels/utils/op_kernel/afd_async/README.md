# afd_async device headers

Device-side headers shared by the `afd_async_*_*` operators. They provide the
Ascend record layouts and the UB JFS/JFC queue helpers.

The native device helpers and EP fragments in these headers trace back to
[DeepEP-Ascend at `3b25377d`][ascend-base]. The individual headers record
the source files and describe the CAM adaptations.

The AFD implementations and wire layouts also have a matching precursor in
the [AFD fork at `19fe6b7`][afd-base]. The F-local transaction layout traces
to the [transaction prototype at `8757a68d`][txn-base]. The fork references
identify the AFD implementations and layouts separately from the official
DeepEP-Ascend source.

The [third-party notice][third-party-notice] records the proposed MIT text
from [DeepEP-Ascend PR #25][mit-pr] for review. The proposed text is pending
confirmation for the referenced version.

`utils/op_kernel/*` is copied into every generated CAM operator project, so a
kernel translation unit can include `<afd_async/...>` without an external
DeepEP checkout.

These headers are regular CAM sources; edit them here.

[ascend-base]: https://github.com/deepseek-ai/DeepEP-Ascend/tree/3b25377d04b24fc6154698ded78a2bcb2c59afff
[afd-base]: https://github.com/puxiaokun3721/DeepEP-Ascend/tree/19fe6b7a1055d9bf7709f6a46acc48a35e98e0b9
[txn-base]: https://github.com/puxiaokun3721/DeepEP-Ascend/tree/8757a68d5f258c302ab5146df62119b70ea80b6d
[third-party-notice]: ../../../../../../../LICENSES/Third_Party_Open_Source_Software_Notice.txt
[mit-pr]: https://github.com/deepseek-ai/DeepEP-Ascend/pull/25
