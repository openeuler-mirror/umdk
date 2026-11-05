# deep_ep device headers

Device-side headers shared by the `cam_deepep_*` operators. They provide the
Ascend record layouts and the UB JFS/JFC queue helpers.

The interface follows the DeepEP device-header layout
([deepseek-ai/DeepEP](https://github.com/deepseek-ai/DeepEP), MIT) so the CAM
kernels keep the same record semantics as the reference implementation. The
Ascend port is part of CAM and is licensed under MIT; see the SPDX header of
each file.

`utils/op_kernel/*` is copied into every generated CAM operator project, so a
kernel translation unit can include `<deep_ep/...>` without an external
DeepEP checkout.

These headers are regular CAM sources; edit them here.
