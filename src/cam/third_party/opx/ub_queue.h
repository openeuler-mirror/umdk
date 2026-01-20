/*
* Copyright (c) 2025 Huawei Technologies Co., Ltd.
* This file is a part of the CANN Open Software.
* Licensed under CANN Open Software License Agreement Version 1.0 (the "License").
* Please refer to the License for details. You may not use this file except in compliance with the License.
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
* INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
* See LICENSE in the root of the software repository for the full text of the License.
*/

#pragma once

#include "kernel_operator.h"
#include "opx/type_traits.h"

namespace opx
{

template <auto src, auto dst>
OPX_DEVICE constexpr
AscendC::HardEvent GetHardEventByPipe()
{
    AscendC::HardEvent ret = AscendC::HardEvent::MAX;
    if (src == PIPE_MTE2 && dst == PIPE_MTE1) {
        ret = AscendC::HardEvent::MTE2_MTE1;
    }
    else if (src == PIPE_MTE1 && dst == PIPE_MTE2) {
        ret = AscendC::HardEvent::MTE1_MTE2;
    }
    else if (src == PIPE_MTE1 && dst == PIPE_M) {
        ret = AscendC::HardEvent::MTE1_M;
    }
    else if (src == PIPE_M && dst == PIPE_MTE1) {
        ret = AscendC::HardEvent::M_MTE1;
    }
    else if (src == PIPE_MTE2 && dst == PIPE_V) {
        ret = AscendC::HardEvent::MTE2_V;
    }
    else if (src == PIPE_V && dst == PIPE_MTE2) {
        ret = AscendC::HardEvent::V_MTE2;
    }
    else if (src == PIPE_MTE3 && dst == PIPE_V) {
        ret = AscendC::HardEvent::MTE3_V;
    }
    else if (src == PIPE_V && dst == PIPE_MTE3) {
        ret = AscendC::HardEvent::V_MTE3;
    }
    else if (src == PIPE_M && dst == PIPE_V) {
        ret = AscendC::HardEvent::M_V;
    }
    else if (src == PIPE_V && dst == PIPE_M) {
        ret = AscendC::HardEvent::V_M;
    }
    else if (src == PIPE_V && dst == PIPE_V) {
        ret = AscendC::HardEvent::V_V;
    }
    else if (src == PIPE_MTE3 && dst == PIPE_MTE1) {
        ret = AscendC::HardEvent::MTE3_MTE1;
    }
    else if (src == PIPE_MTE1 && dst == PIPE_MTE3) {
        ret = AscendC::HardEvent::MTE1_MTE3;
    }
    else if (src == PIPE_MTE1 && dst == PIPE_V) {
        ret = AscendC::HardEvent::MTE1_V;
    }
    else if (src == PIPE_MTE2 && dst == PIPE_M) {
        ret = AscendC::HardEvent::MTE2_M;
    }
    else if (src == PIPE_M && dst == PIPE_MTE2) {
        ret = AscendC::HardEvent::M_MTE2;
    }
    else if (src == PIPE_V && dst == PIPE_MTE1) {
        ret = AscendC::HardEvent::V_MTE1;
    }
    else if (src == PIPE_MTE3 && dst == PIPE_MTE2) {
        ret = AscendC::HardEvent::MTE3_MTE2;
    }
    else if (src == PIPE_MTE2 && dst == PIPE_MTE3) {
        ret = AscendC::HardEvent::MTE2_MTE3;
    }
    else if (src == PIPE_S && dst == PIPE_V) {
        ret = AscendC::HardEvent::S_V;
    }
    else if (src == PIPE_V && dst == PIPE_S) {
        ret = AscendC::HardEvent::V_S;
    }
    else if (src == PIPE_S && dst == PIPE_MTE2) {
        ret = AscendC::HardEvent::S_MTE2;
    }
    else if (src == PIPE_MTE2 && dst == PIPE_S) {
        ret = AscendC::HardEvent::MTE2_S;
    }
    else if (src == PIPE_S && dst == PIPE_MTE3) {
        ret = AscendC::HardEvent::S_MTE3;
    }
    else if (src == PIPE_MTE3 && dst == PIPE_S) {
        ret = AscendC::HardEvent::MTE3_S;
    }
    else if (src == PIPE_M && dst == PIPE_S) {
        ret = AscendC::HardEvent::M_S;
    }
#if (__CCE_AICORE__ >= 210)
    else if (src == PIPE_M && dst == PIPE_FIX) {
        ret = AscendC::HardEvent::M_FIX;
    }
    else if (src == PIPE_FIX && dst == PIPE_M) {
        ret = AscendC::HardEvent::FIX_M;
    }
    else if (src == PIPE_MTE2 && dst == PIPE_FIX) {
        ret = AscendC::HardEvent::MTE2_FIX;
    }
    else if (src == PIPE_FIX && dst == PIPE_MTE2) {
        ret = AscendC::HardEvent::FIX_MTE2;
    }
    else if (src == PIPE_FIX && dst == PIPE_S) {
        ret = AscendC::HardEvent::FIX_S;
    }
    else if (src == PIPE_FIX && dst == PIPE_MTE3) {
        ret = AscendC::HardEvent::FIX_MTE3;
    }
    else if (src == PIPE_MTE1 && dst == PIPE_FIX) {
        ret = AscendC::HardEvent::MTE1_FIX;
    }
    else if (src == PIPE_FIX && dst == PIPE_MTE1) {
        ret = AscendC::HardEvent::FIX_MTE1;
    }
    else if (src == PIPE_FIX && dst == PIPE_FIX) {
        ret = AscendC::HardEvent::FIX_FIX;
    }
#endif
    return ret;
}

constexpr int PIPE_NONE = -1;

template <auto src, auto dst, uint32_t depth_ = 1>
class UBQue
{
public:
    static constexpr auto src_pipe = src;
    static constexpr auto dst_pipe = dst;
    static constexpr auto fwd_evt = GetHardEventByPipe<src_pipe, dst_pipe>();
    static constexpr auto bwd_evt = GetHardEventByPipe<dst_pipe, src_pipe>();

    static constexpr bool valid_src = std::is_same_v<pipe_t, std::remove_const_t<decltype(src_pipe)>>;
    static constexpr bool valid_dst = std::is_same_v<pipe_t, std::remove_const_t<decltype(dst_pipe)>>;

    static_assert([]() constexpr {
        bool cond = true;
        if constexpr (valid_src) { // Skip call AscendC::IsSupportedPipe when arg is not pipe_t
            cond = cond && AscendC::IsSupportedPipe(src_pipe);
        }
        if constexpr (valid_dst) {
            cond = cond && AscendC::IsSupportedPipe(dst_pipe);
        }
        if constexpr (valid_src && valid_dst) {
            cond = cond && fwd_evt != AscendC::HardEvent::MAX && bwd_evt != AscendC::HardEvent::MAX;
        }
        return cond;
    }(),
        "Unsupported pipe config detected!"
    );

    static constexpr bool disable_sync =
        !valid_src || !valid_dst || (src_pipe == dst_pipe && dst_pipe == PIPE_S);

public:
    // Keep compatibility with TPipe/TBufPool
    static constexpr bool isTQue = true;
    static constexpr uint32_t queDepth = depth_;
    static_assert(queDepth > 0, "Unsupport queDepth is zero");
    static constexpr AscendC::TPosition srcPosition = AscendC::TPosition::VECCALC;
    static constexpr AscendC::TPosition dstPosition = AscendC::TPosition::VECCALC;
    static constexpr AscendC::HardEvent enQueEvt = fwd_evt;
    static constexpr AscendC::HardEvent freeBufEvt = bwd_evt;
#ifndef __ASCC_HOST__
    AscendC::TQueConfig config = {0};
#endif

    union {
        uint64_t value;
        struct {
            uint8_t bufNum;
            uint8_t usedCount;
            uint16_t head;
            uint16_t tail;
            uint8_t bufUsedCount;
            uint8_t bufCursor;
        };
    };

    AscendC::TBufType* bufStart;
    AscendC::TBufHandle que[queDepth];

public:
    OPX_DEVICE
    UBQue() noexcept : value(0), bufStart(nullptr)
    {
        for (uint32_t i = 0; i < queDepth; i++) {
            que[i] = nullptr;
        }
    }

    UBQue(const UBQue&) = delete;

    OPX_DEVICE
    UBQue(UBQue&& other) noexcept :
        value(other.value), bufStart(other.bufStart)
    {
        for (uint32_t i = 0; i < queDepth; i++) {
            que[i] = other.que[i];
            other.que[i] = nullptr;
        }
        other.value = 0;
        other.bufStart = nullptr;
    }

    OPX_DEVICE
    ~UBQue()
    {
        FreeAllEvent();
    }

    OPX_DEVICE
    UBQue& operator=(UBQue&& other) noexcept
    {
        if (this != &other) {
            FreeAllEvent();
            bufStart = other.bufStart;
            value = other.value;
            other.bufStart = nullptr;
            other.value = 0;
            for (uint32_t i = 0; i < queDepth; i++) {
                que[i] = other.que[i];
                other.que[i] = nullptr;
            }
        }
        return *this;
    }

    template <typename T>
    OPX_DEVICE
    AscendC::LocalTensor<T> AllocTensor()
    {
        AscendC::TBufType *ptr;
        while (true) {
            if constexpr (queDepth == 1) {
                ptr = bufStart;
            } else {
                ptr = bufStart + bufCursor;
                bufCursor++;
                if (bufCursor == queDepth) {
                    bufCursor = 0;
                }
            }
#ifndef DNDEBUG
            bufUsedCount++;
#endif
            if (ptr->state != AscendC::TBufState::FREE) {
                continue;
            }
            ptr->state = AscendC::TBufState::OCCUPIED;

            if constexpr (disable_sync) {
                break;
            } else if constexpr (src_pipe != dst_pipe) {
                if (ptr->freeBufEvtID != AscendC::INVALID_TEVENTID) {
                    AscendC::TQueSync<dst_pipe, src_pipe>().WaitFlag(ptr->freeBufEvtID);
                    GetTPipePtr()->ReleaseEventID<bwd_evt>(ptr->freeBufEvtID);
                    ptr->freeBufEvtID = AscendC::INVALID_TEVENTID;
                }
            } else {
                AscendC::PipeBarrier<src_pipe>();
            }
            break;
        }
        return Buf2Tensor<T>(ptr);
    }

    template <typename T>
    OPX_DEVICE
    void EnQue(const AscendC::LocalTensor<T>& tensor)
    {
        AscendC::TBufHandle buf = tensor.GetBufferHandle();
        if constexpr (queDepth == 1) {
            que[0] = buf;
        } else {
            que[tail] = buf;
            if (++tail >= queDepth) {
                tail = 0;
            }
        }
#ifndef DNDEBUG
        usedCount++;
#endif
        if constexpr (disable_sync) {
            return;
        } else if constexpr (src_pipe != dst_pipe) {
            auto ptr = reinterpret_cast<AscendC::TBufType*>(buf);
            ptr->enQueEvtID = GetTPipePtr()->AllocEventID<fwd_evt>();
            AscendC::TQueSync<src_pipe, dst_pipe>().SetFlag(ptr->enQueEvtID);
        }
    }

    template <typename T>
    OPX_DEVICE
    AscendC::LocalTensor<T> DeQue()
    {
        AscendC::TBufHandle buf;
        if constexpr (queDepth == 1) {
            buf = que[0];
            que[0] = nullptr;
        } else {
            buf = que[head];
            que[head] = nullptr;
            if (++head >= queDepth) {
                head = 0;
            }
        }
#ifndef DNDEBUG
        usedCount--;
#endif
        auto ptr = reinterpret_cast<AscendC::TBufType*>(buf);
        if constexpr (disable_sync) {
            // noop
        } else if constexpr (src_pipe != dst_pipe) {
            if (ptr->enQueEvtID != AscendC::INVALID_TEVENTID) {
                AscendC::TQueSync<src_pipe, dst_pipe>().WaitFlag(ptr->enQueEvtID);
                GetTPipePtr()->ReleaseEventID<fwd_evt>(ptr->enQueEvtID);
                ptr->enQueEvtID = AscendC::INVALID_TEVENTID;
            }
        } else {
            AscendC::PipeBarrier<src_pipe>();
        }
        return Buf2Tensor<T>(ptr);
    }

    template <typename T>
    OPX_DEVICE
    void FreeTensor(const AscendC::LocalTensor<T>& tensor)
    {
        AscendC::TBufHandle buf = tensor.GetBufferHandle();
        auto ptr = reinterpret_cast<AscendC::TBufType*>(buf);
        ptr->state = AscendC::TBufState::FREE;
#ifndef DNDEBUG
        bufUsedCount--;
#endif
        if constexpr (disable_sync) {
            return;
        } else if constexpr (src_pipe != dst_pipe) {
            ptr->freeBufEvtID = GetTPipePtr()->AllocEventID<bwd_evt>();
            AscendC::TQueSync<dst_pipe, src_pipe>().SetFlag(ptr->freeBufEvtID);
        }
    }

    OPX_DEVICE
    void FreeAllEvent()
    {
        if constexpr (disable_sync || src_pipe == dst_pipe) {
            return;
        } else {
            auto ptr = bufStart;
            for (uint32_t i = 0; i < bufNum; i++, ptr++) {
                if (ptr->freeBufEvtID != AscendC::INVALID_TEVENTID) {
                    AscendC::TQueSync<dst_pipe, src_pipe>().WaitFlag(ptr->freeBufEvtID);
                    GetTPipePtr()->ReleaseEventID<bwd_evt>(ptr->freeBufEvtID);
                    ptr->freeBufEvtID = AscendC::INVALID_TEVENTID;
                }
            }
        }
    }

    template <typename T>
    OPX_DEVICE
    AscendC::LocalTensor<T> Buf2Tensor(AscendC::TBufType* buf)
    {
        AscendC::TBuffAddr addr;
        addr.dataLen = buf->dataLen;
        addr.bufferAddr = buf->address;
        addr.bufferHandle = reinterpret_cast<AscendC::TBufHandle>(buf);
        addr.logicPos = static_cast<uint8_t>(AscendC::TPosition::VECCALC);

        AscendC::LocalTensor<T> tensor;
        tensor.SetAddr(addr);
        return tensor;
    }

#ifndef DNDEBUG
    OPX_DEVICE
    bool VacantInQue()
    {
        return usedCount < queDepth;
    }

    OPX_DEVICE
    bool HasTensorInQue()
    {
        return usedCount > 0;
    }

    OPX_DEVICE
    bool HasIdleBuffer()
    {
        return bufUsedCount < bufNum;
    }
#endif
};

} // end namespace opx
