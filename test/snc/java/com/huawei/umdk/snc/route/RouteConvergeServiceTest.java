/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: route converge service test
 * Create: 2026-08-18
 * Note:
 */
package com.huawei.umdk.snc.route;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.huawei.umdk.snc.entity.LinkEvent;
import com.huawei.umdk.snc.entity.NpuDevice;
import com.huawei.umdk.snc.entity.NpuForwardingChip;
import com.huawei.umdk.snc.entity.NpuPortEntity;
import com.huawei.umdk.snc.entity.OutPortInfo;
import com.huawei.umdk.snc.entity.PortEntity;
import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.entity.SwDevice;
import com.huawei.umdk.snc.entity.SwForwardingChip;
import com.huawei.umdk.snc.entity.SwPortEntity;
import com.huawei.umdk.snc.entity.SwitchLevel;
import com.huawei.umdk.snc.route.service.RouteConvergeService;
import com.huawei.umdk.snc.route.service.RouteInstantiationService;

/**
 * RouteConvergeService 路由收敛单元测试。
 *
 * <p>测试聚焦于 BFS 路由收敛算法本身：在已实例化的 instantiationRouteMap 上，基于 link
 * 事件（down/up）按广度优先策略在互联转发节点间传播收敛状态，刷新 OutPortInfo.convergedFlag
 * 与 RoutingEntry.reachable。
 *
 * <p>路由表 key 遵循 {@link RouteInstantiationService#buildRouteTableKey} 规范
 * （"deviceName#chipIndex"），OutPortInfo.portName 与 SuperNode 中 PortEntity.portName
 * 一致，等价于经 RouteMspService + RouteInstantiationService 实例化后的状态。
 * 路由模板生成与实例化的端到端验证已由 {@link RouteMspTest} / {@link RouteInstantiationTest}
 * 覆盖；本测试在相同的数据契约下验证收敛传播逻辑。
 *
 * <p>算法语义说明：link 事件 device=X port=P 触发的收敛，从 X 的 P 所属 chip 出发，
 * 通过该 chip 上其他 linkStatus=up 端口向对端传播。因此：
 * <ul>
 *   <li>叶子节点（如 NPU，仅有上行端口）端口 down 时，本节点路由收敛但无其他端口可向对端传播
 *       ——对应"仅本地收敛无需传播"场景；</li>
 *   <li>中间节点（如 L1SW/L2SW，多端口）端口 down 时，通过其他 up 端口向对端传播
 *       ——对应"跨节点传播"场景。</li>
 * </ul>
 *
 * <p>网络结构（NPU / L1 SW / L2 SW 三层）：
 * <pre>
 *   NPU0 --\
 *          L1SW -- L2SW
 *   NPU1 --/
 * </pre>
 * - NPU0/NPU1 各有 1 个上行端口连到 L1SW（叶子节点）；
 * - L1SW 有 2 个下行端口连到 NPU0/NPU1，1 个上行端口连到 L2SW（中间节点）；
 * - L2SW 有 1 个下行端口连到 L1SW。
 * </pre>
 * 路由表里每条路由的出端口名与上述 PortEntity.portName 一致。
 */
class RouteConvergeServiceTest {

    private static final String SUPER_NODE_NAME = "sn-01";

    // 设备名
    private static final String NPU0 = "npu-0";
    private static final String NPU1 = "npu-1";
    private static final String L1_SW = "sw-l1-0";
    private static final String L2_SW = "sw-l2-0";

    // NPU chip index
    private static final int NPU_CHIP = 2;

    // SW chip index
    private static final int SW_CHIP = 1;

    // 端口名（与路由表 OutPortInfo.portName 严格一致）
    private static final String NPU0_UP = "npu-0-up";
    private static final String NPU1_UP = "npu-1-up";
    private static final String L1SW_DOWN_TO_NPU0 = "l1sw-down-0";
    private static final String L1SW_DOWN_TO_NPU1 = "l1sw-down-1";
    private static final String L1SW_UP = "l1sw-up";
    private static final String L2SW_DOWN = "l2sw-down";

    // 路由前缀（目的地址）
    private static final String PREFIX_NPU0 = "10.0.0.1";
    private static final String PREFIX_NPU1 = "10.0.0.2";
    private static final String PREFIX_L1SW = "10.0.0.3";
    private static final String PREFIX_L2SW = "10.0.0.4";

    private RouteConvergeService service;
    private SuperNode superNode;
    private Map<String, Map<String, RoutingEntry>> routeMap;

    @BeforeEach
    void setUp() {
        service = new RouteConvergeService();
        superNode = buildSuperNode();
        routeMap = buildInstantiationRouteMap();
    }

    // ==================== 仅本地收敛（无传播）场景 ====================

    /**
     * 场景1：NPU0（叶子节点）上行端口 down。
     * NPU0 上所有以 NPU0_UP 为出端口的路由收敛、reachable 变 false；
     * 但 NPU0 chip 上无其他端口可向对端传播，BFS 在起点后即终止。
     *
     * <p>验证：起始节点本地收敛正确，对端（L1SW/L2SW/NPU1）路由可达性不受影响。
     */
    @Test
    void converge_down_onLeafNode_convergesLocalOnlyNoPropagation() {
        // 初始全部可达
        assertReachable(NPU0, NPU_CHIP, PREFIX_NPU0, true);
        assertReachable(L1_SW, SW_CHIP, PREFIX_NPU0, true);

        // 触发 NPU0 上行端口 down
        LinkEvent event = new LinkEvent(NPU0, NPU0_UP, LinkEvent.LINK_STATUS_DOWN, "t1");
        service.converge(routeMap, superNode, event);

        // NPU0 上所有以 NPU0_UP 为出端口的路由均收敛、不可达
        assertReachable(NPU0, NPU_CHIP, PREFIX_NPU0, false);
        assertOutPortConverged(NPU0, NPU_CHIP, PREFIX_NPU0, NPU0_UP, true);
        assertReachable(NPU0, NPU_CHIP, PREFIX_NPU1, false);
        assertOutPortConverged(NPU0, NPU_CHIP, PREFIX_NPU1, NPU0_UP, true);
        assertReachable(NPU0, NPU_CHIP, PREFIX_L1SW, false);
        assertReachable(NPU0, NPU_CHIP, PREFIX_L2SW, false);

        // L1SW/L2SW/NPU1 未受影响（无传播）
        assertReachable(L1_SW, SW_CHIP, PREFIX_NPU0, true);
        assertOutPortConverged(L1_SW, SW_CHIP, PREFIX_NPU0, L1SW_DOWN_TO_NPU0, false);
        assertReachable(L2_SW, SW_CHIP, PREFIX_NPU0, true);
        assertOutPortConverged(L2_SW, SW_CHIP, PREFIX_NPU0, L2SW_DOWN, false);
        assertReachable(NPU1, NPU_CHIP, PREFIX_NPU1, true);
    }

    /**
     * 场景2：NPU0 上行端口 down，但 NPU0 上没有以该端口为出端口的路由。
     * 起始节点 reachable 无变化，BFS 在起点即终止，不传播给任何对端。
     */
    @Test
    void converge_down_noRouteOnStartPort_terminatesImmediately() {
        // 删除 NPU0 上的所有路由，确保 down 事件命不中任何 OutPortInfo
        routeMap.get(RouteInstantiationService.buildRouteTableKey(NPU0, NPU_CHIP)).clear();

        LinkEvent event = new LinkEvent(NPU0, NPU0_UP, LinkEvent.LINK_STATUS_DOWN, "t2");
        service.converge(routeMap, superNode, event);

        // L1SW/L2SW 上 PREFIX_NPU0 仍可达，未被收敛
        assertReachable(L1_SW, SW_CHIP, PREFIX_NPU0, true);
        assertOutPortConverged(L1_SW, SW_CHIP, PREFIX_NPU0, L1SW_DOWN_TO_NPU0, false);
        assertReachable(L2_SW, SW_CHIP, PREFIX_NPU0, true);
        assertOutPortConverged(L2_SW, SW_CHIP, PREFIX_NPU0, L2SW_DOWN, false);
    }

    // ==================== 跨节点传播场景 ====================

    /**
     * 场景3：L1SW 的下行端口 L1SW_DOWN_TO_NPU0 down（中间节点端口 down）。
     * L1SW 上 PREFIX_NPU0 不可达；通过 L1SW 其他 up 端口（L1SW_DOWN_TO_NPU1、L1SW_UP）
     * 传播给 NPU1 和 L2SW，使其上 PREFIX_NPU0 路由收敛、reachable 变 false。
     * NPU1/L2SW 均为叶子（单端口），不再继续传播。
     *
     * <p>验证三层传播：L1SW -> NPU1 / L2SW。
     */
    @Test
    void converge_down_onIntermediateNode_propagatesToPeers() {
        LinkEvent event = new LinkEvent(L1_SW, L1SW_DOWN_TO_NPU0, LinkEvent.LINK_STATUS_DOWN, "t3");
        service.converge(routeMap, superNode, event);

        // L1SW 上 PREFIX_NPU0 不可达，L1SW_DOWN_TO_NPU0 收敛
        assertReachable(L1_SW, SW_CHIP, PREFIX_NPU0, false);
        assertOutPortConverged(L1_SW, SW_CHIP, PREFIX_NPU0, L1SW_DOWN_TO_NPU0, true);
        // L1SW 上其他路由（PREFIX_NPU1 等）不受影响
        assertReachable(L1_SW, SW_CHIP, PREFIX_NPU1, true);
        assertOutPortConverged(L1_SW, SW_CHIP, PREFIX_NPU1, L1SW_DOWN_TO_NPU1, false);

        // NPU1 上 PREFIX_NPU0 不可达（经 L1SW_DOWN_TO_NPU1 端口传播过来），NPU1_UP 收敛
        assertReachable(NPU1, NPU_CHIP, PREFIX_NPU0, false);
        assertOutPortConverged(NPU1, NPU_CHIP, PREFIX_NPU0, NPU1_UP, true);

        // L2SW 上 PREFIX_NPU0 不可达（经 L1SW_UP 端口传播过来），L2SW_DOWN 收敛
        assertReachable(L2_SW, SW_CHIP, PREFIX_NPU0, false);
        assertOutPortConverged(L2_SW, SW_CHIP, PREFIX_NPU0, L2SW_DOWN, true);

        // NPU0 不在传播路径上（L1SW_DOWN_TO_NPU0 已 down，被跳过），其路由不受影响
        assertReachable(NPU0, NPU_CHIP, PREFIX_NPU0, true);
        assertOutPortConverged(NPU0, NPU_CHIP, PREFIX_NPU0, NPU0_UP, false);
    }

    /**
     * 场景4：L1SW 的上行端口 L1SW_UP down。
     * L1SW 上以 L1SW_UP 为出端口的路由（PREFIX_L2SW）收敛、不可达；
     * 通过 L1SW 下行端口传播给 NPU0/NPU1，使其 PREFIX_L2SW 路由收敛。
     */
    @Test
    void converge_down_onL1swUpPort_propagatesDownToNpus() {
        setPortLinkStatus(L1_SW, L1SW_UP, LinkEvent.LINK_STATUS_DOWN);
        LinkEvent event = new LinkEvent(L1_SW, L1SW_UP, LinkEvent.LINK_STATUS_DOWN, "t4");
        service.converge(routeMap, superNode, event);

        // L1SW 上 PREFIX_L2SW 不可达，L1SW_UP 收敛
        assertReachable(L1_SW, SW_CHIP, PREFIX_L2SW, false);
        assertOutPortConverged(L1_SW, SW_CHIP, PREFIX_L2SW, L1SW_UP, true);
        // L1SW 上 PREFIX_NPU0/PREFIX_NPU1 不受影响
        assertReachable(L1_SW, SW_CHIP, PREFIX_NPU0, true);
        assertReachable(L1_SW, SW_CHIP, PREFIX_NPU1, true);

        // NPU0 上 PREFIX_L2SW 不可达，NPU0_UP 收敛
        assertReachable(NPU0, NPU_CHIP, PREFIX_L2SW, false);
        assertOutPortConverged(NPU0, NPU_CHIP, PREFIX_L2SW, NPU0_UP, true);

        // NPU1 上 PREFIX_L2SW 不可达，NPU1_UP 收敛
        assertReachable(NPU1, NPU_CHIP, PREFIX_L2SW, false);
        assertOutPortConverged(NPU1, NPU_CHIP, PREFIX_L2SW, NPU1_UP, true);

        // L2SW 不在传播路径上（L1SW_UP 已 down，跳过该对端），其路由不受影响
        assertReachable(L2_SW, SW_CHIP, PREFIX_L2SW, true);
    }

    /**
     * 场景5：L1SW 下行端口 down，但 L1SW 上 PREFIX_NPU0 有两个出端口
     * （L1SW_DOWN_TO_NPU0 和 L1SW_DOWN_TO_NPU1），down NPU0 端口后仍可达，
     * 不向对端传播。
     */
    @Test
    void converge_down_multiPathPeerStillReachable_noPropagation() {
        // 给 L1SW 的 PREFIX_NPU0 再加一个出端口 L1SW_DOWN_TO_NPU1，使 down NPU0 后仍可达
        RoutingEntry l1Entry = routeMap.get(RouteInstantiationService.buildRouteTableKey(L1_SW, SW_CHIP))
            .get(PREFIX_NPU0);
        l1Entry.getMutableOutPortInfos().put(L1SW_DOWN_TO_NPU1,
            new OutPortInfo(L1SW_DOWN_TO_NPU1, null, null, null, null, 0));
        l1Entry.refreshReachable();

        LinkEvent event = new LinkEvent(L1_SW, L1SW_DOWN_TO_NPU0, LinkEvent.LINK_STATUS_DOWN, "t5");
        service.converge(routeMap, superNode, event);

        // L1SW 上 PREFIX_NPU0 仍可达（多端口中 L1SW_DOWN_TO_NPU1 仍有效）
        assertReachable(L1_SW, SW_CHIP, PREFIX_NPU0, true);
        // L1SW_DOWN_TO_NPU0 被收敛，L1SW_DOWN_TO_NPU1 未收敛
        assertOutPortConverged(L1_SW, SW_CHIP, PREFIX_NPU0, L1SW_DOWN_TO_NPU0, true);
        assertOutPortConverged(L1_SW, SW_CHIP, PREFIX_NPU0, L1SW_DOWN_TO_NPU1, false);

        // reachable 未变化，不向 NPU1/L2SW 传播
        assertReachable(NPU1, NPU_CHIP, PREFIX_NPU0, true);
        assertOutPortConverged(NPU1, NPU_CHIP, PREFIX_NPU0, NPU1_UP, false);
        assertReachable(L2_SW, SW_CHIP, PREFIX_NPU0, true);
        assertOutPortConverged(L2_SW, SW_CHIP, PREFIX_NPU0, L2SW_DOWN, false);
    }

    // ==================== up 恢复场景 ====================

    /**
     * 场景6：先 down L1SW 的 L1SW_DOWN_TO_NPU0，再 up 恢复。
     * 验证收敛状态被清除、reachable 恢复 true，并传播给 NPU1/L2SW 恢复其对应路由。
     *
     * <p>复用历史 link 状态：down 后端口 linkStatus=down，up 事件清除 PASSIVE_CONVERRGED。
     */
    @Test
    void converge_downThenUp_restoresReachabilityAcrossLayers() {
        // 先 down
        setPortLinkStatus(L1_SW, L1SW_DOWN_TO_NPU0, LinkEvent.LINK_STATUS_DOWN);
        service.converge(routeMap, superNode,
            new LinkEvent(L1_SW, L1SW_DOWN_TO_NPU0, LinkEvent.LINK_STATUS_DOWN, "t6-1"));
        // 此时三层 PREFIX_NPU0 均不可达
        assertReachable(L1_SW, SW_CHIP, PREFIX_NPU0, false);
        assertReachable(NPU1, NPU_CHIP, PREFIX_NPU0, false);
        assertReachable(L2_SW, SW_CHIP, PREFIX_NPU0, false);

        // 再 up 恢复：linkStatus 置 up，触发 up 事件
        setPortLinkStatus(L1_SW, L1SW_DOWN_TO_NPU0, LinkEvent.LINK_STATUS_UP);
        service.converge(routeMap, superNode,
            new LinkEvent(L1_SW, L1SW_DOWN_TO_NPU0, LinkEvent.LINK_STATUS_UP, "t6-2"));

        // 三层 PREFIX_NPU0 恢复可达，PASSIVE 标志被清除
        assertReachable(L1_SW, SW_CHIP, PREFIX_NPU0, true);
        assertOutPortConverged(L1_SW, SW_CHIP, PREFIX_NPU0, L1SW_DOWN_TO_NPU0, false);
        assertReachable(NPU1, NPU_CHIP, PREFIX_NPU0, true);
        assertOutPortConverged(NPU1, NPU_CHIP, PREFIX_NPU0, NPU1_UP, false);
        assertReachable(L2_SW, SW_CHIP, PREFIX_NPU0, true);
        assertOutPortConverged(L2_SW, SW_CHIP, PREFIX_NPU0, L2SW_DOWN, false);
    }

    /**
     * 场景7：连续多次 notifyLinkEvent 调用，复用历史 link 状态。
     * down L1SW_DOWN_TO_NPU0 -> down L1SW_UP -> up L1SW_UP -> up L1SW_DOWN_TO_NPU0，
     * 验证每次都基于当前 linkStatus 正确传播，已 down 的端口在后续传播中被跳过。
     *
     * <p>恢复顺序设计为"先 up 上行、再 up 下行"：up L1SW_UP 时 L1SW_DOWN_TO_NPU0 仍 down，
     * 传播跳过该端口不到 NPU0/NPU1；up L1SW_DOWN_TO_NPU0 时 L1SW_UP 已 up，能向 L2SW
     * 恢复 PREFIX_NPU0，也能向 NPU1 恢复（NPU0 是 task.port 对端，被跳过）。
     */
    @Test
    void converge_multipleEvents_reuseLinkState() {
        // 1. down L1SW_DOWN_TO_NPU0：PREFIX_NPU0 在 L1SW/NPU1/L2SW 不可达
        //    （L1SW_DOWN_TO_NPU0 是 task.port，对端 NPU0 不被传播）
        setPortLinkStatus(L1_SW, L1SW_DOWN_TO_NPU0, LinkEvent.LINK_STATUS_DOWN);
        service.converge(routeMap, superNode,
            new LinkEvent(L1_SW, L1SW_DOWN_TO_NPU0, LinkEvent.LINK_STATUS_DOWN, "t7-1"));
        assertReachable(L1_SW, SW_CHIP, PREFIX_NPU0, false);
        assertReachable(NPU1, NPU_CHIP, PREFIX_NPU0, false);
        assertReachable(L2_SW, SW_CHIP, PREFIX_NPU0, false);
        // NPU0 未被传播，PREFIX_NPU0 仍可达
        assertReachable(NPU0, NPU_CHIP, PREFIX_NPU0, true);
        // PREFIX_L2SW 仍可达
        assertReachable(L1_SW, SW_CHIP, PREFIX_L2SW, true);

        // 2. down L1SW_UP：PREFIX_L2SW 在 L1SW/NPU0/NPU1 不可达
        //    此时 L1SW_DOWN_TO_NPU0 已 down，传播跳过该端口（不到 NPU0）
        setPortLinkStatus(L1_SW, L1SW_UP, LinkEvent.LINK_STATUS_DOWN);
        service.converge(routeMap, superNode,
            new LinkEvent(L1_SW, L1SW_UP, LinkEvent.LINK_STATUS_DOWN, "t7-2"));
        assertReachable(L1_SW, SW_CHIP, PREFIX_L2SW, false);
        assertReachable(NPU0, NPU_CHIP, PREFIX_L2SW, true);
        assertOutPortConverged(NPU0, NPU_CHIP, PREFIX_L2SW, NPU0_UP, false);
        assertReachable(NPU1, NPU_CHIP, PREFIX_L2SW, false);
        assertOutPortConverged(NPU1, NPU_CHIP, PREFIX_L2SW, NPU1_UP, true);
        // PREFIX_NPU0 仍保持 down（未被 up 恢复）
        assertReachable(L1_SW, SW_CHIP, PREFIX_NPU0, false);

        // 3. up L1SW_UP 恢复：L1SW_DOWN_TO_NPU0 仍 down，传播跳过该端口不到 NPU0；
        //    L1SW_DOWN_TO_NPU1 仍 up，能向 NPU1 恢复 PREFIX_L1SW/PREFIX_L2SW；
        //    L1SW_UP 是 task.port，对端 L2SW 不被传播
        setPortLinkStatus(L1_SW, L1SW_UP, LinkEvent.LINK_STATUS_UP);
        service.converge(routeMap, superNode,
            new LinkEvent(L1_SW, L1SW_UP, LinkEvent.LINK_STATUS_UP, "t7-3"));
        // L1SW PREFIX_L1SW/PREFIX_L2SW 恢复可达，L1SW_UP 清除收敛
        assertReachable(L1_SW, SW_CHIP, PREFIX_L2SW, true);
        assertOutPortConverged(L1_SW, SW_CHIP, PREFIX_L2SW, L1SW_UP, false);
        // NPU0 的 PREFIX_L2SW 未被收敛过，仍可达（未被传播影响）
        assertReachable(NPU0, NPU_CHIP, PREFIX_L2SW, true);
        // NPU1 的 PREFIX_L2SW 经 L1SW_DOWN_TO_NPU1 恢复可达
        assertReachable(NPU1, NPU_CHIP, PREFIX_L2SW, true);
        assertOutPortConverged(NPU1, NPU_CHIP, PREFIX_L2SW, NPU1_UP, false);
        // PREFIX_NPU0 仍 down（未恢复，需 up L1SW_DOWN_TO_NPU0 才能恢复）
        assertReachable(L1_SW, SW_CHIP, PREFIX_NPU0, false);
        assertReachable(L2_SW, SW_CHIP, PREFIX_NPU0, false);

        // 4. up L1SW_DOWN_TO_NPU0 恢复：此时 L1SW_UP 已 up，能向 L2SW 恢复 PREFIX_NPU0；
        //    L1SW_DOWN_TO_NPU1 up 能向 NPU1 恢复 PREFIX_NPU0；
        //    L1SW_DOWN_TO_NPU0 是 task.port，对端 NPU0 不被传播（NPU0 的 PREFIX_NPU0 本就可达）
        setPortLinkStatus(L1_SW, L1SW_DOWN_TO_NPU0, LinkEvent.LINK_STATUS_UP);
        service.converge(routeMap, superNode,
            new LinkEvent(L1_SW, L1SW_DOWN_TO_NPU0, LinkEvent.LINK_STATUS_UP, "t7-4"));
        // PREFIX_NPU0 在 L1SW/NPU1/L2SW 恢复可达
        assertReachable(L1_SW, SW_CHIP, PREFIX_NPU0, true);
        assertOutPortConverged(L1_SW, SW_CHIP, PREFIX_NPU0, L1SW_DOWN_TO_NPU0, false);
        assertReachable(NPU1, NPU_CHIP, PREFIX_NPU0, true);
        assertOutPortConverged(NPU1, NPU_CHIP, PREFIX_NPU0, NPU1_UP, false);
        assertReachable(L2_SW, SW_CHIP, PREFIX_NPU0, true);
        assertOutPortConverged(L2_SW, SW_CHIP, PREFIX_NPU0, L2SW_DOWN, false);
        // 所有前缀最终全部可达
        assertReachable(L1_SW, SW_CHIP, PREFIX_L2SW, true);
        assertReachable(NPU1, NPU_CHIP, PREFIX_L2SW, true);
    }

    // ==================== 参数校验场景 ====================

    @Test
    void converge_nullRouteMap_throwsIllegalArgument() {
        LinkEvent event = new LinkEvent(NPU0, NPU0_UP, LinkEvent.LINK_STATUS_DOWN, "t");
        assertThrows(IllegalArgumentException.class,
            () -> service.converge(null, superNode, event));
    }

    @Test
    void converge_nullSuperNode_throwsIllegalArgument() {
        LinkEvent event = new LinkEvent(NPU0, NPU0_UP, LinkEvent.LINK_STATUS_DOWN, "t");
        assertThrows(IllegalArgumentException.class,
            () -> service.converge(routeMap, null, event));
    }

    @Test
    void converge_nullEvent_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class,
            () -> service.converge(routeMap, superNode, null));
    }

    @Test
    void converge_invalidEventType_throwsIllegalArgument() {
        LinkEvent event = new LinkEvent(NPU0, NPU0_UP, "unknown", "t");
        assertThrows(IllegalArgumentException.class,
            () -> service.converge(routeMap, superNode, event));
    }

    @Test
    void converge_portNotFound_throwsIllegalState() {
        LinkEvent event = new LinkEvent(NPU0, "not-exist-port", LinkEvent.LINK_STATUS_DOWN, "t");
        assertThrows(IllegalStateException.class,
            () -> service.converge(routeMap, superNode, event));
    }

    // ==================== 测试数据构建 ====================

    /**
     * 构造三层互联 SuperNode：NPU0/NPU1 -- L1SW -- L2SW。
     * 端口互连关系通过 PortEntity.remoteDevice/remotePort 双向设置。
     */
    private SuperNode buildSuperNode() {
        // NPU0: 1 个上行端口连到 L1SW
        NpuPortEntity npu0Up = new NpuPortEntity();
        npu0Up.setPortName(NPU0_UP);
        npu0Up.setRemoteDevice(L1_SW);
        npu0Up.setRemotePort(L1SW_DOWN_TO_NPU0);
        npu0Up.setLinkStatus(LinkEvent.LINK_STATUS_UP);
        Map<String, NpuPortEntity> npu0Ports = new LinkedHashMap<>();
        npu0Ports.put(NPU0_UP, npu0Up);
        NpuForwardingChip npu0Chip = new NpuForwardingChip(NPU_CHIP, npu0Ports);
        Map<Integer, NpuForwardingChip> npu0Chips = new HashMap<>();
        npu0Chips.put(NPU_CHIP, npu0Chip);
        NpuDevice npu0 = new NpuDevice(NPU0, null, "rack-1", npu0Chips, "os", null, 1, 0, 1);

        // NPU1: 1 个上行端口连到 L1SW
        NpuPortEntity npu1Up = new NpuPortEntity();
        npu1Up.setPortName(NPU1_UP);
        npu1Up.setRemoteDevice(L1_SW);
        npu1Up.setRemotePort(L1SW_DOWN_TO_NPU1);
        npu1Up.setLinkStatus(LinkEvent.LINK_STATUS_UP);
        Map<String, NpuPortEntity> npu1Ports = new LinkedHashMap<>();
        npu1Ports.put(NPU1_UP, npu1Up);
        NpuForwardingChip npu1Chip = new NpuForwardingChip(NPU_CHIP, npu1Ports);
        Map<Integer, NpuForwardingChip> npu1Chips = new HashMap<>();
        npu1Chips.put(NPU_CHIP, npu1Chip);
        NpuDevice npu1 = new NpuDevice(NPU1, null, "rack-1", npu1Chips, "os", null, 1, 0, 2);

        // L1SW: 2 个下行端口连到 NPU0/NPU1，1 个上行端口连到 L2SW
        SwPortEntity l1Down0 = new SwPortEntity();
        l1Down0.setPortName(L1SW_DOWN_TO_NPU0);
        l1Down0.setRemoteDevice(NPU0);
        l1Down0.setRemotePort(NPU0_UP);
        l1Down0.setLinkStatus(LinkEvent.LINK_STATUS_UP);
        SwPortEntity l1Down1 = new SwPortEntity();
        l1Down1.setPortName(L1SW_DOWN_TO_NPU1);
        l1Down1.setRemoteDevice(NPU1);
        l1Down1.setRemotePort(NPU1_UP);
        l1Down1.setLinkStatus(LinkEvent.LINK_STATUS_UP);
        SwPortEntity l1Up = new SwPortEntity();
        l1Up.setPortName(L1SW_UP);
        l1Up.setRemoteDevice(L2_SW);
        l1Up.setRemotePort(L2SW_DOWN);
        l1Up.setLinkStatus(LinkEvent.LINK_STATUS_UP);
        Map<String, SwPortEntity> l1Ports = new LinkedHashMap<>();
        l1Ports.put(L1SW_DOWN_TO_NPU0, l1Down0);
        l1Ports.put(L1SW_DOWN_TO_NPU1, l1Down1);
        l1Ports.put(L1SW_UP, l1Up);
        SwForwardingChip l1Chip = new SwForwardingChip(SW_CHIP, l1Ports);
        Map<Integer, SwForwardingChip> l1Chips = new HashMap<>();
        l1Chips.put(SW_CHIP, l1Chip);
        SwDevice l1Sw = new SwDevice(L1_SW, null, "rack-1", l1Chips, SwitchLevel.L1, 1);

        // L2SW: 1 个下行端口连到 L1SW
        SwPortEntity l2Down = new SwPortEntity();
        l2Down.setPortName(L2SW_DOWN);
        l2Down.setRemoteDevice(L1_SW);
        l2Down.setRemotePort(L1SW_UP);
        l2Down.setLinkStatus(LinkEvent.LINK_STATUS_UP);
        Map<String, SwPortEntity> l2Ports = new LinkedHashMap<>();
        l2Ports.put(L2SW_DOWN, l2Down);
        SwForwardingChip l2Chip = new SwForwardingChip(SW_CHIP, l2Ports);
        Map<Integer, SwForwardingChip> l2Chips = new HashMap<>();
        l2Chips.put(SW_CHIP, l2Chip);
        SwDevice l2Sw = new SwDevice(L2_SW, null, null, l2Chips, SwitchLevel.L2, 1);

        Map<String, NpuDevice> npuDevices = new LinkedHashMap<>();
        npuDevices.put(NPU0, npu0);
        npuDevices.put(NPU1, npu1);
        Map<String, SwDevice> swDevices = new LinkedHashMap<>();
        swDevices.put(L1_SW, l1Sw);
        swDevices.put(L2_SW, l2Sw);
        return new SuperNode(SUPER_NODE_NAME, "v1", npuDevices, swDevices);
    }

    /**
     * 构造 instantiationRouteMap，key 由 {@link RouteInstantiationService#buildRouteTableKey} 生成。
     *
     * <p>路由出端口名严格对应 SuperNode 中 PortEntity.portName，等价于实例化后的状态：
     * - NPU0 路由表（自环地址 + 经 L1SW 转发到其他节点）：
     *     PREFIX_NPU0 -> NPU0_UP (自环，仅 NPU0 自己有)
     *     PREFIX_NPU1 -> NPU0_UP
     *     PREFIX_L1SW -> NPU0_UP
     *     PREFIX_L2SW -> NPU0_UP
     * - NPU1 路由表：
     *     PREFIX_NPU1 -> NPU1_UP
     *     PREFIX_NPU0 -> NPU1_UP
     *     PREFIX_L1SW -> NPU1_UP
     *     PREFIX_L2SW -> NPU1_UP
     * - L1SW 路由表：
     *     PREFIX_NPU0 -> L1SW_DOWN_TO_NPU0
     *     PREFIX_NPU1 -> L1SW_DOWN_TO_NPU1
     *     PREFIX_L1SW -> L1SW_UP        (经 L2SW 绕回，仅用于 up 端口 down 测试)
     *     PREFIX_L2SW -> L1SW_UP
     * - L2SW 路由表：
     *     PREFIX_NPU0 -> L2SW_DOWN
     *     PREFIX_NPU1 -> L2SW_DOWN
     *     PREFIX_L1SW -> L2SW_DOWN
     *     PREFIX_L2SW -> L2SW_DOWN
     * </p>
     */
    private Map<String, Map<String, RoutingEntry>> buildInstantiationRouteMap() {
        Map<String, Map<String, RoutingEntry>> map = new HashMap<>();

        // NPU0 路由表
        Map<String, RoutingEntry> npu0Routes = new LinkedHashMap<>();
        npu0Routes.put(PREFIX_NPU0, buildRoute(PREFIX_NPU0, NPU0_UP));
        npu0Routes.put(PREFIX_NPU1, buildRoute(PREFIX_NPU1, NPU0_UP));
        npu0Routes.put(PREFIX_L1SW, buildRoute(PREFIX_L1SW, NPU0_UP));
        npu0Routes.put(PREFIX_L2SW, buildRoute(PREFIX_L2SW, NPU0_UP));
        map.put(RouteInstantiationService.buildRouteTableKey(NPU0, NPU_CHIP), npu0Routes);

        // NPU1 路由表
        Map<String, RoutingEntry> npu1Routes = new LinkedHashMap<>();
        npu1Routes.put(PREFIX_NPU1, buildRoute(PREFIX_NPU1, NPU1_UP));
        npu1Routes.put(PREFIX_NPU0, buildRoute(PREFIX_NPU0, NPU1_UP));
        npu1Routes.put(PREFIX_L1SW, buildRoute(PREFIX_L1SW, NPU1_UP));
        npu1Routes.put(PREFIX_L2SW, buildRoute(PREFIX_L2SW, NPU1_UP));
        map.put(RouteInstantiationService.buildRouteTableKey(NPU1, NPU_CHIP), npu1Routes);

        // L1SW 路由表
        Map<String, RoutingEntry> l1Routes = new LinkedHashMap<>();
        l1Routes.put(PREFIX_NPU0, buildRoute(PREFIX_NPU0, L1SW_DOWN_TO_NPU0));
        l1Routes.put(PREFIX_NPU1, buildRoute(PREFIX_NPU1, L1SW_DOWN_TO_NPU1));
        l1Routes.put(PREFIX_L1SW, buildRoute(PREFIX_L1SW, L1SW_UP));
        l1Routes.put(PREFIX_L2SW, buildRoute(PREFIX_L2SW, L1SW_UP));
        map.put(RouteInstantiationService.buildRouteTableKey(L1_SW, SW_CHIP), l1Routes);

        // L2SW 路由表
        Map<String, RoutingEntry> l2Routes = new LinkedHashMap<>();
        l2Routes.put(PREFIX_NPU0, buildRoute(PREFIX_NPU0, L2SW_DOWN));
        l2Routes.put(PREFIX_NPU1, buildRoute(PREFIX_NPU1, L2SW_DOWN));
        l2Routes.put(PREFIX_L1SW, buildRoute(PREFIX_L1SW, L2SW_DOWN));
        l2Routes.put(PREFIX_L2SW, buildRoute(PREFIX_L2SW, L2SW_DOWN));
        map.put(RouteInstantiationService.buildRouteTableKey(L2_SW, SW_CHIP), l2Routes);

        return map;
    }

    /**
     * 构造一条路由：单个出端口，默认 convergedFlag=0（可达）。
     */
    private RoutingEntry buildRoute(String prefix, String outPortName) {
        RoutePrefix routePrefix = new RoutePrefix(prefix, 32);
        Map<String, OutPortInfo> outPorts = new LinkedHashMap<>();
        outPorts.put(outPortName, new OutPortInfo(outPortName, null, null, null, null, 0));
        RoutingEntry entry = new RoutingEntry(routePrefix, outPorts, true);
        entry.refreshReachable();
        return entry;
    }

    // ==================== 断言辅助 ====================

    private void assertReachable(String device, int chip, String prefix, boolean expected) {
        Map<String, RoutingEntry> routes = routeMap.get(RouteInstantiationService.buildRouteTableKey(device, chip));
        assertNotNull(routes, "route table not found for " + device + "#" + chip);
        RoutingEntry entry = routes.get(prefix);
        assertNotNull(entry, "routing entry not found for prefix " + prefix);
        assertEquals(expected, entry.isReachable(),
            "reachable mismatch for " + device + "#" + chip + " prefix=" + prefix);
    }

    private void assertOutPortConverged(String device, int chip, String prefix,
                                        String portName, boolean converged) {
        Map<String, RoutingEntry> routes = routeMap.get(RouteInstantiationService.buildRouteTableKey(device, chip));
        RoutingEntry entry = routes.get(prefix);
        assertNotNull(entry, "routing entry not found for prefix " + prefix);
        OutPortInfo outPort = entry.getMutableOutPortInfos().get(portName);
        assertNotNull(outPort, "out port not found: " + portName);
        if (converged) {
            assertTrue(outPort.isConverged(),
                "expected port " + portName + " converged but not, device=" + device + " prefix=" + prefix);
        } else {
            assertFalse(outPort.isConverged(),
                "expected port " + portName + " not converged but is, device=" + device + " prefix=" + prefix);
        }
    }

    /**
     * 设置 SuperNode 中某设备某端口的 linkStatus，模拟 LinkEventService 的刷新行为。
     * 这样 RouteConvergeService 在 propagateToPeers 中读取 port.getLinkStatus() 时
     * 能正确跳过已 down 的端口。
     */
    private void setPortLinkStatus(String deviceName, String portName, String status) {
        for (PortEntity port : superNode.getAllDevices().get(deviceName).getForwardingChips().values()
            .iterator().next().getPorts().values()) {
            if (portName.equals(port.getPortName())) {
                port.setLinkStatus(status);
                port.setUpdateAt(status);
                return;
            }
        }
        throw new AssertionError("port not found: " + deviceName + "/" + portName);
    }
}
