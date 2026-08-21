/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-08-18
 * Note:
 * History: 2026-08-18  Create File; 实现 BFS 路由收敛算法
 */
package com.huawei.umdk.snc.route.service;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

import com.huawei.umdk.snc.entity.DeviceEntity;
import com.huawei.umdk.snc.entity.ForwardingChip;
import com.huawei.umdk.snc.entity.LinkEvent;
import com.huawei.umdk.snc.entity.OutPortInfo;
import com.huawei.umdk.snc.entity.PortEntity;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.log.Logger;

/**
 * 路由收敛服务：基于 link 事件，按广度优先策略在互联转发节点间传播收敛状态。
 *
 * <p>注意：同一设备内不同 forwardingChip 是转发隔离的，因此收敛只在端口所属 chip 的路由表
 * 内传播，且向对端传播时也只更新对端 peerPort 所属 chip 的路由表。
 *
 * <p>算法步骤：
 * <ol>
 *   <li>定位本节点 currPort 所属 chip C，遍历 "device#C" 路由表中以 currPort 为出端口的
 *       RoutingEntry，刷新命中的 OutPortInfo.convergedFlag；</li>
 *   <li>调用 {@link RoutingEntry#refreshReachable()} 刷新可达性，记录 reachable 变化的路由前缀
 *       converge-routes；</li>
 *   <li>若 reachable 发生变化，则遍历 chip C 上其他端口，通过 PortEntity.remoteDevice/remotePort
 *       定位对端转发节点及对应入接口 converge-port；</li>
 *   <li>在远端转发节点上定位 converge-port 所属 chip C'，在 "peerDevice#C'" 路由表中查询
 *       converge-routes，刷新其出端口为 converge-port 的 OutPortInfo 状态，并刷新 reachable；</li>
 *   <li>迭代直到没有转发节点的路由 reachable 变化需要传播。</li>
 * </ol>
 *
 * <p>查询与更新的路由对象均存放在 SNCService 持有的 instantiationRouteMap 中。
 */
public class RouteConvergeService {

    private static final Logger LOG = new Logger(RouteConvergeService.class);

    /**
     * 执行路由收敛。
     */
    public void converge(Map<String, Map<String, RoutingEntry>> instantiationRouteMap,
        SuperNode supernode, LinkEvent event) {

        ConvergeContext ctx = prepareContext(instantiationRouteMap, supernode, event);
        if (ctx == null) {
            return;
        }
        LOG.info("converge start: device=%s, port=%s, isDown=%s, routeMapSize=%d",
            ctx.startDevice, ctx.startPort, ctx.isDown, ctx.instantiationRouteMap.size());

        Queue<ConvergeTask> queue = new LinkedList<>();
        Set<String> visited = new HashSet<>();
        visited.add(visitKey(ctx.startDevice, ctx.startPort));

        // 在本地 chip 路由表中扫描事件端口，得到起始节点可达性变化的前缀集合
        Set<String> startChanged = processLocalChip(ctx, ctx.startDevice, ctx.startChipIndex, ctx.startPort);
        if (startChanged.isEmpty()) {
            LOG.info("converge finished: device=%s, port=%s, no reachable change on start", ctx.startDevice, ctx.startPort);
            return;
        }
        queue.offer(new ConvergeTask(ctx, ctx.startDevice, ctx.startPort, ctx.startChipIndex, startChanged));

        while (!queue.isEmpty()) {
            ConvergeTask task = queue.poll();
            LOG.info("converge propagate: device=%s, inPort=%s, isDown=%s, changedPrefixCount=%d",
                task.device, task.inPort, ctx.isDown, task.changedPrefixes.size());
            propagateToPeers(task, queue, visited);
        }
        LOG.info("converge finished: device=%s, port=%s, visitedCount=%d", ctx.startDevice, ctx.startPort, visited.size());
    }

    /**
     * 校验入参并构造 ConvergeContext；返回 null 表示无需收敛。
     */
    private ConvergeContext prepareContext(Map<String, Map<String, RoutingEntry>> routeMap,
        SuperNode supernode, LinkEvent event) {

        if (routeMap == null || supernode == null || event == null) {
            LOG.error("converge: error=params must not be null");
            throw new IllegalArgumentException("converge params must not be null");
        }
        String eventType = event.getEventType();
        if (!LinkEvent.LINK_STATUS_UP.equals(eventType) && !LinkEvent.LINK_STATUS_DOWN.equals(eventType)) {
            LOG.error("converge: error=invalid eventType=%s, expected=up|down", eventType);
            throw new IllegalArgumentException("invalid eventType: " + eventType + ", expected: up|down");
        }

        String startDevice = event.getDeviceName();
        String startPort = event.getPortName();
        ForwardingChip startChip = findChipByPort(supernode, startDevice, startPort);
        if (startChip == null) {
            LOG.error("converge: error=port not found, device=%s, port=%s", startDevice, startPort);
            throw new IllegalStateException(
                "Port not found: " + startPort + " in device " + startDevice);
        }
        Integer startChipIndex = startChip.getChipIndex();
        if (startChipIndex == null) {
            LOG.error("converge: error=chipIndex is null, device=%s, port=%s", startDevice, startPort);
            throw new IllegalStateException("chipIndex is null for port " + startPort);
        }
        return new ConvergeContext(routeMap, supernode,
            LinkEvent.LINK_STATUS_DOWN.equals(eventType), startDevice, startPort, startChipIndex);
    }

    /**
     * 在本节点 "device#chipIndex" 的路由表中，刷新出端口 == portName 的
     * OutPortInfo，刷新所属 RoutingEntry.reachable，返回 reachable 变化的前缀集合。
     */
    private Set<String> processLocalChip(ConvergeContext ctx, String device, int chipIndex, String portName) {
        return updateOutPortOnChip(ctx.instantiationRouteMap, device, chipIndex, portName, ctx.isDown);
    }

    /**
     * 在 task.chipIndex 这一个 chip 上遍历其他端口（跳过接收传播的入端口 task.inPort，
     * 避免往回传播给上游节点），通过端口拓扑找到对端 (peerDevice, peerPort)，
     * 在对端 peerPort 所属 chip 上传播收敛状态；reachable 变化的对端任务入队继续 BFS。
     */
    private void propagateToPeers(ConvergeTask task, Queue<ConvergeTask> queue, Set<String> visited) {
        ConvergeContext ctx = task.ctx;
        ForwardingChip chip = getChipByIndex(ctx.supernode, task.device, task.chipIndex);
        if (chip == null || chip.getPorts() == null) {
            LOG.warn("converge: device=%s, chip=%d, warning=chip or ports null, skip peer lookup",
                task.device, task.chipIndex);
            return;
        }
        for (PortEntity port : chip.getPorts().values()) {
            if (port == null || task.inPort.equals(port.getPortName())) {
                continue;
            }
            // 跳过链路状态为 down 的端口：down 端口无法将本节点可达性传递给对端
            if (LinkEvent.LINK_STATUS_DOWN.equals(port.getLinkStatus())) {
                LOG.debug("converge: skip down port, device=%s, port=%s",
                    task.device, port.getPortName());
                continue;
            }
            String peerDevice = port.getRemoteDevice();
            String peerPort = port.getRemotePort();
            if (peerDevice == null || peerDevice.isEmpty() || peerPort == null || peerPort.isEmpty()) {
                continue;
            }
            String visitKey = visitKey(peerDevice, peerPort);
            if (!visited.add(visitKey)) {
                continue;
            }
            propagateToPeer(task, peerDevice, peerPort, queue);
        }
    }

    /**
     * 在单个对端 (peerDevice, peerPort) 上传播：定位 peerPort 所属 chip，
     * 在 "peerDevice#peerChipIndex" 路由表中查询 converge-routes 刷新出端口收敛状态；
     * 若 reachable 变化则入队继续 BFS。
     */
    private void propagateToPeer(ConvergeTask task, String peerDevice, String peerPort,
        Queue<ConvergeTask> queue) {
        ConvergeContext ctx = task.ctx;
        ForwardingChip peerChip = findChipByPort(ctx.supernode, peerDevice, peerPort);
        if (peerChip == null || peerChip.getChipIndex() == null) {
            LOG.warn("converge: peerDevice=%s, peerPort=%s, warning=peer chip not found, skip",
            peerDevice, peerPort);
            return;
        }
        int peerChipIndex = peerChip.getChipIndex();
        Set<String> peerRouteChanged = updateOutPortOnChipByPrefixes(ctx.instantiationRouteMap, peerDevice,
            peerChipIndex, peerPort, task.changedPrefixes, ctx.isDown);
        if (!peerRouteChanged.isEmpty()) {
            LOG.info("converge: peerChanged, peerDevice=%s, peerPort=%s, peerChip=%d, count=%d",
                peerDevice, peerPort, peerChipIndex, peerRouteChanged.size());
            // 携带本节点可达性变化的前缀集合，传递给下一跳对端作为待检查范围；
            // 对端入接口已在上面的 updateOutPortOnChipByPrefixes 中更新完毕，无需重复扫描
            queue.offer(new ConvergeTask(ctx, peerDevice, peerPort, peerChipIndex, peerRouteChanged));
        }
    }

    /**
     * 在指定 device 的指定 chip 路由表中，找到出端口为 portName 的 OutPortInfo，
     * 修改其 convergedFlag，并刷新所属 RoutingEntry 的 reachable。
     *
     * @return reachable 发生变化的路由前缀集合
     */
    private Set<String> updateOutPortOnChip(Map<String, Map<String, RoutingEntry>> routeMap, String deviceName, 
        int chipIndex, String portName, boolean isDown) {

        Set<String> changedPrefixes = new HashSet<>();
        Map<String, RoutingEntry> routes = routeMap.get(routeKey(deviceName, chipIndex));
        if (routes == null) {
            return changedPrefixes;
        }
        for (Map.Entry<String, RoutingEntry> routeEntry : routes.entrySet()) {
            RoutingEntry routingEntry = routeEntry.getValue();
            if (routingEntry == null) {
                continue;
            }
            Map<String, OutPortInfo> outPorts = routingEntry.getMutableOutPortInfos();
            if (outPorts == null) {
                continue;
            }
            OutPortInfo outPort = outPorts.get(portName);
            if (outPort == null) {
                continue;
            }
            if (applyConverge(outPort, routingEntry, isDown)) {
                changedPrefixes.add(routeEntry.getKey());
            }
        }
        return changedPrefixes;
    }

    /**
     * 在指定 device 的指定 chip 路由表中，查询前缀属于 prefixes 的路由，
     * 刷新其中出端口为 portName 的 OutPortInfo 状态，并刷新 RoutingEntry.reachable。
     *
     * @return reachable 发生变化的路由前缀集合
     */
    private Set<String> updateOutPortOnChipByPrefixes(Map<String, Map<String, RoutingEntry>> routeMap, 
        String deviceName, int chipIndex, String portName, Set<String> prefixes, boolean isDown) {

        Set<String> changedPrefixes = new HashSet<>();
        Map<String, RoutingEntry> routes = routeMap.get(routeKey(deviceName, chipIndex));
        if (routes == null) {
            return changedPrefixes;
        }
        for (String prefix : prefixes) {
            RoutingEntry routingEntry = routes.get(prefix);
            if (routingEntry == null) {
                continue;
            }
            Map<String, OutPortInfo> outPorts = routingEntry.getMutableOutPortInfos();
            if (outPorts == null) {
                continue;
            }
            OutPortInfo outPort = outPorts.get(portName);
            if (outPort == null) {
                continue;
            }
            if (applyConverge(outPort, routingEntry, isDown)) {
                changedPrefixes.add(prefix);
            }
        }
        return changedPrefixes;
    }

    /**
     * 修改 OutPortInfo 的 convergedFlag（down=按位或 PASSIVE，up=清 PASSIVE），
     * 然后刷新 RoutingEntry.reachable，返回 reachable 是否发生变化。
     */
    private boolean applyConverge(OutPortInfo outPort, RoutingEntry routingEntry, boolean isDown) {
        boolean oldReachable = routingEntry.isReachable();
        if (isDown) {
            outPort.setFlag(OutPortInfo.FLAG_PASSIVE_CONVERRGED);
        } else {
            outPort.clearFlag(OutPortInfo.FLAG_PASSIVE_CONVERRGED);
        }
        routingEntry.refreshReachable();
        return routingEntry.isReachable() != oldReachable;
    }

    /**
     * 在指定设备的所有 forwardingChip 中，找到包含 portName 的那个 chip。
     * 返回 null 表示端口不存在。
     */
    private ForwardingChip findChipByPort(SuperNode supernode, String deviceName, String portName) {
        if (supernode == null || deviceName == null || portName == null) {
            return null;
        }
        DeviceEntity device = supernode.getAllDevices().get(deviceName);
        if (device == null || device.getForwardingChips() == null) {
            return null;
        }
        for (ForwardingChip chip : device.getForwardingChips().values()) {
            if (chip == null || chip.getPorts() == null) {
                continue;
            }
            if (chip.getPorts().containsKey(portName)) {
                return chip;
            }
        }
        return null;
    }

    /**
     * 获取指定 device 上指定 chipIndex 的 ForwardingChip，找不到返回 null。
     */
    private ForwardingChip getChipByIndex(SuperNode supernode, String deviceName, int chipIndex) {
        if (supernode == null || deviceName == null) {
            return null;
        }
        DeviceEntity device = supernode.getAllDevices().get(deviceName);
        if (device == null || device.getForwardingChips() == null) {
            return null;
        }
        return device.getForwardingChips().get(chipIndex);
    }

    private static String routeKey(String deviceName, int chipIndex) {
        return RouteInstantiationService.buildRouteTableKey(deviceName, chipIndex);
    }

    private static String visitKey(String device, String port) {
        return device + RouteInstantiationService.KEY_SEPARATOR + port;
    }

    /**
     * 一次收敛的上下文：承载整个 BFS 过程中不变的输入和参数，避免方法间长参数列表。
     */
    private static final class ConvergeContext {
        private final Map<String, Map<String, RoutingEntry>> instantiationRouteMap;
        private final SuperNode supernode;
        private final boolean isDown;
        private final String startDevice;
        private final String startPort;
        private final int startChipIndex;

        ConvergeContext(Map<String, Map<String, RoutingEntry>> instantiationRouteMap,
                        SuperNode supernode, boolean isDown,
                        String startDevice, String startPort, int startChipIndex) {
            this.instantiationRouteMap = instantiationRouteMap;
            this.supernode = supernode;
            this.isDown = isDown;
            this.startDevice = startDevice;
            this.startPort = startPort;
            this.startChipIndex = startChipIndex;
        }
    }

    /**
     * BFS 任务：携带本节点收敛上下文 ctx、device、接收传播的入端口 inPort、inPort 所属 chipIndex，
     * 以及本节点可达性变化的前缀集合 changedPrefixes，保证只在该 chip 范围内做收敛与传播，
     * 并仅向对端传播上游变化的前缀范围。
     *
     * <p>inPort 语义：起始任务为 link 事件端口（接收外部事件的"入端口"），
     * 传播任务为对端转发节点接收上游传播的入接口。在 {@link #propagateToPeers} 遍历
     * chip 所有端口时跳过 inPort，避免往回传播给上游节点。
     *
     * <p>初始任务的 changedPrefixes 由 {@link #processLocalChip} 在入队前计算；
     * 传播任务的 changedPrefixes 由 {@link #propagateToPeer} 在入队前通过对端入接口
     * OutPortInfo 更新后得到。所有任务的 changedPrefixes 均不为 null。
     */
    private static final class ConvergeTask {
        private final ConvergeContext ctx;
        private final String device;
        private final String inPort;
        private final int chipIndex;
        private final Set<String> changedPrefixes;

        ConvergeTask(ConvergeContext ctx, String device, String inPort, int chipIndex, Set<String> changedPrefixes) {
            this.ctx = ctx;
            this.device = device;
            this.inPort = inPort;
            this.chipIndex = chipIndex;
            this.changedPrefixes = changedPrefixes;
        }
    }
}
