/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: active drain service
 * Create: 2026-11-05
 * Note:
 * History: 2026-11-05  Create File
 */

package com.huawei.umdk.snc.route.service;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import com.huawei.umdk.snc.entity.ConvergedNodeRoute;
import com.huawei.umdk.snc.entity.ConvergedPrefix;
import com.huawei.umdk.snc.entity.ConvergedRouteResult;
import com.huawei.umdk.snc.entity.DeviceEntity;
import com.huawei.umdk.snc.entity.DrainEvent;
import com.huawei.umdk.snc.entity.ForwardingChip;
import com.huawei.umdk.snc.entity.OutPortInfo;
import com.huawei.umdk.snc.entity.PortEntity;
import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import com.huawei.umdk.snc.entity.RoutingTable;
import com.huawei.umdk.snc.entity.SuperNode;
import com.huawei.umdk.snc.log.Logger;
import com.huawei.umdk.snc.route.model.ChipRef;
import com.huawei.umdk.snc.route.model.MergedNotice;
import com.huawei.umdk.snc.route.model.MergedPrefix;
import com.huawei.umdk.snc.route.model.NoticeTask;
import com.huawei.umdk.snc.route.model.ChipNode;
import com.huawei.umdk.snc.route.model.DrainContext;

public class ActiveDrainService {

    private static final Logger LOG = new Logger(ActiveDrainService.class);

    private Map<String, ChipNode> getStartNodeForDeviceDrain(SuperNode supernode, String deviceName) {
        Map<String, ChipNode> chipMap = new HashMap<>();
        DeviceEntity device = supernode.getAllDevices().get(deviceName);
        if (device == null) {
            LOG.error("device not found, device=%s", deviceName);
            throw new IllegalArgumentException("device not found: " + deviceName);
        }

        Set<String> peerDevices = findPeerDevices(device);
        Set<String> excludePeerChipKeys = allChipKeys(device, deviceName);
        for (String peerName : peerDevices) {
            DeviceEntity peer = supernode.getAllDevices().get(peerName);
            if (peer == null) {
                throw new IllegalArgumentException("device not found: " + peerName);
            }
            for (ForwardingChip chip : peer.getForwardingChips().values()) {
                if (chip == null || chip.getPorts() == null || chip.getChipIndex() == null) {
                    continue;
                }
                for (PortEntity port : chip.getPorts().values()) {
                    if (port != null && deviceName.equals(port.getRemoteDevice())) {
                        ChipRef chipRef = new ChipRef(peerName, chip.getChipIndex());
                        ChipNode chipNode = chipMap.computeIfAbsent(chipRef.routeKey(),
                            k -> new ChipNode(chipRef, excludePeerChipKeys));
                        chipNode.getInPorts().add(port.getPortName());
                    }
                }
            }
        }

        return chipMap;
    }

    /**
     * 设备排流：将指定设备（仅交换机）承载的流量整体切走/切回。
     * 被切设备自身的路由不处理；对其每个对端设备上朝向该设备的端口按芯片分组，逐芯片起始计算。
     *
     * @param supernode 超节点拓扑（非空，芯片路由表已实例化）
     * @param event     设备排流事件（非空）
     * @return 收敛明细（不为 null，routeMap 可能为空 Map，key=设备名）
     */
    public ConvergedRouteResult drainDevice(SuperNode supernode, DrainEvent event) {
        String deviceName = event.getDeviceName();
        if (supernode.getSwDevices() == null || !supernode.getSwDevices().containsKey(deviceName)) {
            LOG.error("only sw device supports drain, device=%s", deviceName);
            throw new IllegalArgumentException(
                "only sw device supports drain, device=" + deviceName);
        }

        DrainContext ctx = new DrainContext(supernode, event.getAction());
        LOG.info("drain device start: device=%s, action=%s, event type=%s", deviceName, event.getAction(),
            event.getEventType());

        Map<String, ChipNode> chipNodeMap = getStartNodeForDeviceDrain(supernode, event.getDeviceName());
        for (Map.Entry<String, ChipNode> en : chipNodeMap.entrySet()) {
            ChipNode start = en.getValue();
            computeStartNode(ctx, start.getChipRef().getDevice(), start.getChipRef().getChipIndex(),
                start.getInPorts(), start.getExcludeChips());
        }

        ConvergedRouteResult result = propagateAndCollect(ctx);
        LOG.info("switchDevice finished: device=%s, action=%s, changeCount=%d",
            deviceName, event.getAction(), result.getRouteMap().size());
        return result;
    }

    private Map<String, ChipNode> getStartNodeForLinkDrain(SuperNode supernode, String deviceName,
                                                           Set<String> portNames) {
        Map<String, ChipNode> chipMap = new HashMap<>();
        String peerDevice = null; // 对端设备（必须唯一）
        for (String portName : portNames) {
            ChipRef local = locateChipByPort(supernode, deviceName, portName);
            PortEntity port = findPort(supernode, deviceName, portName);
            if (port == null) {
                throw new IllegalArgumentException(
                    String.format("deviceName %s portName %s not found", deviceName, portName));
            }

            if (peerDevice == null) {
                if (port.getRemoteDevice() == null) {
                    throw new IllegalArgumentException("port " + portName + " has no remote device");
                }
                peerDevice = port.getRemoteDevice();
            } else if (!peerDevice.equals(port.getRemoteDevice())) {
                LOG.error("All ports must peer the same device, expected: "
                    + peerDevice + ", but port " + portName + " peers: " + port.getRemoteDevice());
                throw new IllegalArgumentException("All ports must peer the same device, expected: "
                    + peerDevice + ", but port " + portName + " peers: " + port.getRemoteDevice());
            }
            ChipRef remote = locateChipByPort(supernode, port.getRemoteDevice(), port.getRemotePort());
            ChipNode localNode = chipMap.computeIfAbsent(local.routeKey(), k -> new ChipNode(local));
            localNode.getExcludeChips().add(remote.routeKey());
            localNode.getInPorts().add(portName);

            ChipNode remoteNode = chipMap.computeIfAbsent(remote.routeKey(), k -> new ChipNode(remote));
            remoteNode.getExcludeChips().add(local.routeKey());
            remoteNode.getInPorts().add(port.getRemotePort());
        }
        return chipMap;
    }

    /**
     * 链路排流：对本端 portNames 与其共同对端设备之间的若干条链路执行切走/切回。
     * 事件仅携带本端 deviceName + portNames，对端设备/端口由 SuperNode 拓扑查询；
     * 所有端口的对端须为同一个设备，本端与对端各自按涉及芯片分组起始计算。
     *
     * @param supernode 超节点拓扑（非空，芯片路由表已实例化）
     * @param event     排流事件（非空，portNames 非空、无 null 元素）
     * @return 收敛明细（不为 null，routeMap 可能为空 Map，key=设备名）
     */
    public ConvergedRouteResult drainLinks(SuperNode supernode, DrainEvent event) {
        Set<String> portNames = event.getPortNames();
        if (portNames == null || portNames.isEmpty()) {
            LOG.error("portNames must not be null or empty");
            throw new IllegalArgumentException("portNames must not be null or empty");
        }
        for (String portName : portNames) {
            if (portName == null) {
                LOG.error("portName must not be null");
                throw new IllegalArgumentException("portName must not be null");
            }
        }
        String deviceName = event.getDeviceName();
        LOG.info("drain link start: device=%s action=%s event type=%s ports=%s, ",
            deviceName, event.getAction(), event.getEventType(), portNames);

        DrainContext ctx = new DrainContext(supernode, event.getAction());
        Map<String, ChipNode> chipNodeMap = getStartNodeForLinkDrain(supernode, deviceName, portNames);
        for (Map.Entry<String, ChipNode> en : chipNodeMap.entrySet()) {
            ChipNode start = en.getValue();
            computeStartNode(ctx, start.getChipRef().getDevice(), start.getChipRef().getChipIndex(),
                start.getInPorts(), start.getExcludeChips());
        }

        ConvergedRouteResult result = propagateAndCollect(ctx);
        LOG.info("switchLinks finished: device=%s, portCount=%d, action=%s, changeCount=%d",
            deviceName, portNames.size(), event.getAction(), result.getRouteMap().size());
        return result;
    }

    /**
     * 起始节点计算
     *
     * @param ctx                 切流上下文
     * @param device              起始计算节点所在设备名
     * @param chipIndex           起始计算节点的芯片号
     * @param excludedPorts       被切端口集合
     * @param excludePeerChipKeys 起始通告需排除的对端芯片方向
     */
    private void computeStartNode(DrainContext ctx, String device, int chipIndex,
                                  Set<String> excludedPorts, Set<String> excludePeerChipKeys) {
        Map<RoutePrefix, RoutingEntry> routes = getChipRoutes(ctx, device, chipIndex);
        LOG.info("start to compute device %s chip %s port size %d route prefix size %d", device, chipIndex,
            excludedPorts.size(), routes.size());
        Set<RoutePrefix> toNotice = computeNode(ctx, device, chipIndex, excludedPorts, routes.keySet());
        if (!toNotice.isEmpty()) {
            noticePeers(ctx, device, chipIndex, toNotice, excludePeerChipKeys);
            LOG.info("compute device %s chip %d notice prefix size %d",
                device, chipIndex, toNotice.size());
        }
        LOG.info("compute device %s chip %s local result port size %d", device, chipIndex,
            ctx.getChangeMap().get(device) == null ? 0 : ctx.getChangeMap().get(device).getPortPrefixes().size());
    }

    /**
     * 节点计算：在本芯片路由表范围内，对出接口命中 excludedPorts 的前缀判定可用性是否翻转——翻转的前缀进入通告集合，未翻转的前缀记录下来；
     * NPU 设备不产生通告。
     *
     * @param ctx           切流上下文
     * @param device        计算节点所在设备名
     * @param chipIndex     计算节点的芯片号
     * @param excludedPorts 被切端口集合：出接口命中该集合的前缀才参与计算
     * @param routePrefixes 参与计算的前缀范围（非空）
     * @return 需要继续通告的前缀集合：drain → 新不可达前缀；recovery → 恢复可达前缀
     */
    private Set<RoutePrefix> computeNode(DrainContext ctx, String device, int chipIndex,
                                         Set<String> excludedPorts, Set<RoutePrefix> routePrefixes) {
        Set<RoutePrefix> toNotice = new HashSet<>();
        Map<RoutePrefix, RoutingEntry> routes = getChipRoutes(ctx, device, chipIndex);
        Map<String, ? extends PortEntity> chipPorts = getChipPorts(ctx.getSupernode(), device, chipIndex);
        if (chipPorts == null || chipPorts.isEmpty()) {
            throw new IllegalArgumentException(String.format("device %s chip %d chipPorts must not be null or empty",
                device, chipIndex));
        }
        for (RoutePrefix routePrefix : routePrefixes) {
            RoutingEntry routingEntry = routes.get(routePrefix);
            if (routingEntry == null || routingEntry.getOutPortInfos() == null) {
                continue;
            }
            // 受影响判定：任意 1 个出接口落在 excludedPorts 中即受影响
            Set<String> hitPorts = new HashSet<>(routingEntry.getOutPortInfos().keySet());
            // 获取hitPorts和excludedPorts两个集合的交集，结果放到hitPorts
            hitPorts.retainAll(excludedPorts);
            if (hitPorts.isEmpty()) {
                continue;
            }

            if (checkPropagationNeeded(ctx, routingEntry, chipPorts, hitPorts)) {
                toNotice.add(routingEntry.getPrefix());
                applyNoticeConvergence(ctx, device, routingEntry, hitPorts);
            } else {
                applyLocalConvergence(ctx, device, routingEntry, hitPorts);
            }
        }

        if (ctx.getSupernode().getNpuDevices().get(device) != null) {
            toNotice.clear();
        }
        return toNotice;
    }

    /**
     * 判定单条路由切流前后可用性是否翻转：
     * 切流时判断：
     *     oldUsable：查看路由的所有端口，是否可用
     *     newUsable：去掉相关端口，是否可用
     * 恢复时判断：
     *     oldUsable：去掉相关端口，是否可用
     *     newUsable：查看路由的所有端口，是否可用(忽略端口的drain状态)
     *
     * @param ctx          切流上下文（提供 drain/recovery 方向）
     * @param routingEntry 待判定的路由
     * @param chipPorts    本芯片端口表
     * @param hitPorts     该路由受影响的出接口集合
     * @return true = 可用性翻转，需要通告传播；false = 未翻转，本地收敛
     */
    private boolean checkPropagationNeeded(DrainContext ctx, RoutingEntry routingEntry,
                                           Map<String, ? extends PortEntity> chipPorts, Set<String> hitPorts) {
        boolean oldUsable;
        boolean newUsable;
        if (DrainEvent.ACTION_DISABLE.equals(ctx.getAction())) {
            oldUsable = hasUsableOutPort(routingEntry, chipPorts, new HashSet<>(), false);
            newUsable = hasUsableOutPort(routingEntry, chipPorts, hitPorts, false);
        } else {
            oldUsable = hasUsableOutPort(routingEntry, chipPorts, hitPorts, false);
            newUsable = hasUsableOutPort(routingEntry, chipPorts, new HashSet<>(), true);
        }

        return (oldUsable != newUsable);
    }

    private void applyLocalConvergence(DrainContext ctx, String device,
                                       RoutingEntry routingEntry, Set<String> hitPorts) {
        ConvergedNodeRoute nodeRoute = ctx.getChangeMap().computeIfAbsent(device, k -> new ConvergedNodeRoute());
        nodeRoute.setDeviceName(device);
        nodeRoute.setAction(ctx.getAction());
        for (String portName : hitPorts) {
            nodeRoute.addPrefix(portName, routingEntry.getPrefix());
        }
    }

    private void applyNoticeConvergence(DrainContext ctx, String device,
                                        RoutingEntry routingEntry, Set<String> hitPorts) {
        ConvergedNodeRoute nodeRoute = ctx.getNoticeMap().computeIfAbsent(device, k -> new ConvergedNodeRoute());
        nodeRoute.setDeviceName(device);
        nodeRoute.setAction(ctx.getAction());
        for (String portName : hitPorts) {
            nodeRoute.addPrefix(portName, routingEntry.getPrefix());
        }
    }

    /**
     * 判定路由是否存在可用出接口
     *
     * @param routingEntry 待判定的路由
     * @param chipPorts    本芯片端口表
     * @param hitPorts     需跳过的出接口集合（本次切流受影响端口）
     * @param ignoreDrainStatus 忽略端口的drain状态，端口按照没有drain来处理
     */
    private boolean hasUsableOutPort(RoutingEntry routingEntry,
        Map<String, ? extends PortEntity> chipPorts, Set<String> hitPorts, boolean ignoreDrainStatus) {
        for (Map.Entry<String, OutPortInfo> portEntry : routingEntry.getOutPortInfos().entrySet()) {
            PortEntity portEntity = chipPorts.get(portEntry.getKey());
            if (portEntity == null) {
                throw new IllegalArgumentException(portEntry.getKey() + " port entry must not be null");
            }
            if (hitPorts.contains(portEntry.getKey())) {
                continue;
            }
            boolean isDrained = portEntity.isDrained();
            if (ignoreDrainStatus) {
                isDrained = false;
            }
            if (isDrained) {
                continue;
            }
            return true;
        }
        return false;
    }

    private Map<String, ? extends PortEntity> getChipPorts(SuperNode supernode, String device,
        int chipIndex) {
        ForwardingChip chip = supernode.getChipByIndex(device, chipIndex);
        return chip == null ? null : chip.getPorts();
    }

    /**
     * 芯片级通告：遍历本芯片全部端口，将对端端口按所属芯片分组聚合，向每个对端芯片构造
     * 一个 NoticeTask；排除 excludePeerChipKeys 指定的芯片
     * （回传保护），notified 通告边去重。
     */
    private void noticePeers(DrainContext ctx, String device, int chipIndex,
                             Set<RoutePrefix> prefixes, Set<String> excludePeerChipKeys) {
        ForwardingChip chip = ctx.getSupernode().getChipByIndex(device, chipIndex);
        if (chip == null || chip.getPorts() == null) {
            LOG.warn("noticePeers: device=%s, chip=%d, warning=chip or ports null, skip notice",
                device, chipIndex);
            return;
        }

        // 按对端芯片分组聚合入接口集合
        Map<ChipRef, ChipNode> peerChips = new HashMap<>();
        for (PortEntity port : chip.getPorts().values()) {
            String peerDevice = port.getRemoteDevice();
            String peerPort = port.getRemotePort();
            ChipRef peerChip = locateChipByPort(ctx.getSupernode(), peerDevice, peerPort);
            if (excludePeerChipKeys.contains(peerChip.routeKey())) {
                // 回传保护
                continue;
            }
            peerChips.computeIfAbsent(peerChip, k -> new ChipNode(peerChip)).getInPorts().add(peerPort);
        }

        // notified 通告边去重（芯片级 from→to#prefix），通过去重的前缀合并为一个任务
        String fromKey = routeKey(device, chipIndex);
        for (Map.Entry<ChipRef, ChipNode> entry : peerChips.entrySet()) {
            Set<RoutePrefix> noticed = new HashSet<>();
            for (RoutePrefix prefix : prefixes) {
                if (ctx.getNotified().add(noticeKey(fromKey, entry.getKey().routeKey(), prefix))) {
                    noticed.add(prefix);
                }
            }
            if (noticed.isEmpty()) {
                continue;
            }
            ctx.getQueue().offer(new NoticeTask(new ChipRef(device, chipIndex),
                entry.getKey(), entry.getValue().getInPorts(), noticed));
        }
    }

    /**
     * 汇总收敛结果：将 SuperNode 各芯片路由表统计为 设备 → 出接口 → 前缀集合
     * @param ctx 切流上下文（提供路由表来源与 changeMap/noticeMap）
     * @return 收敛明细（key=设备名）
     */
    private ConvergedRouteResult collectResult(DrainContext ctx) {
        // 1. 统计全网路由：device → portName → 前缀集合
        Map<String, Map<String, Set<RoutePrefix>>> totalRoutes = new LinkedHashMap<>();
        for (Map.Entry<String, DeviceEntity> devEn : ctx.getSupernode().getAllDevices().entrySet()) {
            DeviceEntity device = devEn.getValue();
            if (device == null || device.getForwardingChips() == null) {
                continue;
            }
            for (ForwardingChip chip : device.getForwardingChips().values()) {
                if (chip == null || chip.getRoutingTable() == null
                    || chip.getRoutingTable().getRoutes() == null) {
                    continue;
                }
                for (RoutingEntry entry : chip.getRoutingTable().getRoutes().values()) {
                    if (entry == null || entry.getOutPortInfos() == null || entry.getPrefix() == null) {
                        continue;
                    }
                    for (String portName : entry.getOutPortInfos().keySet()) {
                        totalRoutes.computeIfAbsent(devEn.getKey(), k -> new LinkedHashMap<>())
                            .computeIfAbsent(portName, k -> new HashSet<>())
                            .add(entry.getPrefix());
                    }
                }
            }
        }

        // 2. 逐设备、逐出接口对比：路由表前缀数 == changeMap + noticeMap 记录数之和
        //    → 该出接口全部路由已收敛，allConverged 置 true
        for (Map.Entry<String, ConvergedNodeRoute> en : ctx.getChangeMap().entrySet()) {
            String deviceName = en.getKey();
            Map<String, Set<RoutePrefix>> portRoutes = totalRoutes.get(deviceName);
            if (portRoutes == null) {
                throw new IllegalArgumentException("device " + deviceName + " not found route");
            }
            ConvergedNodeRoute noticed = ctx.getNoticeMap().get(deviceName);
            for (Map.Entry<String, ConvergedPrefix> portEn : en.getValue().getPortPrefixes().entrySet()) {
                String portName = portEn.getKey();
                int total = portRoutes.containsKey(portName) ? portRoutes.get(portName).size() : 0;
                int changed = portEn.getValue().getRoutePrefixes().size();
                int noticedCount = noticed != null && noticed.getPortPrefixes().containsKey(portName)
                    ? noticed.getPortPrefixes().get(portName).getRoutePrefixes().size() : 0;
                if (changed + noticedCount == total) {
                    portEn.getValue().setAllConverged(true);
                }
            }
        }

        return new ConvergedRouteResult(ctx.getChangeMap());
    }

    /**
     * 通告传播循环（逐层处理）：每轮取出队列中的全部任务，按目标芯片合并，合并后
     * 逐芯片、逐前缀计算，翻转的前缀继续通告，新产生的通告进入队列在下一轮处理，直至队列清空。
     *
     * @return 收敛明细（key=设备名）
     */
    private ConvergedRouteResult propagateAndCollect(DrainContext ctx) {
        while (!ctx.getQueue().isEmpty()) {
            // 1. 取出本层全部任务，按目标芯片 → 地址前缀合并（同一前缀的入接口、通告来源芯片取并集）
            Map<String, MergedNotice> layer = new LinkedHashMap<>();
            while (!ctx.getQueue().isEmpty()) {
                NoticeTask task = ctx.getQueue().poll();
                layer.computeIfAbsent(task.getToChip().routeKey(),
                    k -> new MergedNotice(task.getToChip())).merge(task);
            }
            // 2. 逐芯片、逐前缀统一处理
            for (MergedNotice notice : layer.values()) {
                String device = notice.getChip().getDevice();
                int chipIndex = notice.getChip().getChipIndex();
                LOG.info("compute device %s chip %s", device, chipIndex);
                for (Map.Entry<RoutePrefix, MergedPrefix> en : notice.getPrefixes().entrySet()) {
                    MergedPrefix merged = en.getValue();
                    Set<RoutePrefix> toNotice = computeNode(ctx, device, chipIndex,
                        merged.getInPorts(), Collections.singleton(en.getKey()));
                    if (toNotice.isEmpty()) {
                        continue;
                    }
                    noticePeers(ctx, device, chipIndex, toNotice, merged.getFromChips());
                }
                LOG.info("compute device %s chip %d record port size %d notice port size %d",
                    device, chipIndex,
                    ctx.getChangeMap().get(device) == null ? 0 : ctx.getChangeMap().get(device).getPortPrefixes().size(),
                    ctx.getNoticeMap().get(device) == null ? 0 : ctx.getNoticeMap().get(device).getPortPrefixes().size());
            }
        }
        return collectResult(ctx);
    }

    /**
     * 定位端口所属芯片
     */
    private ChipRef locateChipByPort(SuperNode supernode, String deviceName, String portName) {
        ForwardingChip chip = supernode.getChipByPortName(deviceName, portName);
        if (chip == null || chip.getChipIndex() == null) {
            LOG.error("chip not found, device=%s, port=%s", deviceName, portName);
            throw new IllegalArgumentException(
                "chip not found: " + portName + " in device " + deviceName);
        }
        return new ChipRef(deviceName, chip.getChipIndex());
    }

    /**
     * 收集设备的全部对端设备名。
     */
    private Set<String> findPeerDevices(DeviceEntity device) {
        Set<String> peers = new TreeSet<>();
        for (ForwardingChip chip : device.getForwardingChips().values()) {
            if (chip == null || chip.getPorts() == null) {
                continue;
            }
            for (PortEntity port : chip.getPorts().values()) {
                if (port != null && port.getRemoteDevice() != null && !port.getRemoteDevice().isEmpty()) {
                    peers.add(port.getRemoteDevice());
                }
            }
        }
        return peers;
    }

    private Set<String> allChipKeys(DeviceEntity device, String deviceName) {
        Set<String> keys = new HashSet<>();
        for (ForwardingChip chip : device.getForwardingChips().values()) {
            if (chip != null && chip.getChipIndex() != null) {
                keys.add(routeKey(deviceName, chip.getChipIndex()));
            }
        }
        return keys;
    }

    /**
     * 获取指定芯片的路由表
     */
    private Map<RoutePrefix, RoutingEntry> getChipRoutes(DrainContext ctx, String device,
                                                         int chipIndex) {
        ForwardingChip chip = ctx.getSupernode().getChipByIndex(device, chipIndex);
        if (chip == null) {
            throw new IllegalArgumentException(String.format("device %s chip %d not found",device, chipIndex));
        }
        RoutingTable routingTable = chip.getRoutingTable();
        Map<RoutePrefix, RoutingEntry> routes = routingTable == null ? null : routingTable.getRoutes();
        if (routes == null) {
            LOG.error("route is null, device=%s, chip=%d",
                device, chipIndex);
            throw new IllegalArgumentException(routeKey(device, chipIndex) + " route is null ");
        }
        return routes;
    }

    private PortEntity findPort(SuperNode supernode, String deviceName, String portName) {
        ForwardingChip chip = supernode.getChipByPortName(deviceName, portName);
        return chip == null || chip.getPorts() == null ? null : chip.getPorts().get(portName);
    }

    private static String routeKey(String deviceName, int chipIndex) {
        return RouteInstantiationService.buildRouteTableKey(deviceName, chipIndex);
    }

    private static String noticeKey(String fromKey, String toKey, RoutePrefix prefix) {
        return fromKey + "->" + toKey + "#" + prefix.getDstAddress()
            + "/" + prefix.getMaskLength();
    }
}
