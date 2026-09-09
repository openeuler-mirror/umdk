/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: path engine test
 * Create: 2026-09-09
 * Note:
 */
package com.huawei.umdk.snc.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;

import com.huawei.umdk.snc.entity.*;
import com.huawei.umdk.snc.exception.SuperNodeNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("PathEngine")
class PathEngineTest {

    private PathEngine engine;

    @BeforeEach
    void setUp() {
        engine = new PathEngine();
    }

    @Test
    @DisplayName("resolveDirectPath creates 2-hop InternalPathInfo with correct src/dest EIDs")
    void resolveDirectPath() {
        NpuDevice npu1 = createNpu("NPU1", "eid1", "cna1", null, null);
        NpuDevice npu2 = createNpu("NPU2", "eid2", "cna2", null, null);

        NpuPortEntity srcPort = findPortOnNpu(npu1, "port1");
        NpuPortEntity destPort = findPortOnNpu(npu2, "port1");

        InternalPathInfo path = engine.resolveDirectPath(npu1, srcPort, npu2, destPort);

        assertEquals(2, path.getHops().size());
        assertEquals("eid1", path.getSrcEid());
        assertEquals("eid2", path.getDstEid());
        assertEquals("cna1", path.getSourceCna());
        assertEquals("cna2", path.getDestCna());

        InternalPathHop srcHop = path.getHops().get(0);
        assertEquals("NPU1", srcHop.getDeviceName());
        assertNull(srcHop.getInPort());
        assertEquals("port1", srcHop.getOutPort());
        assertEquals("eid1", srcHop.getEid());

        InternalPathHop destHop = path.getHops().get(1);
        assertEquals("NPU2", destHop.getDeviceName());
        assertEquals("port1", destHop.getInPort());
        assertNull(destHop.getOutPort());
        assertEquals("eid2", destHop.getEid());
    }

    @Test
    @DisplayName("resolveMultiHopPath creates 3-hop path with correct connections")
    void resolveMultiHopPath() {
        NpuDevice npu1 = createNpu("NPU1", "e1", "c1", "L1SW", "swPort1");
        NpuDevice npu2 = createNpu("NPU2", "e2", "c2", "L1SW", "swPort2");
        SwDevice sw = createSw("L1SW", "NPU2", "npu2Port1");

        NpuPortEntity srcPort = findPortOnNpu(npu1, "port1");
        NpuPortEntity destPort = findPortOnNpu(npu2, "port1");

        Map<String, String> interDevices = new HashMap<>();
        interDevices.put("L1SW", "swPort2");

        Map<String, DeviceEntity> allDevices = new HashMap<>();
        allDevices.put("NPU1", npu1);
        allDevices.put("L1SW", sw);
        allDevices.put("NPU2", npu2);

        InternalPathInfo path = engine.resolveMultiHopPath(npu1, srcPort, npu2, destPort,
            interDevices, allDevices);

        assertEquals(3, path.getHops().size());
        assertEquals("e1", path.getSrcEid());
        assertEquals("e2", path.getDstEid());

        InternalPathHop hop0 = path.getHops().get(0);
        assertEquals("NPU1", hop0.getDeviceName());
        assertNull(hop0.getInPort());
        assertEquals("port1", hop0.getOutPort());
        assertEquals("L1SW", hop0.getRemoteDevice());

        InternalPathHop hop1 = path.getHops().get(1);
        assertEquals("L1SW", hop1.getDeviceName());
        assertEquals("swPort2", hop1.getInPort());
        assertEquals("swPort2", hop1.getOutPort());
        assertEquals("NPU2", hop1.getRemoteDevice());

        InternalPathHop hop2 = path.getHops().get(2);
        assertEquals("NPU2", hop2.getDeviceName());
        assertEquals("port1", hop2.getInPort());
        assertNull(hop2.getOutPort());
    }

    @Test
    @DisplayName("resolveMultiHopPath throws SuperNodeNotFoundException when connection mismatches")
    void resolveMultiHopPath_connectionMismatch() {
        NpuDevice npu1 = createNpu("NPU1", "e1", "c1", "L1SW", "swPort1");
        NpuDevice npu2 = createNpu("NPU2", "e2", "c2", "L1SW", "swPort2");
        SwDevice sw = createSw("L1SW", "WRONG_DEVICE", "wrongPort");

        NpuPortEntity srcPort = findPortOnNpu(npu1, "port1");
        NpuPortEntity destPort = findPortOnNpu(npu2, "port1");

        Map<String, String> interDevices = Map.of("L1SW", "swPort2");
        Map<String, DeviceEntity> allDevices = Map.of("NPU1", npu1, "L1SW", sw, "NPU2", npu2);

        assertThrows(SuperNodeNotFoundException.class, () ->
            engine.resolveMultiHopPath(npu1, srcPort, npu2, destPort,
                interDevices, allDevices));
    }

    @Test
    @DisplayName("resolveMultiHopPath throws SuperNodeNotFoundException when device not found")
    void resolveMultiHopPath_deviceNotFound() {
        NpuDevice npu1 = createNpu("NPU1", "e1", "c1", "L1SW", "swPort1");
        NpuDevice npu2 = createNpu("NPU2", "e2", "c2", null, null);

        SwDevice sw = new SwDevice();
        sw.setSwitchLevel(SwitchLevel.L1);
        sw.setIndex(1);
        sw.setDeviceName("L1SW");
        sw.setForwardingChips(new HashMap<>());

        NpuPortEntity srcPort = findPortOnNpu(npu1, "port1");
        NpuPortEntity destPort = findPortOnNpu(npu2, "port1");

        Map<String, String> interDevices = Map.of("MISSING_DEV", "port1");
        Map<String, DeviceEntity> allDevices = Map.of("NPU1", npu1, "NPU2", npu2);

        assertThrows(SuperNodeNotFoundException.class, () ->
            engine.resolveMultiHopPath(npu1, srcPort, npu2, destPort,
                interDevices, allDevices));
    }

    @Test
    @DisplayName("reverseHops reverses order and swaps inPort/outPort")
    void reverseHops() {
        InternalPathHop h1 = new InternalPathHop();
        h1.setDeviceName("A");
        h1.setInPort("inA");
        h1.setOutPort("outA");
        h1.setCna("cna1");
        h1.setEid("eid1");
        h1.setRemoteDevice("B");
        h1.setRemotePort("inB");
        h1.setRack("rack1");
        h1.setHopIndex(0);

        InternalPathHop h2 = new InternalPathHop();
        h2.setDeviceName("B");
        h2.setInPort("inB");
        h2.setOutPort("outB");
        h2.setCna("cna2");
        h2.setEid("eid2");
        h2.setRemoteDevice("C");
        h2.setRemotePort("inC");
        h2.setRack("rack2");
        h2.setHopIndex(1);

        InternalPathHop h3 = new InternalPathHop();
        h3.setDeviceName("C");
        h3.setInPort("inC");
        h3.setOutPort("outC");
        h3.setCna("cna3");
        h3.setEid("eid3");
        h3.setRack("rack3");
        h3.setHopIndex(2);

        List<InternalPathHop> reversed = engine.reverseHops(List.of(h1, h2, h3));

        assertEquals(3, reversed.size());
        assertEquals("C", reversed.get(0).getDeviceName());
        assertEquals("outC", reversed.get(0).getInPort());
        assertEquals("inC", reversed.get(0).getOutPort());
        assertEquals("cna3", reversed.get(0).getCna());
        assertEquals(0, reversed.get(0).getHopIndex());

        assertEquals("B", reversed.get(1).getDeviceName());
        assertEquals("outB", reversed.get(1).getInPort());
        assertEquals("inB", reversed.get(1).getOutPort());
        assertEquals(1, reversed.get(1).getHopIndex());

        assertEquals("A", reversed.get(2).getDeviceName());
        assertEquals("outA", reversed.get(2).getInPort());
        assertEquals("inA", reversed.get(2).getOutPort());
        assertEquals("rack1", reversed.get(2).getRack());
        assertEquals(2, reversed.get(2).getHopIndex());
    }

    @Test
    @DisplayName("findPortByName returns port from chip's port map")
    void findPortByName() {
        NpuDevice npu = createNpu("NPU1", "eid1", "cna1", null, null);
        PortEntity port = engine.findPortByName(npu, "port1");
        assertNotNull(port);
        assertEquals("port1", port.getPortName());
    }

    @Test
    @DisplayName("findPortByName returns null for non-existent port")
    void findPortByName_notFound() {
        NpuDevice npu = createNpu("NPU1", "eid1", "cna1", null, null);
        assertNull(engine.findPortByName(npu, "nonexistent"));
    }

    @Test
    @DisplayName("findPortByName returns null for null device")
    void findPortByName_nullDevice() {
        assertNull(engine.findPortByName(null, "port1"));
    }

    @Test
    @DisplayName("findPortByConnection returns first port with remoteDevice set")
    void findPortByConnection() {
        NpuDevice npu = new NpuDevice();
        npu.setOsName("os");
        npu.setOsIp("ip");
        npu.setBoardId(0);
        npu.setModuleId(1);
        npu.setBoardIndex(2);
        npu.setDeviceName("NPU1");

        NpuPortEntity portNoConn = new NpuPortEntity();
        portNoConn.setPortName("noConn");
        portNoConn.setId(1);

        NpuPortEntity portWithConn = new NpuPortEntity();
        portWithConn.setPortName("connPort");
        portWithConn.setId(2);
        portWithConn.setRemoteDevice("NPU2");
        portWithConn.setRemotePort("port1");

        NpuForwardingChip chip = new NpuForwardingChip();
        chip.setChipIndex(0);
        chip.setPorts(Map.of("noConn", portNoConn, "connPort", portWithConn));

        npu.setForwardingChips(Map.of(0, chip));

        PortEntity found = engine.findPortByConnection(npu);
        assertNotNull(found);
        assertEquals("connPort", found.getPortName());
    }

    @Test
    @DisplayName("findPortByConnection returns null when no port has remoteDevice")
    void findPortByConnection_noConnection() {
        NpuDevice npu = new NpuDevice();
        npu.setOsName("os");
        npu.setOsIp("ip");
        npu.setBoardId(0);
        npu.setModuleId(1);
        npu.setBoardIndex(2);
        npu.setDeviceName("NPU1");
        npu.setForwardingChips(new HashMap<>());

        assertNull(engine.findPortByConnection(npu));
    }

    @Test
    @DisplayName("findPortByConnection returns null for null device")
    void findPortByConnection_nullDevice() {
        assertNull(engine.findPortByConnection(null));
    }

    @Test
    @DisplayName("findPortByConnection returns null when chips is null")
    void findPortByConnection_nullChips() {
        NpuDevice npu = new NpuDevice();
        npu.setOsName("os");
        npu.setOsIp("ip");
        npu.setBoardId(0);
        npu.setModuleId(1);
        npu.setBoardIndex(2);
        npu.setDeviceName("NPU1");
        npu.setForwardingChips(null);
        assertNull(engine.findPortByConnection(npu));
    }

    @Test
    @DisplayName("findPortByName returns null when chips is null")
    void findPortByName_nullChips() {
        NpuDevice npu = new NpuDevice();
        npu.setOsName("os");
        npu.setOsIp("ip");
        npu.setBoardId(0);
        npu.setModuleId(1);
        npu.setBoardIndex(2);
        npu.setDeviceName("NPU1");
        npu.setForwardingChips(null);
        assertNull(engine.findPortByName(npu, "port1"));
    }

    @Test
    @DisplayName("resolveMultiHopPath with null interDevice chips does not throw, port stays null")
    void resolveMultiHopPath_swNoChips() {
        NpuDevice npu1 = createNpu("NPU1", "e1", "c1", null, null);
        NpuDevice npu2 = createNpu("NPU2", "e2", "c2", null, null);

        SwDevice sw = new SwDevice();
        sw.setSwitchLevel(SwitchLevel.L1);
        sw.setIndex(1);
        sw.setDeviceName("SW");
        sw.setForwardingChips(null);

        NpuPortEntity srcPort = findPortOnNpu(npu1, "port1");
        NpuPortEntity destPort = findPortOnNpu(npu2, "port1");

        InternalPathInfo path = engine.resolveMultiHopPath(npu1, srcPort, npu2, destPort,
            Map.of("SW", "swPort"), Map.of("NPU1", npu1, "SW", sw, "NPU2", npu2));
        assertEquals(3, path.getHops().size());
        assertEquals("SW", path.getHops().get(1).getDeviceName());
    }

    @Test
    @DisplayName("resolveMultiHopPath with empty interDevice chip ports does not throw")
    void resolveMultiHopPath_swChipNoPorts() {
        NpuDevice npu1 = createNpu("NPU1", "e1", "c1", null, null);
        NpuDevice npu2 = createNpu("NPU2", "e2", "c2", null, null);

        SwDevice sw = new SwDevice();
        sw.setSwitchLevel(SwitchLevel.L1);
        sw.setIndex(1);
        sw.setDeviceName("SW");
        SwForwardingChip swChip = new SwForwardingChip();
        swChip.setChipIndex(0);
        swChip.setPorts(new HashMap<>());
        sw.setForwardingChips(Map.of(0, swChip));

        NpuPortEntity srcPort = findPortOnNpu(npu1, "port1");
        NpuPortEntity destPort = findPortOnNpu(npu2, "port1");

        InternalPathInfo path = engine.resolveMultiHopPath(npu1, srcPort, npu2, destPort,
            Map.of("SW", "swPort"), Map.of("NPU1", npu1, "SW", sw, "NPU2", npu2));
        assertEquals(3, path.getHops().size());
    }

    private static NpuDevice createNpu(String name, String eid, String cna,
                                        String remoteDevice, String remotePort) {
        NpuDevice dev = new NpuDevice();
        dev.setOsName("os");
        dev.setOsIp("ip");
        dev.setBoardId(0);
        dev.setModuleId(1);
        dev.setBoardIndex(2);
        dev.setDeviceName(name);

        NpuPortEntity port = new NpuPortEntity(eid, null);
        port.setPortName("port1");
        port.setId(1);
        port.setChipIndex(0);
        port.setCna(cna);
        port.setRemoteDevice(remoteDevice);
        port.setRemotePort(remotePort);

        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        chip.setPorts(Map.of("port1", port));

        dev.setForwardingChips(Map.of(0, chip));
        return dev;
    }

    @Test
    @DisplayName("findPortByName returns null when chip ports is null")
    void findPortByName_nullPorts() {
        NpuDevice npu = new NpuDevice();
        npu.setOsName("os");
        npu.setOsIp("ip");
        npu.setBoardId(0);
        npu.setModuleId(1);
        npu.setBoardIndex(2);
        npu.setDeviceName("NPU1");
        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        chip.setPorts(null);
        npu.setForwardingChips(Map.of(0, chip));
        assertNull(engine.findPortByName(npu, "port1"));
    }

    @Test
    @DisplayName("findPortByConnection returns null when chip ports is null")
    void findPortByConnection_nullPorts() {
        NpuDevice npu = new NpuDevice();
        npu.setOsName("os");
        npu.setOsIp("ip");
        npu.setBoardId(0);
        npu.setModuleId(1);
        npu.setBoardIndex(2);
        npu.setDeviceName("NPU1");
        NpuForwardingChip chip = new NpuForwardingChip(null);
        chip.setChipIndex(0);
        chip.setPorts(null);
        npu.setForwardingChips(Map.of(0, chip));
        assertNull(engine.findPortByConnection(npu));
    }

    @Test
    @DisplayName("findPortByConnection returns null when port has only remoteDevice but no remotePort")
    void findPortByConnection_onlyRemoteDevice() {
        NpuDevice npu = new NpuDevice();
        npu.setOsName("os");
        npu.setOsIp("ip");
        npu.setBoardId(0);
        npu.setModuleId(1);
        npu.setBoardIndex(2);
        npu.setDeviceName("NPU1");
        NpuPortEntity swPort = new NpuPortEntity();
        swPort.setPortName("port1");
        swPort.setId(1);
        swPort.setChipIndex(0);
        swPort.setRemoteDevice("NPU2");
        swPort.setRemotePort(null);
        NpuForwardingChip chip = new NpuForwardingChip();
        chip.setChipIndex(0);
        chip.setPorts(Map.of("port1", swPort));
        npu.setForwardingChips(Map.of(0, chip));
        assertNull(engine.findPortByConnection(npu));
    }

    @Test
    @DisplayName("findPortByConnection returns null when port has only remotePort but no remoteDevice")
    void findPortByConnection_onlyRemotePort() {
        NpuDevice npu = new NpuDevice();
        npu.setOsName("os");
        npu.setOsIp("ip");
        npu.setBoardId(0);
        npu.setModuleId(1);
        npu.setBoardIndex(2);
        npu.setDeviceName("NPU1");
        NpuPortEntity swPort = new NpuPortEntity();
        swPort.setPortName("port1");
        swPort.setId(1);
        swPort.setChipIndex(0);
        swPort.setRemoteDevice(null);
        swPort.setRemotePort("port2");
        NpuForwardingChip chip = new NpuForwardingChip();
        chip.setChipIndex(0);
        chip.setPorts(Map.of("port1", swPort));
        npu.setForwardingChips(Map.of(0, chip));
        assertNull(engine.findPortByConnection(npu));
    }

    @Test
    @DisplayName("resolveMultiHopPath when interPortName is null uses findPortByConnection")
    void resolveMultiHopPath_interPortNameNull() {
        NpuDevice npu1 = createNpu("NPU1", "e1", "c1", null, null);
        NpuDevice npu2 = createNpu("NPU2", "e2", "c2", null, null);
        SwDevice sw = new SwDevice();
        sw.setSwitchLevel(SwitchLevel.L1);
        sw.setIndex(1);
        sw.setDeviceName("L1SW");
        SwPortEntity swPort1 = new SwPortEntity();
        swPort1.setPortName("swPort1");
        swPort1.setId(1);
        swPort1.setChipIndex(0);
        swPort1.setRemoteDevice("NPU2");
        swPort1.setRemotePort("port1");
        SwForwardingChip swChip = new SwForwardingChip();
        swChip.setChipIndex(0);
        swChip.setPorts(Map.of("swPort1", swPort1));
        sw.setForwardingChips(Map.of(0, swChip));

        NpuPortEntity srcPort = findPortOnNpu(npu1, "port1");
        NpuPortEntity destPort = findPortOnNpu(npu2, "port1");

        Map<String, String> interDevices = new HashMap<>();
        interDevices.put("L1SW", null);
        InternalPathInfo path = engine.resolveMultiHopPath(npu1, srcPort, npu2, destPort,
            interDevices, Map.of("NPU1", npu1, "L1SW", sw, "NPU2", npu2));
        assertEquals(3, path.getHops().size());
    }

    @Test
    @DisplayName("resolveMultiHopPath when dest already in orderedDevices skips adding dest")
    void resolveMultiHopPath_destAlreadyOrdered() {
        NpuDevice npu1 = createNpu("NPU1", "e1", "c1", "L1SW", "swPort1");
        NpuDevice npu2 = createNpu("NPU2", "e2", "c2", "L1SW", "swPort2");
        SwDevice sw = new SwDevice();
        sw.setSwitchLevel(SwitchLevel.L1);
        sw.setIndex(1);
        sw.setDeviceName("L1SW");
        SwPortEntity swPort1 = new SwPortEntity();
        swPort1.setPortName("swPort1");
        swPort1.setId(1);
        swPort1.setChipIndex(0);
        swPort1.setRemoteDevice("NPU1");
        swPort1.setRemotePort("port1");
        SwPortEntity swPort2 = new SwPortEntity();
        swPort2.setPortName("swPort2");
        swPort2.setId(2);
        swPort2.setChipIndex(0);
        swPort2.setRemoteDevice("NPU2");
        swPort2.setRemotePort("port1");
        SwForwardingChip swChip = new SwForwardingChip();
        swChip.setChipIndex(0);
        swChip.setPorts(Map.of("swPort1", swPort1, "swPort2", swPort2));
        sw.setForwardingChips(Map.of(0, swChip));

        NpuPortEntity srcPort = findPortOnNpu(npu1, "port1");
        NpuPortEntity destPort = findPortOnNpu(npu2, "port1");

        Map<String, String> interDevices = new HashMap<>();
        interDevices.put("L1SW", "swPort2");
        interDevices.put("NPU2", null);

        InternalPathInfo path = engine.resolveMultiHopPath(npu1, srcPort, npu2, destPort,
            interDevices, Map.of("NPU1", npu1, "L1SW", sw, "NPU2", npu2));
        assertEquals(3, path.getHops().size());
    }

    @Test
    @DisplayName("resolveMultiHopPath validates connection between hops")
    void resolveMultiHopPath_connectionCheck_pass() {
        NpuDevice npu1 = createNpu("NPU1", "e1", "c1", "L1SW", "swPort1");
        NpuDevice npu2 = createNpu("NPU2", "e2", "c2", "L1SW", "swPort2");
        SwDevice sw = createSw("L1SW", "NPU2", "npu2Port1");

        NpuPortEntity srcPort = findPortOnNpu(npu1, "port1");
        NpuPortEntity destPort = findPortOnNpu(npu2, "port1");

        InternalPathInfo path = engine.resolveMultiHopPath(npu1, srcPort, npu2, destPort,
            Map.of("L1SW", "swPort2"), Map.of("NPU1", npu1, "L1SW", sw, "NPU2", npu2));
        assertEquals(3, path.getHops().size());
    }

    private static NpuPortEntity findPortOnNpu(NpuDevice dev, String portName) {
        return (NpuPortEntity) dev.getForwardingChips().get(0).getPorts().get(portName);
    }

    private static SwDevice createSw(String name, String remoteDevice, String remotePort) {
        SwDevice sw = new SwDevice();
        sw.setSwitchLevel(SwitchLevel.L1);
        sw.setIndex(1);
        sw.setDeviceName(name);

        SwPortEntity swPort1 = new SwPortEntity();
        swPort1.setPortName("swPort1");
        swPort1.setId(1);
        swPort1.setChipIndex(0);
        swPort1.setRemoteDevice("NPU1");
        swPort1.setRemotePort("port1");

        SwPortEntity swPort2 = new SwPortEntity();
        swPort2.setPortName("swPort2");
        swPort2.setId(2);
        swPort2.setChipIndex(0);
        swPort2.setRemoteDevice(remoteDevice);
        swPort2.setRemotePort(remotePort);

        SwForwardingChip chip = new SwForwardingChip();
        chip.setChipIndex(0);
        chip.setPorts(Map.of("swPort1", swPort1, "swPort2", swPort2));

        sw.setForwardingChips(Map.of(0, chip));
        return sw;
    }
}
