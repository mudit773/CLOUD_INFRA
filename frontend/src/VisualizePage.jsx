import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  ArrowLeft, Network, ShieldCheck, Sparkles, Server, Database, ShieldAlert,
  Cloud, Layers3, Search, Activity, ChevronRight,
  ChevronDown, Box, Zap, RefreshCw, Key, ZoomIn, ZoomOut,
  Maximize2, Crosshair, Layers, Eye, EyeOff,
} from "lucide-react";
import "./App.css";

function ConnectedNetworkGraphCanvas({
  nodes,
  edges,
  selectedNode,
  onSelectNode,
  filter,
}) {
  const canvasRef = useRef(null);
  const containerRef = useRef(null);

  // Grouped vs Expanded view toggle (default is MINIMIZED/GROUPED for clutter reduction)
  const [isGroupedView, setIsGroupedView] = useState(true);

  // Pan & zoom transform state
  const [zoom, setZoom] = useState(0.9);
  const [offset, setOffset] = useState({ x: 30, y: 30 });
  const [isDraggingCanvas, setIsDraggingCanvas] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [draggedNodeId, setDraggedNodeId] = useState(null);

  // Layout node positions stored in state
  const [nodePositions, setNodePositions] = useState({});

  // 1. Grouping Algorithm: Group tightly related auxiliary child resources
  const { processedNodes, processedEdges } = useMemo(() => {
    // If user turned off grouping or filter is active, show all individual nodes
    if (!isGroupedView || filter === "attack_path") {
      return { processedNodes: nodes, processedEdges: edges };
    }

    const coreNodes = [];
    const groupedSubnets = [];
    const groupedRouting = [];
    const groupedUtility = [];

    nodes.forEach((n) => {
      // Never group if the node is critical (attack path, choke point, crown jewel, or selected)
      const isCritical =
        n.in_attack_path ||
        n.is_choke_point ||
        n.is_crown_jewel ||
        (selectedNode && selectedNode.id === n.id);

      if (isCritical) {
        coreNodes.push(n);
        return;
      }

      const t = (n.type || "").toLowerCase();
      const id = (n.id || "").toLowerCase();

      if (t === "aws_subnet") {
        groupedSubnets.push(n);
      } else if (t.includes("route_table") || t.includes("route")) {
        groupedRouting.push(n);
      } else if (
        t === "aws_key_pair" ||
        t === "aws_kms_alias" ||
        t === "random_uuid" ||
        id.startsWith("var.")
      ) {
        groupedUtility.push(n);
      } else {
        coreNodes.push(n);
      }
    });

    const finalNodes = [...coreNodes];
    const groupNodeIds = new Set();
    const childToGroupMap = {};

    // Group Subnets master node
    if (groupedSubnets.length > 1) {
      const gId = "group_subnets";
      groupNodeIds.add(gId);
      groupedSubnets.forEach((sn) => (childToGroupMap[sn.id] = gId));
      finalNodes.push({
        id: gId,
        name: `📦 VPC Subnets (${groupedSubnets.length} items)`,
        type: "group_subnets",
        provider: "aws",
        is_group: true,
        count: groupedSubnets.length,
        child_ids: groupedSubnets.map((s) => s.id),
      });
    } else {
      finalNodes.push(...groupedSubnets);
    }

    // Group Routing Rules & Associations master node
    if (groupedRouting.length > 1) {
      const gId = "group_routing";
      groupNodeIds.add(gId);
      groupedRouting.forEach((rn) => (childToGroupMap[rn.id] = gId));
      finalNodes.push({
        id: gId,
        name: `📦 Route Tables & Assoc (${groupedRouting.length} items)`,
        type: "group_routing",
        provider: "aws",
        is_group: true,
        count: groupedRouting.length,
        child_ids: groupedRouting.map((r) => r.id),
      });
    } else {
      finalNodes.push(...groupedRouting);
    }

    // Group Utility / Key Aliases master node
    if (groupedUtility.length > 1) {
      const gId = "group_utility";
      groupNodeIds.add(gId);
      groupedUtility.forEach((un) => (childToGroupMap[un.id] = gId));
      finalNodes.push({
        id: gId,
        name: `📦 Config & Key Aliases (${groupedUtility.length} items)`,
        type: "group_utility",
        provider: "aws",
        is_group: true,
        count: groupedUtility.length,
        child_ids: groupedUtility.map((u) => u.id),
      });
    } else {
      finalNodes.push(...groupedUtility);
    }

    // Map edges to grouped nodes and deduplicate
    const finalEdges = [];
    const seenEdgeKeys = new Set();

    edges.forEach((e) => {
      const mappedSource = childToGroupMap[e.source] || e.source;
      const mappedTarget = childToGroupMap[e.target] || e.target;

      // Don't draw self-loop on a group
      if (mappedSource === mappedTarget) return;

      const edgeKey = `${mappedSource}->${mappedTarget}`;
      if (!seenEdgeKeys.has(edgeKey)) {
        seenEdgeKeys.add(edgeKey);
        finalEdges.push({
          ...e,
          id: edgeKey,
          source: mappedSource,
          target: mappedTarget,
        });
      }
    });

    return { processedNodes: finalNodes, processedEdges: finalEdges };
  }, [nodes, edges, isGroupedView, filter, selectedNode]);

  // Filter nodes based on user selection
  const activeNodes = useMemo(() => {
    if (filter === "attack_path") return processedNodes.filter((n) => n.in_attack_path);
    if (filter === "choke_points") return processedNodes.filter((n) => n.is_choke_point);
    return processedNodes;
  }, [processedNodes, filter]);

  const activeNodeIds = useMemo(() => new Set(activeNodes.map((n) => n.id)), [activeNodes]);

  const activeEdges = useMemo(() => {
    return processedEdges.filter((e) => activeNodeIds.has(e.source) && activeNodeIds.has(e.target));
  }, [processedEdges, activeNodeIds]);

  // Selected node connections
  const connectedEdgeSet = useMemo(() => {
    if (!selectedNode) return new Set();
    const set = new Set();
    activeEdges.forEach((e) => {
      if (e.source === selectedNode.id || e.target === selectedNode.id) {
        set.add(e.id);
      }
    });
    return set;
  }, [selectedNode, activeEdges]);

  const connectedNeighborIds = useMemo(() => {
    if (!selectedNode) return new Set();
    const set = new Set([selectedNode.id]);
    activeEdges.forEach((e) => {
      if (e.source === selectedNode.id) set.add(e.target);
      if (e.target === selectedNode.id) set.add(e.source);
    });
    return set;
  }, [selectedNode, activeEdges]);

  // Clean, generous layout spacing algorithm
  useEffect(() => {
    if (!activeNodes || activeNodes.length === 0) return;

    // Preserve existing positions (e.g., after dragging) and only compute defaults for new nodes
    setNodePositions(prev => {
      const newPositions = { ...prev };
      const cols = {
        ingress: [], // X: 110
        network: [], // X: 450
        compute: [], // X: 790
        storage: [], // X: 1130
      };

      // Categorize nodes
      activeNodes.forEach((n) => {
        const t = (n.type || "").toLowerCase();
        const id = (n.id || "").toLowerCase();
        if (id === "internet" || t.includes("gateway") || t.includes("security_group")) {
          cols.ingress.push(n);
        } else if (t.includes("vpc") || t.includes("subnet") || t.includes("route") || id.includes("subnet") || id.includes("routing")) {
          cols.network.push(n);
        } else if (t.includes("instance") || t.includes("cluster") || t.includes("msk") || t.includes("server")) {
          cols.compute.push(n);
        } else {
          cols.storage.push(n);
        }
      });

      const colXMap = {
        ingress: 120,
        network: 450,
        compute: 780,
        storage: 1110,
      };

      // Assign positions only for nodes that don't already have a saved position
      Object.keys(cols).forEach((colKey) => {
        const items = cols[colKey];
        const startX = colXMap[colKey];
        items.forEach((item, idx) => {
          if (!newPositions[item.id]) {
            const y = 80 + idx * 105;
            newPositions[item.id] = { x: startX, y };
          }
        });
      });

      return newPositions;
    });
  }, [activeNodes]);
// Center or focus on selected node when clicked
useEffect(() => {
if (selectedNode && nodePositions[selectedNode.id]) {
  const pos = nodePositions[selectedNode.id];
  const canvas = canvasRef.current;
  if (canvas) {
    const rect = canvas.getBoundingClientRect();
    setOffset({
      x: Math.round(rect.width / 2 - pos.x * zoom),
      y: Math.round(rect.height / 2 - pos.y * zoom),
    });
  }
}
  }, [selectedNode]);

const fitToView = useCallback(() => {
  setZoom(0.85);
  setOffset({ x: 30, y: 30 });
}, []);

const focusAttackChain = useCallback(() => {
  const attackNodeObjs = activeNodes.filter((n) => n.in_attack_path);
  if (attackNodeObjs.length > 0) {
    setZoom(1.0);
    onSelectNode(attackNodeObjs[1] || attackNodeObjs[0]);
  }
}, [activeNodes, onSelectNode]);

// Render loop on canvas
useEffect(() => {
const canvas = canvasRef.current;
if (!canvas) return;
const ctx = canvas.getContext("2d");
if (!ctx) return;

const dpr = window.devicePixelRatio || 1;
const rect = canvas.getBoundingClientRect();
canvas.width = rect.width * dpr;
canvas.height = rect.height * dpr;
ctx.scale(dpr, dpr);

ctx.clearRect(0, 0, rect.width, rect.height);

ctx.save();
ctx.translate(offset.x, offset.y);
ctx.scale(zoom, zoom);

// Subtle background grid
ctx.fillStyle = "rgba(148, 163, 184, 0.22)";
const gridSize = 32;
const startX = -offset.x / zoom;
const endX = (rect.width - offset.x) / zoom;
const startY = -offset.y / zoom;
const endY = (rect.height - offset.y) / zoom;
for (let x = Math.floor(startX / gridSize) * gridSize; x < endX; x += gridSize) {
  for (let y = Math.floor(startY / gridSize) * gridSize; y < endY; y += gridSize) {
    ctx.fillRect(x, y, 1.2, 1.2);
  }
}

const nodeW = 195;
const nodeH = 56;
const radius = 8;

// Draw directed arrow
function drawDirectedEdge(sourcePos, targetPos, edge) {
  const isAttackEdge = edge.in_attack_path;
  const isSelectedEdge = connectedEdgeSet.has(edge.id);
  const isDimmed = selectedNode && !isSelectedEdge && !isAttackEdge;

  ctx.save();

  const dx = targetPos.x - sourcePos.x;
  const dy = targetPos.y - sourcePos.y;
  const dist = Math.hypot(dx, dy) || 1;

  const targetEdgeDist = nodeW / 2 + 2;
  const endX = targetPos.x - (dx / dist) * targetEdgeDist;
  const endY = targetPos.y - (dy / dist) * (nodeH / 2);

  const startEdgeDist = nodeW / 2;
  const startX = sourcePos.x + (dx / dist) * startEdgeDist;
  const startY = sourcePos.y + (dy / dist) * (nodeH / 2);

  ctx.beginPath();
  ctx.moveTo(startX, startY);

  // Smooth curved path to prevent line overlap
  const midX = (startX + endX) / 2;
  const midY = (startY + endY) / 2 - (dx > 0 ? 16 : -16);
  ctx.quadraticCurveTo(midX, midY, endX, endY);

  if (isAttackEdge) {
    ctx.strokeStyle = "#e11d48";
    ctx.lineWidth = 3.2;
    ctx.shadowColor = "rgba(225, 29, 72, 0.4)";
    ctx.shadowBlur = 8;
  } else if (isSelectedEdge) {
    ctx.strokeStyle = "#087e56";
    ctx.lineWidth = 2.4;
    ctx.shadowColor = "rgba(8, 126, 86, 0.3)";
    ctx.shadowBlur = 6;
  } else if (isDimmed) {
    ctx.strokeStyle = "rgba(148, 163, 184, 0.22)";
    ctx.lineWidth = 1;
  } else {
    ctx.strokeStyle = "#94a3b8";
    ctx.lineWidth = 1.3;
  }

  ctx.stroke();

  // Draw Arrow Head
  const angle = Math.atan2(endY - midY, endX - midX);
  const headLen = isAttackEdge ? 10 : 8;
  ctx.fillStyle = isAttackEdge ? "#e11d48" : isSelectedEdge ? "#087e56" : isDimmed ? "rgba(148, 163, 184, 0.3)" : "#94a3b8";

  ctx.beginPath();
  ctx.moveTo(endX, endY);
  ctx.lineTo(
    endX - headLen * Math.cos(angle - Math.PI / 6),
    endY - headLen * Math.sin(angle - Math.PI / 6)
  );
  ctx.lineTo(
    endX - headLen * Math.cos(angle + Math.PI / 6),
    endY - headLen * Math.sin(angle + Math.PI / 6)
  );
  ctx.closePath();
  ctx.fill();

  // Edge label
  if ((isSelectedEdge || isAttackEdge) && edge.type) {
    ctx.font = "9px Inter, sans-serif";
    ctx.fillStyle = isAttackEdge ? "#9f1239" : "#065f46";
    ctx.textAlign = "center";
    const labelText = edge.rule_id ? `${edge.type} [${edge.rule_id}]` : edge.type;
    ctx.fillText(labelText, midX, midY - 4);
  }

  ctx.restore();
}

// 1. Draw all edges
activeEdges.forEach((edge) => {
  const sPos = nodePositions[edge.source];
  const tPos = nodePositions[edge.target];
  if (sPos && tPos) {
    drawDirectedEdge(sPos, tPos, edge);
  }
});

// 2. Draw nodes
activeNodes.forEach((node) => {
  const pos = nodePositions[node.id];
  if (!pos) return;

  const isSelected = selectedNode?.id === node.id;
  const isNeighbor = connectedNeighborIds.has(node.id);
  const isAttackNode = node.in_attack_path;
  const isChokePoint = node.is_choke_point;
  const isCrownJewel = node.is_crown_jewel;
  const isEntryPoint = node.is_entry_point;
  const isGroup = node.is_group;

  const isDimmed = selectedNode && !isSelected && !isNeighbor;

  ctx.save();
  if (isDimmed) {
    ctx.globalAlpha = 0.28;
  }

  const x = pos.x - nodeW / 2;
  const y = pos.y - nodeH / 2;

  ctx.beginPath();
  ctx.roundRect(x, y, nodeW, nodeH, radius);

  if (isSelected) {
    ctx.fillStyle = "#ffffff";
    ctx.strokeStyle = "#087e56";
    ctx.lineWidth = 3;
    ctx.shadowColor = "rgba(8, 126, 86, 0.45)";
    ctx.shadowBlur = 12;
  } else if (isChokePoint) {
    ctx.fillStyle = "#fffdf5";
    ctx.strokeStyle = "#d97706";
    ctx.lineWidth = 2.4;
    ctx.shadowColor = "rgba(217, 119, 6, 0.35)";
    ctx.shadowBlur = 10;
  } else if (isAttackNode) {
    ctx.fillStyle = "#fff8f8";
    ctx.strokeStyle = "#e11d48";
    ctx.lineWidth = 2.4;
    ctx.shadowColor = "rgba(225, 29, 72, 0.35)";
    ctx.shadowBlur = 10;
  } else if (isCrownJewel) {
    ctx.fillStyle = "#faf5ff";
    ctx.strokeStyle = "#9333ea";
    ctx.lineWidth = 2;
    ctx.shadowColor = "rgba(147, 51, 234, 0.25)";
    ctx.shadowBlur = 8;
  } else if (isGroup) {
    ctx.fillStyle = "#f8fafc";
    ctx.strokeStyle = "#94a3b8";
    ctx.lineWidth = 1.8;
  } else if (isEntryPoint) {
    ctx.fillStyle = "#f0f9ff";
    ctx.strokeStyle = "#0284c7";
    ctx.lineWidth = 2;
  } else {
    ctx.fillStyle = "#ffffff";
    ctx.strokeStyle = "#cbd5e1";
    ctx.lineWidth = 1.3;
    ctx.shadowColor = "rgba(15, 23, 42, 0.06)";
    ctx.shadowBlur = 4;
  }

  ctx.fill();
  ctx.stroke();
  ctx.shadowBlur = 0;

  // Color accent strip on left
  ctx.fillStyle = isChokePoint
    ? "#d97706"
    : isAttackNode
      ? "#e11d48"
      : isCrownJewel
        ? "#9333ea"
        : isGroup
          ? "#64748b"
          : isEntryPoint
            ? "#0284c7"
            : "#10b981";
  ctx.fillRect(x + 2, y + 4, 3.5, nodeH - 8);

  // Node Name Text
  ctx.textAlign = "left";
  ctx.font = isGroup ? "bold 10.5px Inter, sans-serif" : "bold 11px Inter, sans-serif";
  ctx.fillStyle = isAttackNode ? "#881337" : isGroup ? "#1e293b" : "#0f172a";
  const displayName = node.name || node.id;
  const truncatedName = displayName.length > 21 ? displayName.slice(0, 19) + "..." : displayName;
  ctx.fillText(truncatedName, x + 14, y + 20);

  // Node Subtext / Type
  ctx.font = "9px Inter, sans-serif";
  ctx.fillStyle = isGroup ? "#087e56" : "#64748b";
  const displayType = isGroup ? "Click to expand child resources" : (node.type || "").length > 24 ? (node.type || "").slice(0, 22) + ".." : node.type;
  ctx.fillText(displayType, x + 14, y + 34);

  // Node Badges
  let badgeX = x + 14;
  function drawBadgePill(text, bg, fg) {
    ctx.font = "bold 8px Inter, sans-serif";
    const w = ctx.measureText(text).width + 8;
    ctx.fillStyle = bg;
    ctx.roundRect(badgeX, y + 40, w, 12, 3);
    ctx.fill();
    ctx.fillStyle = fg;
    ctx.fillText(text, badgeX + 4, y + 49);
    badgeX += w + 4;
  }

  if (isChokePoint) {
    drawBadgePill("🎯 CHOKE POINT", "#fef3c7", "#92400e");
  } else if (isAttackNode) {
    drawBadgePill("⚡ ATTACK PATH", "#fee2e2", "#991b1b");
  } else if (isCrownJewel) {
    drawBadgePill("💎 CROWN JEWEL", "#f3e8ff", "#6b21a8");
  } else if (isGroup) {
    drawBadgePill("📦 GROUPED MASTER", "#e2e8f0", "#334155");
  } else if (isEntryPoint) {
    drawBadgePill("🌐 ENTRY", "#e0f2fe", "#075985");
  }

  ctx.restore();
});

ctx.restore();
  }, [
  activeNodes,
  activeEdges,
  nodePositions,
  zoom,
  offset,
  selectedNode,
  connectedEdgeSet,
  connectedNeighborIds,
]);

// Click & drag interaction
const handleMouseDown = (e) => {
  const canvas = canvasRef.current;
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  const mouseX = (e.clientX - rect.left - offset.x) / zoom;
  const mouseY = (e.clientY - rect.top - offset.y) / zoom;

  const nodeW = 195;
  const nodeH = 56;

  for (let i = activeNodes.length - 1; i >= 0; i--) {
    const node = activeNodes[i];
    const pos = nodePositions[node.id];
    if (
      pos &&
      mouseX >= pos.x - nodeW / 2 &&
      mouseX <= pos.x + nodeW / 2 &&
      mouseY >= pos.y - nodeH / 2 &&
      mouseY <= pos.y + nodeH / 2
    ) {
      if (node.is_group) {
        // If clicked a grouped master node, expand the full view to reveal child items
        setIsGroupedView(false);
        const firstChildId = node.child_ids?.[0];
        const childObj = nodes.find((n) => n.id === firstChildId);
        if (childObj) onSelectNode(childObj);
      } else {
        onSelectNode(node);
      }
      setDraggedNodeId(node.id);
      return;
    }
  }

  setIsDraggingCanvas(true);
  setDragStart({ x: e.clientX - offset.x, y: e.clientY - offset.y });
};

const handleMouseMove = (e) => {
  if (draggedNodeId) {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const newX = (e.clientX - rect.left - offset.x) / zoom;
    const newY = (e.clientY - rect.top - offset.y) / zoom;

    setNodePositions((prev) => ({
      ...prev,
      [draggedNodeId]: { x: Math.round(newX), y: Math.round(newY) },
    }));
    return;
  }

  if (isDraggingCanvas) {
    setOffset({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y,
    });
  }
};

const handleMouseUp = () => {
  setIsDraggingCanvas(false);
  setDraggedNodeId(null);
};

useEffect(() => {
  const container = containerRef.current;
  if (!container) return;

  const handleWheel = (event) => {
    event.preventDefault();
    event.stopPropagation();
    const delta = event.deltaY < 0 ? 1.08 : 0.92;
    setZoom((prev) => Math.min(Math.max(prev * delta, 0.35), 2.5));
  };

  container.addEventListener("wheel", handleWheel, { passive: false });
  return () => container.removeEventListener("wheel", handleWheel);
}, []);

return (
  <div className="network-graph-canvas-container" ref={containerRef}>
    {/* CANVAS TOOLBAR */}
    <div className="graph-canvas-toolbar">
      <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
        {/* GROUPED / MINIMIZED VIEW TOGGLE */}
        <button
          type="button"
          className={`canvas-tool-btn ${isGroupedView ? "active" : ""}`}
          onClick={() => setIsGroupedView((v) => !v)}
          title="Toggle Clutter Reduction & Node Grouping"
        >
          <Layers size={13} />
          {isGroupedView ? "Minimized Focus (Grouped)" : "Full Expanded Topology"}
        </button>

        <button
          type="button"
          className="canvas-tool-btn"
          onClick={() => setZoom((z) => Math.min(z * 1.2, 2.5))}
          title="Zoom In"
        >
          <ZoomIn size={14} />
        </button>

        <button
          type="button"
          className="canvas-tool-btn"
          onClick={() => setZoom((z) => Math.max(z * 0.8, 0.35))}
          title="Zoom Out"
        >
          <ZoomOut size={14} />
        </button>

        <button
          type="button"
          className="canvas-tool-btn"
          onClick={fitToView}
          title="Fit to View"
        >
          <Maximize2 size={13} />
          Fit View
        </button>

        <button 
        type="button"
        onClick={focusAttackChain}
        className={`canvas-tool-btn ${filter === "attack_path" ? "active" : ""} `}>  
        <Zap size={13} />
          Attack Path
        </button>
      </div>
    </div>

    {/* COMPACT LEGEND */}
    <div className="canvas-legend">
      <span className="legend-item"><span className="legend-dot attack"></span>Attack Path</span>
      <span className="legend-item"><span className="legend-dot choke"></span>Choke Point</span>
      <span className="legend-item"><span className="legend-dot crown"></span>Crown Jewel</span>
      <span className="legend-item"><span className="legend-dot entry"></span>Entry Point</span>
    </div>

      {/* HTML5 DIRECTED GRAPH CANVAS */ }
<canvas
  ref={canvasRef}
  className="connected-network-canvas"
  onMouseDown={handleMouseDown}
  onMouseMove={handleMouseMove}
  onMouseUp={handleMouseUp}
/>
    </div>
  );
}


/* =========================================================
   VISUALIZE PAGE (DYNAMIC GRAPH INTEGRATION)
========================================================= */

function getResourceIcon(type = "") {
  const t = type.toLowerCase();
  if (t.includes("vpc") || t.includes("subnet") || t.includes("gateway")) return <Layers3 size={17} />;
  if (t.includes("instance") || t.includes("ec2")) return <Server size={17} />;
  if (t.includes("database") || t.includes("msk") || t.includes("cluster") || t.includes("db")) return <Database size={17} />;
  if (t.includes("security") || t.includes("sg") || t.includes("firewall")) return <ShieldCheck size={17} />;
  if (t.includes("kms") || t.includes("key") || t.includes("secret") || t.includes("iam")) return <Key size={17} />;
  return <Box size={17} />;
}

function VisualizePage({ analysis }) {
  const {
    graphData,
    loadingGraph,
    triggerScan,
    scanning,
    selectedNode,
    setSelectedNode,
    filter,
    setFilter,
    searchQuery,
    setSearchQuery,
    activeSource,
  } = analysis;

  const summary = graphData?.summary || {
    resources_count: 0,
    relationships_count: 0,
    security_findings_count: 0,
    cloud_provider: "None",
    risk_level: "NONE",
    risk_score: 0.0,
  };

  const allNodes = graphData?.nodes || [];
  const allEdges = graphData?.edges || [];
  const allFindings = graphData?.findings || [];
  const chokePoints = graphData?.choke_points || [];

  // Filter nodes based on view pill and search query
  const filteredNodes = allNodes.filter((node) => {
    const matchesSearch =
      !searchQuery ||
      node.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      node.type.toLowerCase().includes(searchQuery.toLowerCase());

    if (!matchesSearch) return false;

    if (filter === "attack_path") return node.in_attack_path;
    if (filter === "choke_points") return node.is_choke_point;
    return true;
  });

  // Direct connected edges for the currently selected node
  const directConnectedEdges = useMemo(() => {
    if (!selectedNode) return [];
    return allEdges.filter((e) => e.source === selectedNode.id || e.target === selectedNode.id);
  }, [selectedNode, allEdges]);

  // Handle clicking a resource from sidebar: expands focus & selects
  const handleSelectFromSidebar = (res) => {
    setSelectedNode(res);
  };

  return (
    <main className="dashboard-page">
      <div className="dashboard-header">
        <div>
          <div className="section-eyebrow">CONNECTED INFRASTRUCTURE GRAPH</div>
          <h1>Infrastructure Overview</h1>
          <p>
            Interactive network graph visualizing explicit directed relationships,
            lateral attack paths, and identified choke points.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
          {activeSource?.path && (
            <button
              className="re-scan-btn"
              onClick={() => triggerScan(activeSource.path, activeSource.name)}
              disabled={scanning}
              title="Re-run pipeline analysis for this project"
            >
              <RefreshCw size={14} className={scanning ? "spin" : ""} />
              {scanning ? "Scanning..." : "Re-scan Graph"}
            </button>
          )}

          <Link to="/" className="back-button">
            <ArrowLeft size={16} />
            Upload New Project
          </Link>
        </div>
      </div>

      <div className="analysis-source">
        <Activity size={18} />
        {`Analyzing: ${activeSource?.name || "No Project Loaded"}`}
        <span style={{ marginLeft: "auto", fontSize: "10px", color: "#087e56", fontWeight: "700" }}>
          Posture: {summary.risk_level} ({summary.risk_score})
        </span>
      </div>

      {/* METRIC CARDS */}
      <div className="dashboard-stats">
        <DashboardStat
          icon={<Box />}
          number={String(summary.resources_count)}
          label="Resources"
        />

        <DashboardStat
          icon={<Network />}
          number={String(summary.relationships_count)}
          label="Connected Links"
        />

        <DashboardStat
          icon={<ShieldAlert />}
          number={String(summary.security_findings_count)}
          label="Security Findings"
          danger={summary.security_findings_count > 0}
        />

        <DashboardStat
          icon={<Cloud />}
          number={summary.cloud_provider || "AWS"}
          label={`Cloud Provider (${summary.risk_level})`}
        />
      </div>

      {/* VISUALIZATION LAYOUT */}
      <div className="visualization-layout">
        {/* LEFT COLUMN: INTERACTIVE CONNECTED NETWORK GRAPH CANVAS */}
        <div className="graph-panel">
          <div className="panel-header">
            <div>
              <strong>Interactive Connected Network Graph</strong>
              <span>
                {filter === "attack_path"
                  ? "Showing: Traversed Attack Paths to Crown Jewels"
                  : filter === "choke_points"
                    ? "Showing: Critical Choke Points"
                    : "Click nodes or sidebar items to inspect connections • Drag to organize"}
              </span>
            </div>

            <div className="graph-filters">
              <button
                className={`filter-pill ${filter === "all" ? "active" : ""}`}
                onClick={() => setFilter("all")}
              >
                All Resources ({allNodes.length})
              </button>

              <button
                className={`filter-pill danger ${filter === "attack_path" ? "active" : ""}`}
                onClick={() => setFilter("attack_path")}
              >
                ⚡ Attack Path ({allNodes.filter((n) => n.in_attack_path).length})
              </button>

              <button
                className={`filter-pill ${filter === "choke_points" ? "active" : ""}`}
                onClick={() => setFilter("choke_points")}
              >
                🎯 Choke Points ({chokePoints.length})
              </button>
            </div>
          </div>

          {loadingGraph ? (
            <div style={{ height: "540px", display: "grid", placeItems: "center", color: "#6c7e75" }}>
              <div style={{ textAlign: "center" }}>
                <RefreshCw size={26} className="spin" style={{ margin: "0 auto 10px", display: "block", color: "#087e56" }} />
                Loading infrastructure network graph...
              </div>
            </div>
          ) : allNodes.length === 0 ? (
            <div style={{ height: "420px", display: "grid", placeItems: "center", color: "#6c7e75" }}>
              <div style={{ textAlign: "center" }}>
                <p style={{ marginBottom: "14px", fontSize: "13px" }}>No infrastructure project scanned yet.</p>
                <Link to="/" className="primary-button" style={{ display: "inline-flex" }}>
                  Upload Files or Select a Scenario
                </Link>
              </div>
            </div>
          ) : (
            <ConnectedNetworkGraphCanvas
              nodes={allNodes}
              edges={allEdges}
              selectedNode={selectedNode}
              onSelectNode={setSelectedNode}
              filter={filter}
            />
          )}
        </div>

        {/* RIGHT COLUMN: REPOSITIONED RESOURCE INSPECTION PANEL + RESOURCE DIRECTORY SIDEBAR */}
        <div className="resource-panel">
          {/* 1. RESOURCE INSPECTION PANEL (SITS CLEANLY AT THE TOP OF THE SIDEBAR) */}
          {selectedNode ? (
            <div className="sidebar-inspector">
              <div className="inspector-header">
                <div>
                  <span className="inspector-badge">INSPECTING</span>
                  <strong title={selectedNode.id}>{selectedNode.name || selectedNode.id}</strong>
                </div>
                <button
                  className="inspector-close-btn"
                  onClick={() => setSelectedNode(null)}
                  title="Close inspection"
                >
                  ✕
                </button>
              </div>

              {/* Badges row */}
              <div className="inspector-badges-row">
                {selectedNode.is_choke_point && (
                  <span className="badge badge-choke">🎯 CHOKE POINT (100% PATHS)</span>
                )}
                {selectedNode.in_attack_path && (
                  <span className="badge badge-attack">⚡ ATTACK CHAIN NODE</span>
                )}
                {selectedNode.is_crown_jewel && (
                  <span className="badge badge-crown">💎 CROWN JEWEL ASSET</span>
                )}
                {selectedNode.is_entry_point && (
                  <span className="badge badge-entry">🌐 ENTRY POINT</span>
                )}
              </div>

              {/* Meta Grid */}
              <div className="sidebar-inspector-meta">
                <div>
                  <span>Type:</span>
                  <strong>{selectedNode.type}</strong>
                </div>
                <div>
                  <span>Provider:</span>
                  <strong>{selectedNode.provider?.toUpperCase() || "AWS"}</strong>
                </div>
                <div>
                  <span>Region:</span>
                  <strong>{selectedNode.region || "us-east-1"}</strong>
                </div>
                <div>
                  <span>Source File:</span>
                  <strong title={selectedNode.source_location?.file || "main.tf"}>
                    {selectedNode.source_location?.file || "main.tf"}
                  </strong>
                </div>
              </div>

              {/* Direct Relationships List */}
              <div className="inspector-connections-section">
                <div className="connections-title">
                  Connected Links ({directConnectedEdges.length})
                </div>
                <div className="connections-list">
                  {directConnectedEdges.length === 0 ? (
                    <span style={{ fontSize: "10px", color: "#94a3b8" }}>No direct relationships detected</span>
                  ) : (
                    directConnectedEdges.map((e, idx) => {
                      const isOutbound = e.source === selectedNode.id;
                      const neighborId = isOutbound ? e.target : e.source;
                      return (
                        <div
                          key={idx}
                          className={`connection-tag ${e.in_attack_path ? "attack" : ""}`}
                          onClick={() => {
                            const neighborObj = allNodes.find((n) => n.id === neighborId);
                            if (neighborObj) setSelectedNode(neighborObj);
                          }}
                          title="Click to jump to this connected resource"
                        >
                          <span className="conn-direction">
                            {isOutbound ? "➔ Outbound:" : "⬅ Inbound:"}
                          </span>
                          <strong className="conn-neighbor">{neighborId}</strong>
                          <span className="conn-type">({e.type})</span>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="sidebar-inspector-empty">
              <Crosshair size={18} style={{ color: "#087e56", margin: "0 auto 6px", display: "block" }} />
              <strong>Interactive Inspection Ready</strong>
              <span>Click any node in the graph or resource in the list below to inspect relationships and highlight connection paths.</span>
            </div>
          )}

          {/* 2. RESOURCE LIST HEADER & SEARCH */}
          <div className="panel-header" style={{ marginTop: selectedNode ? "14px" : "0" }}>
            <div>
              <strong>Resource Directory</strong>
              <span>Detected ({filteredNodes.length})</span>
            </div>

            <div style={{ position: "relative", width: "115px" }}>
              <input
                type="text"
                placeholder="Search..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  width: "100%",
                  padding: "4px 8px 4px 22px",
                  fontSize: "10px",
                  borderRadius: "5px",
                  border: "1px solid #dce9e4",
                }}
              />
              <Search
                size={12}
                style={{ position: "absolute", left: "6px", top: "7px", color: "#8a9b93" }}
              />
            </div>
          </div>

          {/* 3. SCROLLABLE RESOURCE LIST */}
          <div style={{ maxHeight: "400px", overflowY: "auto" }}>
            {filteredNodes.slice(0, 30).map((res) => (
              <div
                key={res.id}
                onClick={() => handleSelectFromSidebar(res)}
                style={{ cursor: "pointer" }}
              >
                <ResourceRow
                  icon={getResourceIcon(res.type)}
                  name={res.name || res.id}
                  type={res.type}
                  badges={
                    res.is_choke_point ? (
                      <span className="badge badge-choke">CHOKE</span>
                    ) : res.in_attack_path ? (
                      <span className="badge badge-attack">PATH</span>
                    ) : null
                  }
                />
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* SECURITY FINDINGS PANEL WITH INTERACTIVE ACCORDIONS & ON-DEMAND REMEDIATION */}
      <div className="findings-panel">
        <div className="panel-header">
          <div>
            <strong>Security Findings ({allFindings.length})</strong>
            <span>Detected during infrastructure graph analysis • Click any finding to inspect details</span>
          </div>

          <Link to="/insights" className="view-insights">
            View AI Insights & Fixes
            <ChevronRight size={15} />
          </Link>
        </div>

        {allFindings.length === 0 ? (
          <div style={{ padding: "20px", fontSize: "11px", color: "#6c7e75" }}>
            No security findings detected. Infrastructure configuration appears compliant.
          </div>
        ) : (
          allFindings.map((finding) => (
            <FindingCard
              key={finding.id}
              finding={finding}
              onSelectResource={(resId) => {
                const target = allNodes.find((n) => n.id === resId);
                if (target) setSelectedNode(target);
              }}
            />
          ))
        )}
      </div>
    </main>
  );
}

/* =========================================================
   INTERACTIVE FINDING CARD (ACCORDION WITH ON-DEMAND FIXES)
========================================================= */

function FindingCard({ finding, onSelectResource }) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [showRemediation, setShowRemediation] = useState(false);
  const navigate = useNavigate();

  return (
    <div className={`finding-card-accordion ${isExpanded ? "expanded" : ""}`}>
      {/* Finding Row Header */}
      <div
        className="finding-header-row"
        onClick={() => setIsExpanded((prev) => !prev)}
      >
        <div className={`severity ${(finding.severity || "MEDIUM").toLowerCase()}`}>
          {finding.severity || "MEDIUM"}
        </div>

        <div className="finding-content">
          <strong>{finding.title}</strong>
          <span>{finding.description}</span>
          {finding.resource && (
            <span style={{ color: "#087e56", fontWeight: "600", marginTop: "2px" }}>
              Affected: {finding.resource}
            </span>
          )}
        </div>

        <button
          type="button"
          className="finding-expand-btn"
          aria-label={isExpanded ? "Collapse finding details" : "Expand finding details"}
        >
          {isExpanded ? <ChevronDown size={17} /> : <ChevronRight size={17} />}
        </button>
      </div>

      {/* Expandable Details Drawer */}
      {isExpanded && (
        <div className="finding-expanded-body">
          <div className="finding-meta-tags">
            <span><strong>Rule ID:</strong> {finding.id}</span>
            <span><strong>Category:</strong> {finding.category || "NETWORK_EXPOSURE"}</span>
            {finding.resource && (
              <button
                type="button"
                className="finding-resource-link-btn"
                onClick={() => onSelectResource(finding.resource)}
                title="Highlight affected resource on graph canvas"
              >
                🎯 Focus on Graph: {finding.resource}
              </button>
            )}
          </div>

          {finding.attack_vector && (
            <p className="finding-vector-text">
              <strong>Attack Vector:</strong> {finding.attack_vector}
            </p>
          )}

          {/* ON-DEMAND REMEDIATION TOGGLE */}
          <div className="remediation-toggle-section">
            <button
              type="button"
              className="remediation-toggle-action-btn"
              onClick={() => setShowRemediation((prev) => !prev)}
            >
              {showRemediation ? <EyeOff size={13} /> : <Eye size={13} />}
              {showRemediation ? "Hide Remediation Guidance" : "View Remediation Guidance"}
            </button>

            {showRemediation && (
              <div className="remediation-revealed-panel">
                <div className="remediation-text">
                  <strong>Recommended Fix:</strong>{" "}
                  {finding.recommendation || "Apply least-privilege security controls and restrict open network egress."}
                </div>

                <button
                  type="button"
                  className="remediation-navigate-btn"
                  onClick={() => navigate("/insights")}
                >
                  <Sparkles size={13} />
                  Generate Strict AI Patches on AI Insights Page
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* =========================================================
   AI INSIGHTS & REMEDIATION PAGE (CONNECTED AI ENGINE)
========================================================= */

function DashboardStat({ icon, number, label, danger }) {
  return (
    <div className="dashboard-stat">
      <div className={`dashboard-stat-icon ${danger ? "danger" : ""}`}>
        {icon}
      </div>

      <div>
        <strong>{number}</strong>
        <span>{label}</span>
      </div>
    </div>
  );
}

function ResourceRow({ icon, name, type, badges }) {
  return (
    <div className="resource-row">
      <div className="resource-row-icon">{icon}</div>

      <div>
        <strong>{name}</strong>
        <span>{type}</span>
      </div>

      {badges}
      <ChevronRight size={15} />
    </div>
  );
}

export default VisualizePage;
