import React, { createContext, useCallback, useContext, useEffect, useState } from "react";
import { Route, Routes, Link, NavLink } from "react-router-dom";
import UploadPage from "./UploadPage.jsx";
import VisualizePage from "./VisualizePage.jsx";
import AiInsightsPage from "./AiInsightsPage.jsx";
import "./App.css";

const AnalysisContext = createContext(null);

export function AnalysisProvider({ children }) {
  const [graphData, setGraphData] = useState(null);
  const [remediationData, setRemediationData] = useState(null);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [loadingRemediation, setLoadingRemediation] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [filter, setFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [activeSource, setActiveSource] = useState(null);

  const fetchGraph = useCallback(async (force = false) => {
    if (graphData && !force) return;
    setLoadingGraph(true);
    setScanError(null);
    try {
      const res = await fetch("/api/graph");
      if (!res.ok) throw new Error(`Backend error (${res.status})`);
      const data = await res.json();
      if (data && data.nodes && data.nodes.length > 0) {
        setGraphData(data);
        if (!activeSource) {
          setActiveSource({
            name: data.metadata?.project_name || "Existing Analysis",
            type: "Terraform Infrastructure",
          });
        }
      }
    } catch (err) {
      console.warn("Failed to fetch graph data:", err);
      setScanError(err.message);
    } finally {
      setLoadingGraph(false);
    }
  }, [graphData, activeSource]);

  const triggerScan = useCallback(async (inputPath, sourceName = null) => {
    if (!inputPath) return false;
    setScanning(true);
    setScanError(null);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input_path: inputPath, output_path: "output/terraform.json" }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || errData.message || `Scan failed: ${res.status}`);
      }
      const result = await res.json();
      if (result.data) {
        setGraphData(result.data);
        setSelectedNode(null);
      }
      setActiveSource({
        name: sourceName || inputPath,
        type: "Terraform Folder",
        path: inputPath,
      });
      setRemediationData(null);
      return true;
    } catch (err) {
      console.error("Pipeline scan error:", err);
      setScanError(err.message);
      return false;
    } finally {
      setScanning(false);
    }
  }, []);

  const triggerUpload = useCallback(async (formData, sourceName = "Uploaded Terraform") => {
    setScanning(true);
    setScanError(null);
    try {
      const res = await fetch("/api/upload", { method: "POST", body: formData });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || errData.message || `Upload failed: ${res.status}`);
      }
      const result = await res.json();
      if (!result.upload_path) throw new Error("Upload did not return an upload path.");
      const success = await triggerScan(result.upload_path, sourceName);
      if (!success) return false;
      setActiveSource({
        name: result.source_name || sourceName,
        type: "Uploaded Files",
        path: result.upload_path,
      });
      return true;
    } catch (err) {
      console.error("Upload error:", err);
      setScanError(err.message);
      return false;
    } finally {
      setScanning(false);
    }
  }, [triggerScan]);

  const fetchRemediation = useCallback(async (force = false) => {
    if (remediationData && !force) return;
    setLoadingRemediation(true);
    try {
      const res = await fetch("/api/remediate");
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `AI service error: ${res.status}`);
      }
      const data = await res.json();
      setRemediationData(data);
    } catch (err) {
      console.error("Failed to generate remediation:", err);
      alert(err.message);
    } finally {
      setLoadingRemediation(false);
    }
  }, [remediationData]);

  useEffect(() => {
    fetchGraph();
  }, []);

  return (
    <AnalysisContext.Provider value={{
      graphData,
      remediationData,
      loadingGraph,
      loadingRemediation,
      scanning,
      scanError,
      selectedNode,
      setSelectedNode,
      filter,
      setFilter,
      searchQuery,
      setSearchQuery,
      activeSource,
      setActiveSource,
      fetchGraph,
      triggerScan,
      triggerUpload,
      fetchRemediation,
    }}>
      {children}
    </AnalysisContext.Provider>
  );
}

export function useAnalysis() {
  const context = useContext(AnalysisContext);
  if (!context) throw new Error("useAnalysis must be used within an AnalysisProvider");
  return context;
}

function AppRoutes() {
  const analysis = useAnalysis();
  return (
    <div className="app">
      <Navbar />
      <Routes>
        <Route path="/" element={<UploadPage analysis={analysis} />} />
        <Route path="/visualize" element={<VisualizePage analysis={analysis} />} />
        <Route path="/insights" element={<AiInsightsPage analysis={analysis} />} />
      </Routes>
    </div>
  );
}

function Navbar() {
  return (
    <nav className="navbar">
      <Link to="/" className="brand">
        <div className="brand-logo">
          <div className="cube cube-left"></div>
          <div className="cube cube-right"></div>
          <div className="cube cube-bottom"></div>
        </div>
        <div>
          <div className="brand-name">InfraScope</div>
          <div className="brand-tagline">Analyze. Visualize. Secure.</div>
        </div>
      </Link>
      <div className="nav-links">
        <NavLink to="/" className={({ isActive }) => (isActive ? "active" : "")}>Upload</NavLink>
        <NavLink to="/visualize" className={({ isActive }) => (isActive ? "active" : "")}>Visualize</NavLink>
        <NavLink to="/insights" className={({ isActive }) => (isActive ? "active" : "")}>AI Insights</NavLink>
      </div>
    </nav>
  );
}

export default function App() {
  return (
    <AnalysisProvider>
      <AppRoutes />
    </AnalysisProvider>
  );
}
