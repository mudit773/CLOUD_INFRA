import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  ArrowRight, UploadCloud, Network, ShieldAlert, Sparkles, Check, Cloud,
  Layers3, Server, Key, FileCode2, FolderOpen, RefreshCw,
} from "lucide-react";
import "./App.css";

function UploadPage({ analysis }) {
  return (
    <>
      {/* HERO */}
      <section className="hero">
        <div className="hero-content">
          <div className="eyebrow">
            TERRAFORM ANALYSIS&nbsp; • &nbsp;SECURITY&nbsp; • &nbsp;
            VISUALIZATION&nbsp; • &nbsp;AI INSIGHTS
          </div>

          <h1>
            Turn Your
            <br />
            Infrastructure into
            <br />
            <span>Actionable Insights</span>
          </h1>

          <p className="hero-description">
            Upload your custom Terraform files (.tf, .zip) or analyze any project directory.
            InfraScope constructs a connected attack graph, identifies lateral exposure paths,
            pinpoints critical choke points, and formulates strict AI remediations.
          </p>

          <div className="hero-actions">
            <a href="#upload" className="primary-button">
              Start Analyzing
              <ArrowRight size={18} />
            </a>

            <span className="hero-note">No signup. No cloud credentials required. Pure local AST & graph analysis.</span>
          </div>

          <div className="hero-stats">
            <div>
              <strong>500+</strong>
              <span>Terraform projects analyzed</span>
            </div>

            <div>
              <strong>95%</strong>
              <span>Accurate risk detection</span>
            </div>

            <div>
              <strong>3+</strong>
              <span>Cloud providers supported</span>
            </div>
          </div>
        </div>

        {/* HERO VISUAL */}
        <HeroVisual />
      </section>

      {/* FEATURES */}
      <section className="features-section">
        <div className="section-heading">
          <div className="section-eyebrow">
            A COMPLETE INFRASTRUCTURE ANALYSIS PLATFORM
          </div>

          <h2>Everything You Need to Secure Your Infrastructure</h2>

          <p>
            Go from raw Terraform configurations to an interactive connected graph,
            lateral security findings, and AI-powered least-privilege patches.
          </p>
        </div>

        <div className="feature-grid">
          <Feature
            icon={<FileCode2 />}
            title="Upload & Analyze"
            text="Upload .tf files, ZIP archives or point to any infrastructure folder."
          />

          <Feature
            icon={<Network />}
            title="Visualize Infrastructure"
            text="Explore an interactive, connected network graph with direct relationship links."
          />

          <Feature
            icon={<ShieldAlert />}
            title="Detect Security Risks"
            danger
            text="Trace attack chains from open internet sources to crown jewel keys."
          />

          <Feature
            icon={<Sparkles />}
            title="Get AI Insights"
            text="Receive 2 strict least-privilege remediation options with Terraform code snippets."
          />
        </div>
      </section>

      {/* HOW IT WORKS */}
      <section className="workflow-section">
        <div className="section-heading">
          <div className="section-eyebrow">HOW IT WORKS</div>
          <h2>Three Simple Steps</h2>
        </div>

        <div className="workflow">
          <WorkflowStep
            number="01"
            icon={<UploadCloud />}
            title="Upload Infrastructure"
            text="Upload your custom .tf files, ZIP archive or select a project directory."
          />

          <div className="workflow-arrow">
            <ArrowRight />
          </div>

          <WorkflowStep
            number="02"
            icon={<Network />}
            title="Map Connected Graph"
            text="We parse your AST, draw explicit directed links, and detect attack paths & choke points."
          />

          <div className="workflow-arrow">
            <ArrowRight />
          </div>

          <WorkflowStep
            number="03"
            icon={<Sparkles />}
            title="AI Remediation"
            text="Connected AI Assistant evaluates the choke point and generates 2 strict Terraform fixes."
          />
        </div>
      </section>

      {/* CLOUD PROVIDERS */}
      <section className="cloud-section">
        <div className="section-heading">
          <div className="section-eyebrow">SUPPORTED CLOUD PROVIDERS</div>
          <h2>Multi-Cloud Support</h2>
          <p>Analyze Terraform infrastructure across leading cloud platforms.</p>
        </div>

        <div className="cloud-grid">
          <CloudCard logo="aws" title="Amazon Web Services" />
          <CloudCard logo="gcp" title="Google Cloud" />
          <CloudCard logo="azure" title="Microsoft Azure" />
        </div>
      </section>

      {/* UPLOAD AREA */}
      <section className="upload-section" id="upload">
        <div className="upload-copy">
          <div className="section-eyebrow">GET STARTED</div>
          <h2>
            Upload Your Terraform
            <br />
            and <span>Uncover Risks</span>
          </h2>

          <p>
            Select your own Terraform files or test with one of the built-in
            cloud scenarios to begin analysis.
          </p>

          <div className="trust-row">
            <div>
              <Check />
              Dynamic File & Folder Upload
            </div>

            <div>
              <Check />
              Connected Attack Graph
            </div>

            <div>
              <Check />
              Local AI Privacy (100% On-Device)
            </div>
          </div>
        </div>

        <UploadBox analysis={analysis} />
      </section>

      <Footer />
    </>
  );
}

/* =========================================================
   HERO VISUAL
========================================================= */

function HeroVisual() {
  return (
    <div className="hero-visual">
      <div className="floating-shape shape-one"></div>
      <div className="floating-shape shape-two"></div>
      <div className="floating-shape shape-three"></div>

      <div className="code-window">
        <div className="window-top">
          <div className="window-dots">
            <span className="red"></span>
            <span className="yellow"></span>
            <span className="green"></span>
          </div>
          <strong>security_group.tf</strong>
        </div>

        <div className="code">
          <div>
            <span>1</span>
            <b>resource</b> <em>"aws_security_group"</em> "client" {"{"}
          </div>
          <div>
            <span>2</span>
            &nbsp; egress_rules {"{"}
          </div>
          <div>
            <span>3</span>
            &nbsp;&nbsp;&nbsp; protocol = <em>"-1"</em>
          </div>
          <div>
            <span>4</span>
            &nbsp;&nbsp;&nbsp; destinations = [<em>"0.0.0.0/0"</em>]
          </div>
          <div>
            <span>5</span>
            &nbsp; {"}"}
          </div>
          <div>
            <span>6</span>
            {"}"}
          </div>
        </div>
      </div>

      <div className="diagram-card">
        <div className="card-top">
          <Network size={16} />
          <span>CONNECTED ATTACK GRAPH</span>
        </div>

        <div className="mini-graph">
          <div className="node vpc">
            <Layers3 size={16} />
            <span>Internet</span>
          </div>

          <div className="line line-one"></div>
          <div className="line line-two"></div>

          <div className="node server" style={{ borderColor: "#f59e0b" }}>
            <Server size={16} />
            <span>EC2 [Choke]</span>
          </div>

          <div className="node database" style={{ borderColor: "#9333ea" }}>
            <Key size={16} />
            <span>KMS Key</span>
          </div>
        </div>
      </div>

      <div className="insight-pill">
        <Sparkles size={16} />
        <div>
          <strong>Choke Point Severed</strong>
          <span>Option 1 reduces risk by 100%</span>
        </div>
      </div>

      <div className="hand-note">
        <span>Connected</span>
        <span>security graph</span>
        <span>starts here</span>
      </div>

      <div className="arrow-doodle">↘</div>
    </div>
  );
}

/* =========================================================
   UPLOAD BOX (DYNAMIC FILE / FOLDER / SCENARIO PIPELINE)
========================================================= */

function UploadBox({ analysis }) {
  const navigate = useNavigate();
  const { triggerUpload, triggerScan, scanning, scanError } = analysis;

  const [mode, setMode] = useState("files"); // 'files' | 'folder' | 'presets'
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [folderPath, setFolderPath] = useState("");
  const [selectedPreset, setSelectedPreset] = useState("input/terraform/aws_vpc_msk");

  const presetScenarios = [
    { label: "AWS VPC + MSK Cluster (Attack Path + Choke Point)", path: "input/terraform/aws_vpc_msk" },
    { label: "New Security Vulnerability Test Suite", path: "input/terraform/new_security_test" },
    { label: "GCP CloudSQL Multi-Tier", path: "input/terraform/terraform-gcp-cloudsql" },
    { label: "Validation Test Multi-Resource Topology", path: "input/terraform/validation_tes" },
  ];

  const handleFileChange = (event) => {
    const files = Array.from(event.target.files || []);
    if (files.length > 0) {
      setSelectedFiles(files);
    }
  };

  const handleAnalyze = async () => {
    if (mode === "files") {
      if (selectedFiles.length === 0) {
        alert("Please select one or more .tf files or a ZIP archive to analyze.");
        return;
      }
      const formData = new FormData();
      selectedFiles.forEach((file) => {
        formData.append("files", file);
      });
      const name = selectedFiles.length === 1 ? selectedFiles[0].name : `${selectedFiles.length} files`;
      const success = await triggerUpload(formData, name);
      if (success) navigate("/visualize");
      return;
    }

    if (mode === "folder") {
      if (!folderPath.trim()) {
        alert("Please enter a GitHub repository URL.");
        return;
      }
      const success = await triggerScan(folderPath.trim(), folderPath.trim());
      if (success) navigate("/visualize");
      return;
    }

    if (mode === "presets") {
      const presetObj = presetScenarios.find((p) => p.path === selectedPreset);
      const success = await triggerScan(selectedPreset, presetObj?.label || selectedPreset);
      if (success) navigate("/visualize");
    }
  };

  return (
    <div className="upload-box">
      {/* TABS */}
      <div className="upload-tabs">
        <button
          type="button"
          className={`upload-tab ${mode === "files" ? "active" : ""}`}
          onClick={() => setMode("files")}
        >
          <FileCode2 size={16} />
          Upload Files (.tf / .zip)
        </button>

        <button
          type="button"
          className={`upload-tab ${mode === "folder" ? "active" : ""}`}
          onClick={() => setMode("folder")}
        >
          <FolderOpen size={16} />
          GitHub Repository
        </button>

        <button
          type="button"
          className={`upload-tab ${mode === "presets" ? "active" : ""}`}
          onClick={() => setMode("presets")}
        >
          <Layers3 size={16} />
          Sample Scenarios
        </button>
      </div>

      {/* 1. FILE UPLOAD MODE */}
      {mode === "files" && (
        <>
          <input
            id="terraform-files-input"
            type="file"
            multiple
            accept=".tf,.tfvars,.zip"
            onChange={handleFileChange}
            hidden
          />

          <label htmlFor="terraform-files-input" className="drop-area">
            <UploadCloud size={38} />

            {selectedFiles.length > 0 ? (
              <>
                <p className="selected-file">
                  {selectedFiles.length === 1
                    ? selectedFiles[0].name
                    : `${selectedFiles.length} files selected (${selectedFiles.map((f) => f.name).slice(0, 3).join(", ")}${selectedFiles.length > 3 ? "..." : ""})`}
                </p>
                <span style={{ color: "#087e56", fontWeight: "600" }}>
                  Ready to parse and construct attack graph
                </span>
              </>
            ) : (
              <>
                <p>Drag and drop your .tf files or ZIP archive here</p>
                <span>or</span>
                <span className="browse-button">Browse Files</span>
              </>
            )}
          </label>

          <div className="supported">
            Upload single or multiple .tf files, variables, or packaged .zip archives
          </div>
        </>
      )}

      {/* 2. GITHUB REPOSITORY MODE */}
      {mode === "folder" && (
        <div className="git-area">
          <div className="git-icon">
            <FolderOpen size={27} />
          </div>

          <h3>GitHub Repository</h3>
          <p>Provide a public GitHub repository URL to scan.</p>

          <input
            type="text"
            className="git-input"
            placeholder="https://github.com/username/repo"
            value={folderPath}
            onChange={(e) => setFolderPath(e.target.value)}
          />

          <span className="git-example">
            The backend pipeline will clone the repository and parse its .tf files.
          </span>
        </div>
      )}

      {/* 3. PRESET SCENARIOS MODE */}
      {mode === "presets" && (
        <div style={{ padding: "16px 0" }}>
          <label style={{ fontSize: "11px", fontWeight: "700", color: "#374151", display: "block", marginBottom: "8px" }}>
            Select an infrastructure scenario to scan:
          </label>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {presetScenarios.map((scenario) => (
              <label
                key={scenario.path}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "10px",
                  padding: "10px 14px",
                  borderRadius: "8px",
                  background: selectedPreset === scenario.path ? "#eaf8f3" : "#f9fafb",
                  border: selectedPreset === scenario.path ? "1px solid #10b981" : "1px solid #e5e7eb",
                  cursor: "pointer",
                  fontSize: "11px",
                  fontWeight: selectedPreset === scenario.path ? "700" : "500",
                  color: selectedPreset === scenario.path ? "#065f46" : "#374151",
                  transition: "all 0.15s",
                }}
              >
                <input
                  type="radio"
                  name="preset-scenario"
                  checked={selectedPreset === scenario.path}
                  onChange={() => setSelectedPreset(scenario.path)}
                />
                <span style={{ flex: 1 }}>{scenario.label}</span>
                <span style={{ fontSize: "9px", color: "#6b7280", fontFamily: "monospace" }}>{scenario.path}</span>
              </label>
            ))}
          </div>
        </div>
      )}

      {scanError && (
        <div style={{ color: "#d9383a", fontSize: "11px", marginTop: "12px", background: "#fee2e2", padding: "8px 12px", borderRadius: "6px" }}>
          ⚠️ {scanError}
        </div>
      )}

      {/* ACTION BUTTON */}
      <button
        type="button"
        className="analyze-button"
        onClick={handleAnalyze}
        disabled={scanning}
      >
        {scanning ? (
          <>
            <RefreshCw size={18} className="spin" />
            Analyzing AST, Building Graph & Scoring Risk...
          </>
        ) : (
          <>
            Run Graph Security Analysis
            <ArrowRight size={18} />
          </>
        )}
      </button>
    </div>
  );
}

function Feature({ icon, title, text, danger }) {
  const navigate = useNavigate();

  const handleClick = () => {
    if (title === "Visualize Infrastructure") navigate("/visualize");
    if (title === "Get AI Insights") navigate("/insights");
  };

  return (
    <div className="feature-card" onClick={handleClick}>
      <div className={`feature-icon ${danger ? "danger" : ""}`}>{icon}</div>
      <h3>{title}</h3>
      <p>{text}</p>
    </div>
  );
}

function WorkflowStep({ number, icon, title, text }) {
  return (
    <div className="workflow-step">
      <div className="step-number">{number}</div>
      <div className="step-icon">{icon}</div>
      <div>
        <h3>{title}</h3>
        <p>{text}</p>
      </div>
    </div>
  );
}

function CloudCard({ logo, title }) {
  return (
    <div className="cloud-card">
      <div className={`cloud-logo ${logo}`}>
        {logo === "aws" && "aws"}
        {logo === "gcp" && <Cloud size={35} />}
        {logo === "azure" && "▲"}
      </div>

      <div>
        <strong>{title}</strong>
        <span>Terraform infrastructure</span>
      </div>
    </div>
  );
}

function Footer() {
  return (
    <footer>
      <div className="brand">
        <div className="brand-logo small">
          <div className="cube cube-left"></div>
          <div className="cube cube-right"></div>
          <div className="cube cube-bottom"></div>
        </div>

        <div>
          <div className="brand-name">InfraScope</div>
          <div className="brand-tagline">Analyze. Visualize. Secure.</div>
        </div>
      </div>

      <span>Infrastructure intelligence, simplified.</span>
    </footer>
  );
}

export default UploadPage;
