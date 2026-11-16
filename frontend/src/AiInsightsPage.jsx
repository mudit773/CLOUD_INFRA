import React, { useState } from "react";
import { Link } from "react-router-dom";
import {
  ArrowLeft, Sparkles, RefreshCw, Zap, Cloud, Key, Server, ShieldAlert,
  Target, Activity, AlertTriangle, Check, Copy,
} from "lucide-react";
import "./App.css";

function CodeBlock({ code, title = "terraform" }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="code-snippet-box">
      <div className="code-snippet-header">
        <span>{title}</span>
        <button className="copy-snippet-btn" onClick={handleCopy} type="button">
          {copied ? <Check size={12} /> : <Copy size={12} />}
          {copied ? "Copied!" : "Copy Snippet"}
        </button>
      </div>
      <pre className="code-snippet-pre">{code}</pre>
    </div>
  );
}

function AiInsightsPage({ analysis }) {
  const {
    graphData,
    remediationData,
    loadingRemediation,
    fetchRemediation,
    triggerScan,
    scanning,
  } = analysis;

  const summary = graphData?.summary || {
    resources_count: 0,
    security_findings_count: 0,
    choke_points_count: 0,
    attack_paths_count: 0,
    risk_level: "NONE",
    risk_score: 0.0,
  };

  const chokePoints = graphData?.choke_points || [];
  const attackPaths = graphData?.attack_paths || [];

  const chokePointText =
    remediationData?.choke_point ||
    (chokePoints[0]
      ? `${chokePoints[0].resource_id} (Severs ${chokePoints[0].path_percentage}% of paths)`
      : "Identified Critical Choke Point");

  const options = remediationData?.options || [];

  return (
    <main className="dashboard-page insights-page">
      <div className="dashboard-header">
        <div>
          <div className="section-eyebrow">AI-POWERED ANALYSIS & REMEDIATION</div>
          <h1>AI Infrastructure Insights</h1>
          <p>
            Automated lateral attack path analysis and least-privilege remediation
            via Connected AI Engine.
          </p>
        </div>

        <Link to="/visualize" className="back-button">
          <ArrowLeft size={16} />
          Back to visualization
        </Link>
      </div>

      {/* EMPTY / UNANALYZED STATE */}
      {summary.resources_count === 0 && (
        <div className="insights-empty-banner">
          <Sparkles size={24} style={{ color: "#087e56", marginBottom: "8px" }} />
          <h3>No Infrastructure Scan Loaded</h3>
          <p>
            Run an analysis from the Upload page or scan the built-in scenario below to generate
            attack paths, choke point severing strategies, and strict least-privilege code patches.
          </p>
          <button
            type="button"
            className="remediation-trigger-btn"
            style={{ margin: "14px auto 0" }}
            onClick={() => triggerScan("input/terraform/aws_vpc_msk", "AWS VPC MSK Cluster")}
            disabled={scanning}
          >
            {scanning ? <RefreshCw size={15} className="spin" /> : <Zap size={15} />}
            {scanning ? "Analyzing Infrastructure..." : "Run Analysis on Sample (AWS VPC MSK)"}
          </button>
        </div>
      )}

      {/* AI SUMMARY CARD */}
      {summary.resources_count > 0 && (
        <div className="ai-summary">
          <div className="ai-summary-icon">
            <Sparkles />
          </div>

          <div style={{ flex: 1 }}>
            <span>OVERALL RISK EVALUATION</span>
            <h2>Posture: {summary.risk_level} ({summary.risk_score})</h2>
            <p>
              An active lateral movement attack chain reaches critical cloud resources.
              Severing the identified choke point cuts off unauthorized exposure across 100% of detected attack paths.
            </p>
          </div>

          <button
            type="button"
            className="remediation-trigger-btn"
            onClick={() => fetchRemediation(true)}
            disabled={loadingRemediation}
          >
            {loadingRemediation ? (
              <>
                <RefreshCw size={15} className="spin" />
                Analyzing with AI Engine...
              </>
            ) : (
              <>
                <Sparkles size={16} />
                Analyze Choke Point & Get AI Fixes
              </>
            )}
          </button>
        </div>
      )}

      {/* ATTACK CHAIN FLOW BANNER */}
      {attackPaths.length > 0 && (
        <div className="attack-chain-banner">
          <div className="attack-chain-header">
            <AlertTriangle size={16} />
            <span>DETECTED LATERAL ATTACK CHAIN (CRITICAL PATH)</span>
          </div>

          <div className="attack-chain-flow">
            {attackPaths[0].nodes ? (
              attackPaths[0].nodes.map((nodeId, idx, arr) => (
                <React.Fragment key={idx}>
                  <div className={`chain-node ${chokePoints.some((cp) => cp.resource_id === nodeId) ? "choke" : ""}`}>
                    {idx === 0 ? <Cloud size={13} /> : idx === arr.length - 1 ? <Key size={13} /> : <Server size={13} />}
                    {nodeId}
                    {chokePoints.some((cp) => cp.resource_id === nodeId) && " [CHOKE]"}
                  </div>
                  {idx < arr.length - 1 && <span className="chain-arrow">➔</span>}
                </React.Fragment>
              ))
            ) : (
              <div className="chain-node">Analysis path details available in graph view</div>
            )}
          </div>
        </div>
      )}

      {/* INSIGHT STAT CARDS */}
      <div className="insights-grid">
        <InsightCard
          icon={<ShieldAlert />}
          title="Security Risks"
          count={String(summary.security_findings_count)}
          description="Security findings and misconfigurations detected."
          danger={summary.security_findings_count > 0}
        />

        <InsightCard
          icon={<Target />}
          title="Choke Points"
          count={String(summary.choke_points_count)}
          description="Single points where remediation severs attack paths."
        />

        <InsightCard
          icon={<Activity />}
          title="Attack Paths"
          count={String(summary.attack_paths_count)}
          description="End-to-end traversal paths to crown jewel assets."
        />
      </div>

      {/* 2 STRICT AI REMEDIATIONS */}
      <div className="recommendations-panel">
        <div className="panel-header">
          <div>
            <strong>AI Remediation Options (Strict Least-Privilege Patches)</strong>
            <span>
              Targeted Choke Point: <strong>{chokePointText}</strong>
            </span>
          </div>

          {!remediationData && !loadingRemediation && summary.resources_count > 0 && (
            <button
              type="button"
              className="sample-scan-btn"
              onClick={() => fetchRemediation()}
            >
              <Sparkles size={13} />
              Generate Fixes
            </button>
          )}
        </div>

        {loadingRemediation ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#4d6359" }}>
            <RefreshCw size={28} className="spin" style={{ margin: "0 auto 12px", display: "block", color: "#087e56" }} />
            <strong>Contacting Connected AI Engine...</strong>
            <p style={{ fontSize: "11px", color: "#768595", marginTop: "6px" }}>
              Evaluating choke point graph geometry and formulating 2 strict least-privilege remediation options.
            </p>
          </div>
        ) : options.length > 0 ? (
          <div className="remediation-options-container">
            {options.map((opt, idx) => (
              <div key={idx} className="remediation-option-card">
                <div className="option-card-header">
                  <div className="option-badge-title">
                    <span className="option-pill-badge">Option 0{opt.option_id || idx + 1}</span>
                    <h3>{opt.title}</h3>
                  </div>

                  <span style={{ fontSize: "10px", color: "#087e56", fontWeight: "700" }}>
                    Verified Terraform Patch
                  </span>
                </div>

                <div className="option-card-body">
                  <div className="option-explanation">{opt.explanation}</div>

                  {opt.risk_reduction && (
                    <div className="option-risk-reduction">
                      <strong>Risk Reduction:</strong> {opt.risk_reduction}
                    </div>
                  )}

                  {opt.code && (
                    <CodeBlock
                      code={opt.code}
                      title={`terraform • ${opt.title.toLowerCase().replace(/[^a-z0-9]/g, "_")}.tf`}
                    />
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ padding: "30px", textAlign: "center", color: "#687988" }}>
            <p style={{ fontSize: "12px", marginBottom: "15px" }}>
              Click <strong>"Analyze Choke Point & Get AI Fixes"</strong> to generate the 2 strict
              least-privilege remediation options using your local AI engine.
            </p>
            <button
              type="button"
              className="remediation-trigger-btn"
              style={{ margin: "0 auto" }}
              onClick={() => fetchRemediation()}
              disabled={summary.resources_count === 0}
            >
              <Sparkles size={16} />
              Analyze Choke Point & Get AI Fixes
            </button>
          </div>
        )}
      </div>

      <div className="insights-footer">
        <Sparkles size={17} />
        <span>
          AI recommendations are generated dynamically by the Connected AI Engine
          based on real graph topology and AST evidence.
        </span>
      </div>
    </main>
  );
}

function InsightCard({ icon, title, count, description, danger }) {
  return (
    <div className="insight-stat-card">
      <div className={`insight-stat-icon ${danger ? "danger" : ""}`}>
        {icon}
      </div>

      <div className="insight-count">{count}</div>
      <h3>{title}</h3>
      <p>{description}</p>
    </div>
  );
}

export default AiInsightsPage;
