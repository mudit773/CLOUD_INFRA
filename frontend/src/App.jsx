import React, { useState } from "react";

import {
  ArrowRight,
  ArrowLeft,
  UploadCloud,
  Network,
  ShieldCheck,
  Sparkles,
  Server,
  Database,
  ShieldAlert,
  Check,
  Cloud,
  Layers3,
  GitBranch,
  FileCode2,
  Search,
  
  Lock,
  Activity,
  AlertTriangle,
  ChevronRight,
  Box,
} from "lucide-react";

import {
  Routes,
  Route,
  Link,
  NavLink,
  useNavigate,
  useLocation,
} from "react-router-dom";

import "./App.css";


/* =========================================================
   MAIN APP
========================================================= */

function App() {
  return (
    <div className="app">
      <Navbar />

      <Routes>
        <Route path="/" element={<UploadPage />} />
        <Route path="/visualize" element={<VisualizePage />} />
        <Route path="/insights" element={<InsightsPage />} />
      </Routes>
    </div>
  );
}


/* =========================================================
   NAVBAR
========================================================= */

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
          <div className="brand-tagline">
            Analyze. Visualize. Secure.
          </div>
        </div>
      </Link>


      <div className="nav-links">

        <NavLink
          to="/"
          className={({ isActive }) =>
            isActive ? "active" : ""
          }
        >
          Upload
        </NavLink>

        <NavLink
          to="/visualize"
          className={({ isActive }) =>
            isActive ? "active" : ""
          }
        >
          Visualize
        </NavLink>

        <NavLink
          to="/insights"
          className={({ isActive }) =>
            isActive ? "active" : ""
          }
        >
          AI Insights
        </NavLink>

      </div>


     

    </nav>
  );
}


/* =========================================================
   UPLOAD / LANDING PAGE
========================================================= */

function UploadPage() {
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
            Upload your Terraform files or connect a Git repository.
            We analyze your infrastructure, visualize resource
            relationships, detect security risks, and provide
            AI-powered recommendations.
          </p>


          <div className="hero-actions">

            <a href="#upload" className="primary-button">
              Start Analyzing
              <ArrowRight size={18} />
            </a>

            <span className="hero-note">
              No signup. No login. Just insights.
            </span>

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

          <h2>
            Everything You Need to Secure Your Infrastructure
          </h2>

          <p>
            Go from Terraform code to visual infrastructure,
            security findings, and AI-powered recommendations —
            in a few clicks.
          </p>

        </div>


        <div className="feature-grid">

          <Feature
            icon={<FileCode2 />}
            title="Upload & Analyze"
            text="Upload .tf files, ZIP archives or connect a Git repository."
          />

          <Feature
            icon={<Network />}
            title="Visualize Infrastructure"
            text="See your resources and relationships in an interactive graph."
          />

          <Feature
            icon={<ShieldAlert />}
            title="Detect Security Risks"
            danger
            text="Identify misconfigurations, vulnerabilities and compliance issues early."
          />

          <Feature
            icon={<Sparkles />}
            title="Get AI Insights"
            text="Receive clear explanations and actionable remediation steps."
          />

        </div>

      </section>


      {/* HOW IT WORKS */}

      <section className="workflow-section">

        <div className="section-heading">

          <div className="section-eyebrow">
            HOW IT WORKS
          </div>

          <h2>
            Three Simple Steps
          </h2>

        </div>


        <div className="workflow">

          <WorkflowStep
            number="01"
            icon={<UploadCloud />}
            title="Upload Infrastructure"
            text="Upload your .tf files, ZIP archive or provide a Git repository URL."
          />

          <div className="workflow-arrow">
            <ArrowRight />
          </div>

          <WorkflowStep
            number="02"
            icon={<Network />}
            title="Analyze & Map"
            text="We parse your infrastructure, identify resources, relationships and security risks."
          />

          <div className="workflow-arrow">
            <ArrowRight />
          </div>

          <WorkflowStep
            number="03"
            icon={<Sparkles />}
            title="Explore Insights"
            text="Visualize the graph and get AI-powered explanations and recommendations."
          />

        </div>

      </section>


      {/* CLOUD PROVIDERS */}

      <section className="cloud-section">

        <div className="section-heading">

          <div className="section-eyebrow">
            SUPPORTED CLOUD PROVIDERS
          </div>

          <h2>
            Multi-Cloud Support
          </h2>

          <p>
            Analyze Terraform infrastructure across leading cloud platforms.
          </p>

        </div>


        <div className="cloud-grid">

          <CloudCard
            logo="aws"
            title="Amazon Web Services"
          />

          <CloudCard
            logo="gcp"
            title="Google Cloud"
          />

          <CloudCard
            logo="azure"
            title="Microsoft Azure"
          />

        </div>

      </section>


      {/* UPLOAD AREA */}

      <section
        className="upload-section"
        id="upload"
      >

        <div className="upload-copy">

          <div className="section-eyebrow">
            GET STARTED
          </div>

          <h2>
            Upload Your Terraform
            <br />
            and <span>Uncover Risks</span>
          </h2>

          <p>
            Choose a Terraform project or provide a Git repository
            to start your analysis.
          </p>


          <div className="trust-row">

            <div>
              <Check />
              No account required
            </div>

            <div>
              <Check />
              Fast analysis
            </div>

            <div>
              <Check />
              Secure & private
            </div>

          </div>

        </div>


        <UploadBox />

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

          <strong>main.tf</strong>

        </div>


        <div className="code">

          <div>
            <span>1</span>
            <b>resource</b>{" "}
            <em>"aws_s3_bucket"</em> "data" {"{"}
          </div>

          <div>
            <span>2</span>
            &nbsp; bucket = <em>"my-app-data"</em>
          </div>

          <div>
            <span>3</span>
            &nbsp; acl = <em>"private"</em>
          </div>

          <div>
            <span>4</span>
            &nbsp; tags = {"{"}
          </div>

          <div>
            <span>5</span>
            &nbsp;&nbsp;&nbsp;
            Environment = <em>"prod"</em>
          </div>

          <div>
            <span>6</span>
            &nbsp; {"}"}
          </div>

          <div>
            <span>7</span>
            {"}"}
          </div>

        </div>

      </div>


      <div className="insight-card">

        <div className="insight-icon">
          <Sparkles size={17} />
        </div>

        <strong>AI Insights</strong>

        <div className="insight-item">
          <Check size={13} />
          Detect risks
        </div>

        <div className="insight-item">
          <Check size={13} />
          Explain issues
        </div>

        <div className="insight-item">
          <Check size={13} />
          Suggest fixes
        </div>

      </div>


      <div className="code-label">
        <strong>From code</strong>
        <span>to real insights</span>
      </div>


      <div className="vpc-node">
        <Layers3 size={25} />
        <strong>VPC</strong>
      </div>


      <div className="graph-line line-one"></div>
      <div className="graph-line line-two"></div>
      <div className="graph-line line-three"></div>


      <div className="resource-node node-ec2">
        <Server size={25} />
        <strong>EC2</strong>
      </div>

      <div className="resource-node node-s3">
        <Database size={25} />
        <strong>S3</strong>
      </div>

      <div className="resource-node node-rds">
        <Database size={25} />
        <strong>RDS</strong>
      </div>


      <div className="risk-card">

        <ShieldAlert size={25} />

        <div>
          <strong>Security Risk</strong>
          <span>S3 bucket is publicly accessible</span>
        </div>

      </div>


      <div className="hand-note">
        <span>Safer</span>
        <span>infrastructure</span>
        <span>starts here</span>
      </div>

      <div className="arrow-doodle">
        ↘
      </div>

    </div>
  );
}


/* =========================================================
   UPLOAD BOX
========================================================= */

function UploadBox() {

  const navigate = useNavigate();

  const [mode, setMode] = useState("upload");

  const [selectedFile, setSelectedFile] = useState(null);

  const [gitUrl, setGitUrl] = useState("");


  const handleFileChange = (event) => {

    const file = event.target.files?.[0];

    if (file) {
      setSelectedFile(file);
    }

  };


  const handleAnalyze = () => {

    if (mode === "upload") {

      if (!selectedFile) {
        alert("Please select a Terraform file or ZIP archive first.");
        return;
      }

      navigate("/visualize", {
        state: {
          source: "file",
          fileName: selectedFile.name,
        },
      });

      return;
    }


    if (!gitUrl.trim()) {

      alert("Please enter a Git repository URL.");

      return;
    }


    navigate("/visualize", {
      state: {
        source: "git",
        gitUrl: gitUrl,
      },
    });

  };


  return (
    <div className="upload-box">


      {/* TABS */}

      <div className="upload-tabs">

        <button
          type="button"
          className={`upload-tab ${
            mode === "upload" ? "active" : ""
          }`}
          onClick={() => setMode("upload")}
        >
          <FileCode2 size={17} />
          Upload Files
        </button>


        <button
          type="button"
          className={`upload-tab ${
            mode === "git" ? "active" : ""
          }`}
          onClick={() => setMode("git")}
        >
          <GitBranch size={18} />
          Git Repository
        </button>

      </div>


      {/* FILE MODE */}

      {mode === "upload" && (

        <>

          <input
            id="terraform-file"
            type="file"
            accept=".tf,.tfvars,.zip"
            onChange={handleFileChange}
            hidden
          />


          <label
            htmlFor="terraform-file"
            className="drop-area"
          >

            <UploadCloud size={37} />


            {selectedFile ? (

              <>
                <p className="selected-file">
                  {selectedFile.name}
                </p>

                <span>
                  File selected successfully
                </span>
              </>

            ) : (

              <>
                <p>
                  Drag and drop your .tf files or ZIP here
                </p>

                <span>
                  or
                </span>

                <span className="browse-button">
                  Browse Files
                </span>
              </>

            )}

          </label>


          <div className="supported">
            Supported formats: .tf, .tfvars, .zip
          </div>

        </>

      )}


      {/* GIT MODE */}

      {mode === "git" && (

        <div className="git-area">

          <div className="git-icon">
            <GitBranch size={27} />
          </div>


          <h3>
            Connect a Git Repository
          </h3>


          <p>
            Enter the URL of your Terraform repository.
          </p>


          <input
            type="url"
            className="git-input"
            placeholder="https://github.com/username/repository"
            value={gitUrl}
            onChange={(event) =>
              setGitUrl(event.target.value)
            }
          />


          <span className="git-example">
            Example:
            https://github.com/user/terraform-infrastructure
          </span>

        </div>

      )}


      {/* ANALYZE BUTTON */}

      <button
        type="button"
        className="analyze-button"
        onClick={handleAnalyze}
      >

        Analyze Infrastructure

        <ArrowRight size={18} />

      </button>

    </div>
  );
}


/* =========================================================
   VISUALIZE PAGE
========================================================= */

function VisualizePage() {

  const location = useLocation();

  const source = location.state;

  return (
    <main className="dashboard-page">

      <div className="dashboard-header">

        <div>

          <div className="section-eyebrow">
            INFRASTRUCTURE VISUALIZATION
          </div>

          <h1>
            Infrastructure Overview
          </h1>

          <p>
            Explore your Terraform resources and their relationships.
          </p>

        </div>


        <Link
          to="/"
          className="back-button"
        >
          <ArrowLeft size={16} />
          Upload another
        </Link>

      </div>


      {source && (

        <div className="analysis-source">

          <Activity size={18} />

          {source.source === "file"
            ? `Analyzing: ${source.fileName}`
            : `Repository: ${source.gitUrl}`}

        </div>

      )}


      {/* SUMMARY */}

      <div className="dashboard-stats">

        <DashboardStat
          icon={<Box />}
          number="11"
          label="Resources"
        />

        <DashboardStat
          icon={<Network />}
          number="17"
          label="Relationships"
        />

        <DashboardStat
          icon={<ShieldAlert />}
          number="7"
          label="Security Findings"
          danger
        />

        <DashboardStat
          icon={<Cloud />}
          number="AWS"
          label="Cloud Provider"
        />

      </div>


      {/* GRAPH */}

      <div className="visualization-layout">

        <div className="graph-panel">

          <div className="panel-header">

            <div>
              <strong>Infrastructure Graph</strong>
              <span>Resource relationships</span>
            </div>

            <button className="graph-control">
              <Search size={15} />
              Search
            </button>

          </div>


          <div className="infrastructure-graph">

            <div className="graph-node graph-vpc">
              <Layers3 />
              <strong>VPC</strong>
              <span>aws_vpc</span>
            </div>


            <div className="graph-connection connection-a"></div>
            <div className="graph-connection connection-b"></div>
            <div className="graph-connection connection-c"></div>


            <div className="graph-node graph-instance">
              <Server />
              <strong>Web Server</strong>
              <span>aws_instance</span>
            </div>


            <div className="graph-node graph-database">
              <Database />
              <strong>Database</strong>
              <span>aws_db_instance</span>
            </div>


            <div className="graph-node graph-security">
              <ShieldCheck />
              <strong>Security Group</strong>
              <span>aws_security_group</span>
            </div>

          </div>

        </div>


        {/* RESOURCE LIST */}

        <div className="resource-panel">

          <div className="panel-header">
            <div>
              <strong>Resources</strong>
              <span>Detected infrastructure</span>
            </div>
          </div>


          <ResourceRow
            icon={<Layers3 />}
            name="main-vpc"
            type="aws_vpc"
          />

          <ResourceRow
            icon={<Server />}
            name="web-server"
            type="aws_instance"
          />

          <ResourceRow
            icon={<Database />}
            name="production-db"
            type="aws_db_instance"
          />

          <ResourceRow
            icon={<ShieldCheck />}
            name="app-security"
            type="aws_security_group"
          />

        </div>

      </div>


      {/* FINDINGS */}

      <div className="findings-panel">

        <div className="panel-header">

          <div>
            <strong>Security Findings</strong>
            <span>Detected during infrastructure analysis</span>
          </div>

          <Link to="/insights" className="view-insights">
            View AI Insights
            <ChevronRight size={15} />
          </Link>

        </div>


        <Finding
          severity="HIGH"
          title="Publicly Accessible Resource"
          description="A resource is configured with public network access."
        />

        <Finding
          severity="MEDIUM"
          title="Missing Encryption"
          description="Encryption configuration should be reviewed."
        />

        <Finding
          severity="LOW"
          title="Configuration Recommendation"
          description="Review unused or unnecessary infrastructure configuration."
        />

      </div>

    </main>
  );
}


/* =========================================================
   AI INSIGHTS PAGE
========================================================= */

function InsightsPage() {

  return (
    <main className="dashboard-page insights-page">

      <div className="dashboard-header">

        <div>

          <div className="section-eyebrow">
            AI-POWERED ANALYSIS
          </div>

          <h1>
            AI Infrastructure Insights
          </h1>

          <p>
            Understand your infrastructure risks and discover
            actionable recommendations.
          </p>

        </div>


        <Link
          to="/visualize"
          className="back-button"
        >
          <ArrowLeft size={16} />
          Back to visualization
        </Link>

      </div>


      {/* AI SUMMARY */}

      <div className="ai-summary">

        <div className="ai-summary-icon">
          <Sparkles />
        </div>

        <div>

          <span>OVERALL ANALYSIS</span>

          <h2>
            Your infrastructure needs attention
          </h2>

          <p>
            Several configuration areas can be improved to
            reduce security exposure and strengthen your
            infrastructure posture.
          </p>

        </div>

      </div>


      {/* INSIGHT CARDS */}

      <div className="insights-grid">

        <InsightCard
          icon={<ShieldAlert />}
          title="Security Risks"
          count="7"
          description="Security findings detected across your infrastructure."
          danger
        />

        <InsightCard
          icon={<Lock />}
          title="Security Improvements"
          count="4"
          description="Resources where security configuration can be strengthened."
        />

        <InsightCard
          icon={<Activity />}
          title="Architecture"
          count="3"
          description="Architecture relationships worth reviewing."
        />

      </div>


      {/* RECOMMENDATIONS */}

      <div className="recommendations-panel">

        <div className="panel-header">

          <div>

            <strong>
              Recommended Actions
            </strong>

            <span>
              AI-generated explanations and remediation guidance
            </span>

          </div>

        </div>


        <Recommendation
          number="01"
          title="Review public access configuration"
          text="Check resources that allow unrestricted network access and restrict access to trusted sources."
        />

        <Recommendation
          number="02"
          title="Enable encryption where applicable"
          text="Review storage and database resources and enable encryption for sensitive workloads."
        />

        <Recommendation
          number="03"
          title="Review security group rules"
          text="Reduce unnecessarily broad inbound and outbound rules."
        />

      </div>


      <div className="insights-footer">

        <Sparkles size={17} />

        <span>
          AI recommendations are generated from the analyzed
          infrastructure configuration.
        </span>

      </div>

    </main>
  );
}


/* =========================================================
   SMALL COMPONENTS
========================================================= */

function Feature({
  icon,
  title,
  text,
  danger,
}) {

  const navigate = useNavigate();

  const handleClick = () => {

    if (title === "Visualize Infrastructure") {
      navigate("/visualize");
    }

    if (title === "Get AI Insights") {
      navigate("/insights");
    }

  };


  return (
    <div
      className="feature-card"
      onClick={handleClick}
    >

      <div
        className={`feature-icon ${
          danger ? "danger" : ""
        }`}
      >
        {icon}
      </div>

      <h3>{title}</h3>

      <p>{text}</p>

    </div>
  );
}


function WorkflowStep({
  number,
  icon,
  title,
  text,
}) {

  return (
    <div className="workflow-step">

      <div className="step-number">
        {number}
      </div>

      <div className="step-icon">
        {icon}
      </div>

      <div>
        <h3>{title}</h3>
        <p>{text}</p>
      </div>

    </div>
  );
}


function CloudCard({
  logo,
  title,
}) {

  return (
    <div className="cloud-card">

      <div className={`cloud-logo ${logo}`}>

        {logo === "aws" && "aws"}

        {logo === "gcp" && (
          <Cloud size={35} />
        )}

        {logo === "azure" && "▲"}

      </div>


      <div>

        <strong>
          {title}
        </strong>

        <span>
          Terraform infrastructure
        </span>

      </div>

    </div>
  );
}


function DashboardStat({
  icon,
  number,
  label,
  danger,
}) {

  return (
    <div className="dashboard-stat">

      <div className={`dashboard-stat-icon ${
        danger ? "danger" : ""
      }`}>
        {icon}
      </div>

      <div>

        <strong>{number}</strong>
        <span>{label}</span>

      </div>

    </div>
  );
}


function ResourceRow({
  icon,
  name,
  type,
}) {

  return (
    <div className="resource-row">

      <div className="resource-row-icon">
        {icon}
      </div>

      <div>

        <strong>{name}</strong>
        <span>{type}</span>

      </div>

      <ChevronRight size={15} />

    </div>
  );
}


function Finding({
  severity,
  title,
  description,
}) {

  return (
    <div className="finding">

      <div className={`severity ${severity.toLowerCase()}`}>
        {severity}
      </div>

      <div className="finding-content">

        <strong>{title}</strong>

        <span>{description}</span>

      </div>

      <ChevronRight size={17} />

    </div>
  );
}


function InsightCard({
  icon,
  title,
  count,
  description,
  danger,
}) {

  return (
    <div className="insight-stat-card">

      <div
        className={`insight-stat-icon ${
          danger ? "danger" : ""
        }`}
      >
        {icon}
      </div>

      <div className="insight-count">
        {count}
      </div>

      <h3>{title}</h3>

      <p>{description}</p>

    </div>
  );
}


function Recommendation({
  number,
  title,
  text,
}) {

  return (
    <div className="recommendation">

      <div className="recommendation-number">
        {number}
      </div>

      <div>

        <h3>{title}</h3>

        <p>{text}</p>

      </div>

      <ArrowRight size={18} />

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

          <div className="brand-name">
            InfraScope
          </div>

          <div className="brand-tagline">
            Analyze. Visualize. Secure.
          </div>

        </div>

      </div>


      <span>
        Infrastructure intelligence, simplified.
      </span>

    </footer>
  );
}


export default App;