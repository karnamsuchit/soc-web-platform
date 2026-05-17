import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Clock3,
  FileSearch,
  Globe2,
  ListFilter,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import "./styles.css";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";
const severityOrder = ["critical", "high", "medium", "low"];

const navItems = [
  { id: "overview", label: "Overview", icon: BarChart3 },
  { id: "monitoring", label: "Monitoring", icon: Radio },
  { id: "alerts", label: "Alerts", icon: ShieldAlert },
  { id: "logs", label: "Log Analysis", icon: FileSearch },
  { id: "iocs", label: "IOCs", icon: Globe2 },
];

function App() {
  const [activeView, setActiveView] = useState("overview");
  const [samples, setSamples] = useState([]);
  const [selectedSample, setSelectedSample] = useState("soc_mixed_attack_demo.log");
  const [analysis, setAnalysis] = useState(null);
  const [liveFeed, setLiveFeed] = useState(null);
  const [status, setStatus] = useState("Loading sample investigation...");

  useEffect(() => {
    fetch(`${API_BASE}/samples`)
      .then((response) => response.json())
      .then((data) => setSamples(data.samples || []))
      .catch(() => setStatus("Backend is offline. Start FastAPI to load live detections."));
  }, []);

  useEffect(() => {
    if (!selectedSample) return;
    setStatus("Analyzing security logs...");
    fetch(`${API_BASE}/analyze-sample/${selectedSample}`)
      .then((response) => response.json())
      .then((data) => {
        setAnalysis(data);
        setStatus("Live sample analysis loaded");
      })
      .catch(() => setStatus("Backend is offline. Start FastAPI to load live detections."));
  }, [selectedSample]);

  useEffect(() => {
    fetch(`${API_BASE}/monitoring/live`)
      .then((response) => response.json())
      .then((data) => setLiveFeed(data))
      .catch(() => setLiveFeed(null));
  }, [selectedSample]);

  const summary = analysis?.summary || {};
  const alerts = analysis?.alerts || [];
  const events = analysis?.events || [];
  const iocs = analysis?.iocs || {};
  const topAlert = alerts.find((alert) => alert.severity === "critical") || alerts[0];

  const severityData = severityOrder.map((key) => ({
    label: key,
    value: summary.severity_counts?.[key] || 0,
  }));

  const mitreData = useMemo(() => {
    const counts = alerts.reduce((acc, alert) => {
      const tactic = alert.mitre?.tactic || "Unknown";
      acc[tactic] = (acc[tactic] || 0) + 1;
      return acc;
    }, {});
    return Object.entries(counts).map(([label, value]) => ({ label, value }));
  }, [alerts]);

  const highCritical = (summary.severity_counts?.critical || 0) + (summary.severity_counts?.high || 0);

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <ShieldCheck size={28} />
          <div>
            <strong>SOC Sentinel</strong>
            <span>Threat Detection</span>
          </div>
        </div>

        <nav className="nav-list" aria-label="SOC sections">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                className={activeView === item.id ? "active" : ""}
                onClick={() => setActiveView(item.id)}
                type="button"
              >
                <Icon size={18} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Security Operations Center</p>
            <h1>{viewTitle(activeView)}</h1>
          </div>
          <div className="sample-picker">
            <label htmlFor="sample">Dataset</label>
            <select id="sample" value={selectedSample} onChange={(event) => setSelectedSample(event.target.value)}>
              {samples.length === 0 && <option value={selectedSample}>{selectedSample}</option>}
              {samples.map((sample) => (
                <option key={sample.filename} value={sample.filename}>{sample.filename}</option>
              ))}
            </select>
          </div>
        </header>

        <div className="status-strip">
          <Activity size={18} />
          <span>{status}</span>
          <strong>{analysis?.detected_format || "waiting for logs"}</strong>
        </div>

        {activeView === "overview" && (
          <Overview
            analysis={analysis}
            alerts={alerts}
            highCritical={highCritical}
            iocs={iocs}
            severityData={severityData}
            mitreData={mitreData}
            topAlert={topAlert}
          />
        )}

        {activeView === "monitoring" && <MonitoringView liveFeed={liveFeed} />}
        {activeView === "alerts" && <AlertsView alerts={alerts} />}
        {activeView === "logs" && <LogsView events={events} />}
        {activeView === "iocs" && <IocsView iocs={iocs} summary={summary} />}
      </section>
    </main>
  );
}

function MonitoringView({ liveFeed }) {
  const alerts = liveFeed?.alerts || [];
  const events = liveFeed?.events || [];
  const iocs = liveFeed?.iocs || {};
  const datasets = liveFeed?.datasets || [];
  const highPriority = alerts.filter((alert) => ["critical", "high"].includes(alert.severity)).length;

  return (
    <>
      <section className="metrics-grid">
        <Metric title="Monitored Datasets" value={datasets.length} icon={<Radio />} />
        <Metric title="Live Alerts" value={liveFeed?.total_alerts || 0} icon={<AlertTriangle />} accent="orange" />
        <Metric title="High Priority" value={highPriority} icon={<ShieldAlert />} accent="red" />
        <Metric title="Tracked IOCs" value={iocs.total_iocs || 0} icon={<Globe2 />} accent="blue" />
      </section>

      <section className="split-grid">
        <Panel title="Live Alert Feed">
          <div className="compact-list">
            {alerts.slice(0, 10).map((alert) => (
              <article className="feed-card" key={`${alert.dataset}-${alert.alert_id}`}>
                <div>
                  <span className={`severity ${alert.severity}`}>{alert.severity}</span>
                  <strong>{alert.type}</strong>
                </div>
                <p>{alert.description}</p>
                <footer>
                  <code>{alert.source_ip || "unknown source"}</code>
                  <span>{alert.dataset}</span>
                  <code>{alert.mitre?.technique_id || "UNKNOWN"}</code>
                </footer>
              </article>
            ))}
            {alerts.length === 0 && <EmptyState text="No live alerts available." />}
          </div>
        </Panel>

        <Panel title="Monitoring Coverage">
          <div className="coverage-list">
            {datasets.map((dataset) => (
              <div className="source-row" key={dataset}>
                <span>{dataset}</span>
                <strong>active</strong>
              </div>
            ))}
          </div>
        </Panel>
      </section>

      <Panel title="Security Event Stream">
        <div className="data-table">
          <div className="table-head stream-table">
            <span>Time</span>
            <span>Dataset</span>
            <span>Source</span>
            <span>Event</span>
            <span>Evidence</span>
          </div>
          {events.slice(0, 16).map((event, index) => (
            <div className="table-row stream-table" key={`${event.dataset}-${event.line_number}-${index}`}>
              <span>{event.timestamp || "unknown"}</span>
              <code>{event.dataset}</code>
              <code>{event.source_ip || "unknown"}</code>
              <span>{event.method || event.event_type || event.action}</span>
              <p>{event.url || event.message || event.path || "security event"}</p>
            </div>
          ))}
        </div>
      </Panel>
    </>
  );
}

function Overview({ analysis, alerts, highCritical, iocs, severityData, mitreData, topAlert }) {
  return (
    <>
      <section className="metrics-grid">
        <Metric title="Events Parsed" value={analysis?.parsed_events || 0} icon={<Terminal />} />
        <Metric title="Total Alerts" value={analysis?.total_alerts || 0} icon={<AlertTriangle />} accent="orange" />
        <Metric title="High + Critical" value={highCritical} icon={<ShieldAlert />} accent="red" />
        <Metric title="Extracted IOCs" value={iocs.total_iocs || 0} icon={<Globe2 />} accent="blue" />
      </section>

      <section className="overview-grid">
        <Panel title="Severity Distribution">
          <BarList data={severityData} />
        </Panel>

        <Panel title="MITRE ATT&CK Tactics">
          <BarList data={mitreData} />
        </Panel>

        <Panel title="Priority Alert">
          {topAlert ? <AlertDetail alert={topAlert} /> : <EmptyState text="No alerts detected in the current dataset." />}
        </Panel>
      </section>

      <section className="split-grid">
        <Panel title="Recent Alerts">
          <div className="compact-list">
            {alerts.slice(0, 6).map((alert) => <AlertRow key={alert.alert_id} alert={alert} />)}
            {alerts.length === 0 && <EmptyState text="No alerts available." />}
          </div>
        </Panel>

        <Panel title="IOC Snapshot">
          <div className="ioc-grid">
            <IocList title="Source IPs" values={iocs.ips || []} />
            <IocList title="URLs" values={iocs.urls || []} />
          </div>
        </Panel>
      </section>
    </>
  );
}

function AlertsView({ alerts }) {
  return (
    <Panel title="Alert Investigation Queue">
      <div className="table-toolbar">
        <ListFilter size={17} />
        <span>{alerts.length} detections generated from the selected dataset</span>
      </div>
      <div className="data-table">
        <div className="table-head alert-table">
          <span>Severity</span>
          <span>Alert</span>
          <span>Source</span>
          <span>MITRE</span>
          <span>Recommendation</span>
        </div>
        {alerts.map((alert) => (
          <div className="table-row alert-table" key={alert.alert_id}>
            <span className={`severity ${alert.severity}`}>{alert.severity}</span>
            <div>
              <strong>{alert.type}</strong>
              <p>{alert.description}</p>
            </div>
            <code>{alert.source_ip || "unknown"}</code>
            <code>{alert.mitre?.technique_id || "UNKNOWN"}</code>
            <p>{alert.recommendation || "Review event context."}</p>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function LogsView({ events }) {
  return (
    <Panel title="Normalized Log Events">
      <div className="data-table">
        <div className="table-head log-table">
          <span>Time</span>
          <span>Source</span>
          <span>Action</span>
          <span>Status</span>
          <span>Evidence</span>
        </div>
        {events.map((event, index) => (
          <div className="table-row log-table" key={`${event.line_number}-${index}`}>
            <span>{event.timestamp || "unknown"}</span>
            <code>{event.source_ip || "unknown"}</code>
            <span>{event.method || event.event_type || "event"}</span>
            <code>{event.status || event.action || "observed"}</code>
            <p>{event.url || event.message || event.path || "security event"}</p>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function IocsView({ iocs, summary }) {
  return (
    <section className="split-grid">
      <Panel title="Indicators of Compromise">
        <div className="ioc-grid ioc-grid-large">
          <IocList title="IP Addresses" values={iocs.ips || []} />
          <IocList title="Domains" values={iocs.domains || []} />
          <IocList title="URLs" values={iocs.urls || []} />
          <IocList title="Hashes" values={iocs.hashes || []} />
        </div>
      </Panel>

      <Panel title="Top Source IPs">
        <div className="compact-list">
          {(summary.top_source_ips || []).map((item) => (
            <div className="source-row" key={item.ip}>
              <code>{item.ip}</code>
              <strong>{item.count}</strong>
            </div>
          ))}
        </div>
      </Panel>
    </section>
  );
}

function Metric({ title, value, icon, accent = "green" }) {
  return (
    <article className={`metric metric-${accent}`}>
      <div>{React.cloneElement(icon, { size: 22 })}</div>
      <span>{title}</span>
      <strong>{value}</strong>
    </article>
  );
}

function Panel({ title, children }) {
  return (
    <section className="panel">
      <h2>{title}</h2>
      {children}
    </section>
  );
}

function BarList({ data }) {
  const normalized = data.length ? data : [{ label: "No data", value: 0 }];
  const max = Math.max(...normalized.map((item) => item.value), 1);
  return (
    <div className="bar-list">
      {normalized.map((item) => (
        <div className="bar-row" key={item.label}>
          <span>{item.label}</span>
          <div><i style={{ width: `${(item.value / max) * 100}%` }} /></div>
          <strong>{item.value}</strong>
        </div>
      ))}
    </div>
  );
}

function AlertRow({ alert }) {
  return (
    <article className="alert-row">
      <span className={`severity ${alert.severity}`}>{alert.severity}</span>
      <div>
        <strong>{alert.type}</strong>
        <p>{alert.description}</p>
      </div>
      <code>{alert.mitre?.technique_id}</code>
    </article>
  );
}

function AlertDetail({ alert }) {
  return (
    <div className="alert-detail">
      <span className={`severity ${alert.severity}`}>{alert.severity}</span>
      <h3>{alert.type}</h3>
      <p>{alert.description}</p>
      <dl>
        <div><dt>Source</dt><dd>{alert.source_ip || "unknown"}</dd></div>
        <div><dt>Technique</dt><dd>{alert.mitre?.technique_id} {alert.mitre?.technique_name}</dd></div>
        <div><dt>Action</dt><dd>{alert.recommendation}</dd></div>
      </dl>
    </div>
  );
}

function IocList({ title, values }) {
  return (
    <div className="ioc-list">
      <h3>{title}</h3>
      {values.slice(0, 10).map((value) => <code key={value}>{value}</code>)}
      {values.length === 0 && <span>No indicators found</span>}
    </div>
  );
}

function EmptyState({ text }) {
  return <p className="empty-state">{text}</p>;
}

function viewTitle(view) {
  return {
    overview: "Threat Overview",
    monitoring: "Live Monitoring",
    alerts: "Alert Queue",
    logs: "Log Analysis",
    iocs: "IOC Intelligence",
  }[view];
}

createRoot(document.getElementById("root")).render(<App />);
