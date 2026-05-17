import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Clock3,
  FileSearch,
  Globe2,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import "./styles.css";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";
const severityOrder = ["critical", "high", "medium", "low"];

function App() {
  const [samples, setSamples] = useState([]);
  const [selectedSample, setSelectedSample] = useState("soc_mixed_attack_demo.log");
  const [analysis, setAnalysis] = useState(null);
  const [status, setStatus] = useState("Loading sample investigation...");

  useEffect(() => {
    fetch(`${API_BASE}/samples`)
      .then((response) => response.json())
      .then((data) => {
        setSamples(data.samples || []);
        if (data.samples?.[0]?.filename && !selectedSample) {
          setSelectedSample(data.samples[0].filename);
        }
      })
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

  const summary = analysis?.summary || {};
  const alerts = analysis?.alerts || [];
  const events = analysis?.events || [];
  const iocs = analysis?.iocs || {};
  const topAlert = alerts.find((alert) => alert.severity === "critical") || alerts[0];

  const mitreCounts = useMemo(() => {
    return alerts.reduce((acc, alert) => {
      const tactic = alert.mitre?.tactic || "Unknown";
      acc[tactic] = (acc[tactic] || 0) + 1;
      return acc;
    }, {});
  }, [alerts]);

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <ShieldCheck size={28} />
          <div>
            <strong>SOC Sentinel</strong>
            <span>Threat Monitoring</span>
          </div>
        </div>
        <nav>
          <a className="active"><BarChart3 size={18} /> Overview</a>
          <a><ShieldAlert size={18} /> Alerts</a>
          <a><FileSearch size={18} /> Log Analysis</a>
          <a><Globe2 size={18} /> IOCs</a>
        </nav>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Security Operations Center</p>
            <h1>Threat Detection & Log Monitoring</h1>
          </div>
          <div className="sample-picker">
            <label htmlFor="sample">Sample Dataset</label>
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

        <section className="metrics-grid">
          <Metric title="Events Parsed" value={analysis?.parsed_events || 0} icon={<Terminal />} />
          <Metric title="Total Alerts" value={analysis?.total_alerts || 0} icon={<AlertTriangle />} accent="orange" />
          <Metric title="High + Critical" value={(summary.severity_counts?.critical || 0) + (summary.severity_counts?.high || 0)} icon={<ShieldAlert />} accent="red" />
          <Metric title="Extracted IOCs" value={iocs.total_iocs || 0} icon={<Globe2 />} accent="blue" />
        </section>

        <section className="analysis-grid">
          <Panel title="Severity Distribution">
            <BarList data={severityOrder.map((key) => ({ label: key, value: summary.severity_counts?.[key] || 0 }))} />
          </Panel>

          <Panel title="MITRE ATT&CK Tactics">
            <BarList data={Object.entries(mitreCounts).map(([label, value]) => ({ label, value }))} />
          </Panel>

          <Panel title="Priority Alert">
            {topAlert ? <AlertDetail alert={topAlert} /> : <EmptyState text="No alerts detected in the current dataset." />}
          </Panel>
        </section>

        <section className="wide-grid">
          <Panel title="Alert Queue">
            <div className="alert-list">
              {alerts.slice(0, 8).map((alert) => <AlertRow key={alert.alert_id} alert={alert} />)}
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

        <Panel title="Event Timeline">
          <div className="timeline">
            {events.slice(0, 12).map((event, index) => (
              <div className="timeline-item" key={`${event.line_number}-${index}`}>
                <Clock3 size={16} />
                <span>{event.timestamp || "unknown time"}</span>
                <strong>{event.source_ip || "unknown source"}</strong>
                <code>{event.method || event.event_type}</code>
                <p>{event.url || event.message || "security event"}</p>
              </div>
            ))}
          </div>
        </Panel>
      </section>
    </main>
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
  const max = Math.max(...data.map((item) => item.value), 1);
  return (
    <div className="bar-list">
      {data.map((item) => (
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
      {values.slice(0, 8).map((value) => <code key={value}>{value}</code>)}
      {values.length === 0 && <span>No IOCs</span>}
    </div>
  );
}

function EmptyState({ text }) {
  return <p className="empty-state">{text}</p>;
}

createRoot(document.getElementById("root")).render(<App />);
