import { useState } from "react";
import { Activity, ArrowRight, BrainCircuit, Eye, EyeOff, LockKeyhole, Mail, ShieldCheck } from "lucide-react";
import "./login.css";

const capabilities = [
  [Eye, "Continuous Monitoring", "24/7 visibility across your environment"],
  [Activity, "Incident Response", "Detect. Investigate. Contain. Recover."],
  [BrainCircuit, "Threat Intelligence", "Actionable insights, real-world context"],
  [ShieldCheck, "Compliance Ready", "Meet global security standards"],
];

export default function LoginPage() {
  const [visible, setVisible] = useState(false);
  const [workstation, setWorkstation] = useState(true);
  const [message, setMessage] = useState("");

  function submit(event) {
    event.preventDefault();
    setMessage("Sign-in is not connected yet. Your credentials were not sent or saved.");
  }

  return <main className="login-page">
    <div className="login-scene" aria-hidden="true" />
    <div className="login-scrim" aria-hidden="true" />
    <header className="login-brand">
      <div className="login-brand-mark"><img src="/favicon.svg" alt="" /></div>
      <div><strong>Sentra<span>Pixel</span></strong><p>See Threats. Stop Breaches.</p></div>
    </header>
    <div className="login-security" aria-label="Secure detect respond prevent">SECURE <b>•</b> DETECT <b>•</b> RESPOND <b>•</b> PREVENT <i /></div>
    <div className="login-identity" aria-hidden="true">PEOPLE<br />INTELLIGENCE<br />DETECTION<br />RESPONSE<br />A SAFER TOMORROW</div>
    <div className="login-content">
      <section className="login-visual" aria-label="SentraPixel security operations center">
        <div className="login-visual-caption"><span className="login-live-dot" /> MONITOR <span>→</span> DETECT <span>→</span> INVESTIGATE <span>→</span> RESPOND</div>
      </section>
      <section className="login-card" aria-labelledby="login-title">
        <p className="login-eyebrow">WELCOME TO THE SOC</p>
        <h1 id="login-title">Welcome to the <span>SOC</span></h1>
        <p className="login-subtitle">Same mission. A safer tomorrow.</p>
        <form onSubmit={submit} noValidate>
          <label htmlFor="corporate-email">Corporate Email</label>
          <div className="login-input"><Mail aria-hidden="true" /><input id="corporate-email" name="email" type="email" autoComplete="username" placeholder="you@yourcompany.com" required /></div>
          <label htmlFor="account-password">Password</label>
          <div className="login-input"><LockKeyhole aria-hidden="true" /><input id="account-password" name="password" type={visible ? "text" : "password"} autoComplete="current-password" placeholder="Enter your password" required /><button type="button" onClick={() => setVisible(value => !value)} aria-label={visible ? "Hide password" : "Show password"} aria-pressed={visible}>{visible ? <EyeOff /> : <Eye />}</button></div>
          <div className="login-form-options"><label className="login-check"><input type="checkbox" checked={workstation} onChange={event => setWorkstation(event.target.checked)} /> This is a secure workstation</label><span title="Password recovery is not connected yet">Forgot password?</span></div>
          {message && <p className="login-error" role="alert">{message}</p>}
          <button className="login-submit" type="submit"><ArrowRight /> Launch Dashboard</button>
        </form>
        <div className="login-divider"><span>OR</span></div>
        <div className="login-alternatives"><button disabled title="SSO integration is not available yet"><LockKeyhole /> SSO Login</button><button disabled title="MFA integration is not available yet"><ShieldCheck /> Verify with MFA</button></div>
        <p className="login-access-note"><LockKeyhole /> Identity integration pending</p>
        <a className="login-preview" href="/">Preview the existing dashboard <ArrowRight size={15} /></a>
      </section>
    </div>
    <footer className="login-capabilities">{capabilities.map(([Icon, title, description]) => <div key={title} className="login-capability"><span className="login-capability-icon"><Icon aria-hidden="true" /></span><div><strong>{title}</strong><p>{description}</p></div></div>)}</footer>
  </main>;
}
