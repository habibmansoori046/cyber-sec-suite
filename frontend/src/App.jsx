import { useState, useEffect, useRef, useMemo } from "react";
import {
  Search, FileText, GitBranch, LayoutDashboard,
  AlertTriangle, CheckCircle, XCircle, Clock, Upload, Download,
  Play, Square, ChevronRight, Eye, EyeOff, Zap, Server, Globe, Lock,
  Unlock, Bug, Bell, Crosshair, Network, Target, Layers, Info,
  Menu, LogIn, UserPlus, Loader2, Activity, Shield, Settings, X,
  User, Fingerprint, TrendingUp, TrendingDown, MonitorDot, Flame, ScanLine
} from "lucide-react";
import {
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, AreaChart, Area
} from "recharts";
import { auth, scans, forensics, rca, dashboard, reports } from "./api";

const SC={critical:"#EF4444",high:"#F97316",medium:"#EAB308",low:"#10B981",info:"#3B82F6"};

/* ═══ CUSTOM LOGO SVG ═══════════════════════════════════════ */
function Logo({size=36,className=""}){
  return(
    <svg width={size} height={size} viewBox="0 0 48 48" fill="none" className={className}>
      <defs>
        <linearGradient id="lg1" x1="0" y1="0" x2="48" y2="48"><stop offset="0%" stopColor="#2563EB"/><stop offset="100%" stopColor="#06B6D4"/></linearGradient>
        <linearGradient id="lg2" x1="24" y1="6" x2="24" y2="44"><stop offset="0%" stopColor="#3B82F6"/><stop offset="100%" stopColor="#0EA5E9"/></linearGradient>
      </defs>
      <path d="M24 4L6 12v12c0 11 8 18 18 22 10-4 18-11 18-22V12L24 4z" fill="url(#lg1)" opacity="0.12"/>
      <path d="M24 4L6 12v12c0 11 8 18 18 22 10-4 18-11 18-22V12L24 4z" stroke="url(#lg2)" strokeWidth="1.5" fill="none"/>
      <rect x="19" y="21" width="10" height="9" rx="2" stroke="url(#lg2)" strokeWidth="1.2" fill="rgba(37,99,235,0.08)"/>
      <path d="M21 21v-3a3 3 0 0 1 6 0v3" stroke="url(#lg2)" strokeWidth="1.2" fill="none" strokeLinecap="round"/>
      <circle cx="24" cy="25.5" r="1.3" fill="url(#lg2)"/>
      <line x1="24" y1="26.8" x2="24" y2="28" stroke="url(#lg2)" strokeWidth="1" strokeLinecap="round"/>
      <circle cx="11" cy="17" r="1.8" fill="#3B82F6" opacity="0.5"/><circle cx="37" cy="17" r="1.8" fill="#06B6D4" opacity="0.5"/>
      <circle cx="13" cy="33" r="1.5" fill="#3B82F6" opacity="0.35"/><circle cx="35" cy="33" r="1.5" fill="#06B6D4" opacity="0.35"/>
      <line x1="11" y1="17" x2="19" y2="22" stroke="#3B82F6" strokeWidth="0.5" opacity="0.25"/>
      <line x1="37" y1="17" x2="29" y2="22" stroke="#06B6D4" strokeWidth="0.5" opacity="0.25"/>
      <line x1="13" y1="33" x2="19" y2="28" stroke="#3B82F6" strokeWidth="0.5" opacity="0.25"/>
      <line x1="35" y1="33" x2="29" y2="28" stroke="#06B6D4" strokeWidth="0.5" opacity="0.25"/>
    </svg>
  );
}

/* ═══ LOGIN PARTICLES ═══════════════════════════════════════ */
function LoginParticles(){
  const p=useMemo(()=>Array.from({length:20},(_,i)=>({id:i,left:Math.random()*100,size:Math.random()*4+2,dur:Math.random()*15+10,delay:Math.random()*8,op:Math.random()*0.15+0.05})),[]);
  return<div className="login-particles">{p.map(x=><div key={x.id} className="lp" style={{left:`${x.left}%`,width:x.size,height:x.size,opacity:x.op,animationDuration:`${x.dur}s`,animationDelay:`${x.delay}s`}}/>)}</div>;
}

/* ═══ SHARED ════════════════════════════════════════════════ */
const Badge=({severity})=>{
  const c={critical:"bg-red-50 text-red-600 border-red-200",high:"bg-orange-50 text-orange-600 border-orange-200",
    medium:"bg-amber-50 text-amber-600 border-amber-200",low:"bg-emerald-50 text-emerald-600 border-emerald-200",
    info:"bg-blue-50 text-blue-600 border-blue-200"};
  return<span className={`${c[severity]||c.info} text-[10px] px-2 py-0.5 rounded-md border font-semibold uppercase tracking-wider`}>{severity}</span>;
};
const Dot=({status})=>{
  const c={completed:"bg-emerald-500",running:"bg-blue-500 animate-pulse",failed:"bg-red-500",queued:"bg-amber-500"};
  return<span className={`relative inline-block w-2 h-2 rounded-full ${c[status]||"bg-gray-400"} pulse-ring`}/>;
};
const Spinner=()=><div className="flex items-center justify-center py-20 fade-in"><div className="w-9 h-9 rounded-full border-2 border-gray-200 border-t-blue-600 animate-spin"/></div>;
const Tip=({active,payload,label})=>{
  if(!active||!payload)return null;
  return<div className="bg-white rounded-xl p-3 text-xs shadow-lg border border-gray-100"><p className="text-gray-500 font-medium mb-1">{label}</p>
    {payload.map((p,i)=><p key={i} style={{color:p.color}} className="capitalize">{p.dataKey}: {p.value}</p>)}</div>;
};
const Empty=({icon:Icon,msg,action,onClick})=>(
  <div className="flex flex-col items-center justify-center py-20 fade-in">
    <div className="w-16 h-16 rounded-2xl bg-gray-50 border border-gray-100 flex items-center justify-center mb-4"><Icon size={28} strokeWidth={1.5} className="text-gray-300"/></div>
    <p className="text-sm text-gray-400 mb-4">{msg}</p>
    {action&&<button onClick={onClick} className="text-[12px] text-blue-600 hover:text-blue-700 px-4 py-2 rounded-xl border border-blue-200 hover:border-blue-300 hover:bg-blue-50 transition-all">{action}</button>}
  </div>
);

function Stat({icon:Icon,label,value,color,trend}){
  return(
    <div className="card group cursor-default fade-in">
      <div className="p-5">
        <div className="flex items-center justify-between mb-3">
          <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${color} transition-transform duration-200 group-hover:scale-105`}><Icon size={18} strokeWidth={1.8}/></div>
          {trend!==undefined&&<span className={`text-[11px] font-semibold flex items-center gap-0.5 ${trend>=0?"text-red-500":"text-emerald-500"}`}>
            {trend>=0?<TrendingUp size={11}/>:<TrendingDown size={11}/>}{Math.abs(trend)}%</span>}
        </div>
        <div className="text-[26px] font-bold text-gray-900 tracking-tight leading-none">{value}</div>
        <div className="text-[12px] text-gray-400 mt-1.5 font-medium">{label}</div>
      </div>
    </div>
  );
}

function LiveClock(){
  const [now,setNow]=useState(new Date());
  useEffect(()=>{const t=setInterval(()=>setNow(new Date()),1000);return()=>clearInterval(t);},[]);
  return<div className="text-right hidden sm:block">
    <div className="text-[13px] font-semibold text-gray-800 flex items-center gap-1.5">{now.toLocaleTimeString('en',{hour:'2-digit',minute:'2-digit',second:'2-digit'})}
      <span className="w-1 h-1 rounded-full bg-blue-500 clock-dot"/></div>
    <div className="text-[10px] text-gray-400">{now.toLocaleDateString('en',{month:'short',day:'numeric',year:'numeric'})}</div>
  </div>;
}

/* ═══ LOGIN ═════════════════════════════════════════════════ */
function LoginScreen({onLogin}){
  const [mode,setMode]=useState("login");
  const [form,setForm]=useState({username:"",password:"",email:"",full_name:""});
  const [error,setError]=useState("");const [loading,setLoading]=useState(false);
  const [showPw,setShowPw]=useState(false);const [remember,setRemember]=useState(false);

  const submit=async(e)=>{
    e.preventDefault();setError("");setLoading(true);
    try{if(mode==="register"){await auth.register({...form});setMode("login");setForm(p=>({...p,password:""}));setError("");setLoading(false);return;}await auth.login(form.username,form.password);onLogin();}
    catch(err){setError(err.message);}finally{setLoading(false);}
  };

  return(
    <div className="min-h-screen flex relative overflow-hidden">
      {/* Left — Brand Panel */}
      <div className="hidden lg:flex lg:w-[55%] login-bg relative items-center justify-center">
        <LoginParticles/><div className="login-grid"/>
        <div className="login-glow" style={{top:"-10%",left:"20%",width:"400px",height:"400px",background:"radial-gradient(circle,rgba(255,255,255,0.08),transparent 70%)"}}/>
        <div className="login-glow" style={{bottom:"10%",right:"10%",width:"300px",height:"300px",background:"radial-gradient(circle,rgba(6,182,212,0.1),transparent 70%)"}}/>
        <div className="relative z-10 text-center px-12 fade-in">
          <Logo size={80} className="mx-auto mb-6 drop-shadow-2xl"/>
          <h1 className="text-4xl font-bold text-white mb-3 tracking-tight">CyberSec Suite</h1>
          <p className="text-blue-200/80 text-lg mb-2">AI-Powered Security Operations Center</p>
          <p className="text-blue-300/50 text-sm">Protect · Detect · Respond</p>
          <div className="flex items-center justify-center gap-8 mt-12">
            {[{n:"1,248",l:"Scans"},{n:"99.9%",l:"Uptime"},{n:"24/7",l:"Monitoring"}].map(s=>(
              <div key={s.l} className="text-center"><div className="text-2xl font-bold text-white">{s.n}</div><div className="text-[11px] text-blue-300/50 uppercase tracking-wider mt-1">{s.l}</div></div>
            ))}
          </div>
        </div>
      </div>

      {/* Right — Form */}
      <div className="flex-1 flex items-center justify-center bg-white px-6 lg:px-16">
        <div className="w-full max-w-[400px] fade-in">
          <div className="lg:hidden flex items-center gap-3 mb-8"><Logo size={36}/><h1 className="text-xl font-bold text-gray-900">CyberSec Suite</h1></div>

          {/* Tabs */}
          <div className="flex gap-1 mb-8 p-1 rounded-xl bg-gray-50 border border-gray-100">
            {[["login","Sign In",LogIn],["register","Register",UserPlus]].map(([id,label,Icon])=>(
              <button key={id} onClick={()=>{setMode(id);setError("");}}
                className={`flex-1 py-2.5 text-[13px] font-medium flex items-center justify-center gap-2 rounded-lg transition-all ${
                  mode===id?"bg-white text-blue-600 shadow-sm border border-gray-200":"text-gray-400 hover:text-gray-600"
                }`}><Icon size={14}/>{label}</button>
            ))}
          </div>

          <h2 className="text-xl font-bold text-gray-900 mb-1">{mode==="login"?"Welcome Back":"Create Account"}</h2>
          <p className="text-[13px] text-gray-400 mb-6">{mode==="login"?"Sign in to continue to your account":"Set up your security analyst account"}</p>

          <form onSubmit={submit} className="space-y-4">
            {mode==="register"&&<>
              <div><label className="text-[12px] font-medium text-gray-600 block mb-1.5">Full Name</label>
                <input className="input-field" placeholder="Enter your full name" value={form.full_name} onChange={e=>setForm(p=>({...p,full_name:e.target.value}))}/></div>
              <div><label className="text-[12px] font-medium text-gray-600 block mb-1.5">Email Address</label>
                <input className="input-field" type="email" placeholder="analyst@company.com" required value={form.email} onChange={e=>setForm(p=>({...p,email:e.target.value}))}/></div>
            </>}
            <div><label className="text-[12px] font-medium text-gray-600 block mb-1.5">{mode==="login"?"Email or Username":"Username"}</label>
              <input className="input-field" placeholder="Enter your username" required value={form.username} onChange={e=>setForm(p=>({...p,username:e.target.value}))}/></div>
            <div><label className="text-[12px] font-medium text-gray-600 block mb-1.5">Password</label>
              <div className="relative">
                <input className="input-field !pr-10" type={showPw?"text":"password"} placeholder="Enter your password" required value={form.password} onChange={e=>setForm(p=>({...p,password:e.target.value}))}/>
                <button type="button" onClick={()=>setShowPw(!showPw)} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 transition-colors">
                  {showPw?<EyeOff size={16}/>:<Eye size={16}/>}
                </button>
              </div></div>

            {mode==="login"&&<div className="flex items-center justify-between text-[12px]">
              <label className="flex items-center gap-2 text-gray-500 cursor-pointer select-none">
                <input type="checkbox" checked={remember} onChange={e=>setRemember(e.target.checked)} className="w-3.5 h-3.5 rounded border-gray-300 text-blue-600 focus:ring-blue-500/20"/>Remember me</label>
              <a className="text-blue-600 hover:text-blue-700 cursor-pointer font-medium">Forgot password?</a>
            </div>}

            {error&&<div className="text-[12px] text-red-600 bg-red-50 border border-red-200 rounded-xl px-4 py-2.5 flex items-center gap-2"><XCircle size={14}/>{error}</div>}

            <button type="submit" disabled={loading} className="w-full py-3 rounded-xl text-sm font-semibold flex items-center justify-center gap-2 btn-primary">
              {loading?<Loader2 size={16} className="animate-spin"/>:<><Fingerprint size={16}/>{mode==="login"?"Sign In":"Create Account"}</>}
            </button>
          </form>

          <p className="text-[12px] text-gray-400 text-center mt-6">
            {mode==="login"?<>Don't have an account? <button onClick={()=>setMode("register")} className="text-blue-600 hover:text-blue-700 font-medium">Register</button></>
              :<>Already have an account? <button onClick={()=>setMode("login")} className="text-blue-600 hover:text-blue-700 font-medium">Sign In</button></>}
          </p>
        </div>
      </div>
    </div>
  );
}

/* ═══ DASHBOARD ═════════════════════════════════════════════ */
function DashboardView({setActiveTab}){
  const [stats,setStats]=useState(null);const [trend,setTrend]=useState([]);
  const [alerts,setAlerts]=useState([]);const [scanList,setScanList]=useState([]);const [loading,setLoading]=useState(true);
  useEffect(()=>{(async()=>{try{const [s,t,a,sc]=await Promise.all([dashboard.stats().catch(()=>null),dashboard.trend().catch(()=>[]),
    dashboard.alerts().catch(()=>[]),scans.list({limit:5}).catch(()=>[])]);setStats(s);setTrend(t);setAlerts(a);setScanList(sc);}finally{setLoading(false);}})();},[]);
  if(loading)return<Spinner/>;
  const sevData=stats?.severity_distribution?Object.entries(stats.severity_distribution).map(([n,v])=>({name:n,value:v,color:SC[n]})):[];

  return(
    <div className="space-y-5 fade-in">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Stat icon={ScanLine} label="Total Scans" value={stats?.total_scans??0} color="bg-blue-50 text-blue-600" trend={12}/>
        <Stat icon={AlertTriangle} label="Active Threats" value={stats?.open_vulnerabilities??0} color="bg-red-50 text-red-500" trend={-8}/>
        <Stat icon={Bug} label="Vulnerabilities" value={stats?.active_incidents??0} color="bg-amber-50 text-amber-500" trend={5}/>
        <Stat icon={Shield} label="Risk Score" value={`${stats?.risk_score??0} / 100`} color="bg-emerald-50 text-emerald-600"/>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="card-static p-5 lg:col-span-2">
          <h3 className="text-[13px] font-semibold text-gray-700 mb-4 flex items-center gap-2"><Activity size={14} className="text-blue-500"/>Threat Activity (Live)</h3>
          {trend.length>0?(
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={trend}>
                <defs><linearGradient id="tc" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#EF4444" stopOpacity={0.15}/><stop offset="100%" stopColor="#EF4444" stopOpacity={0}/></linearGradient>
                  <linearGradient id="th" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#F97316" stopOpacity={0.1}/><stop offset="100%" stopColor="#F97316" stopOpacity={0}/></linearGradient></defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#F3F4F6"/><XAxis dataKey="date" tick={{fill:"#9CA3AF",fontSize:10}} axisLine={false} tickLine={false}
                  tickFormatter={v=>new Date(v).toLocaleDateString('en',{weekday:'short'})}/><YAxis tick={{fill:"#9CA3AF",fontSize:10}} axisLine={false} tickLine={false}/>
                <Tooltip content={Tip}/>
                <Area type="monotone" dataKey="critical" stackId="1" stroke="#EF4444" fill="url(#tc)" strokeWidth={2}/>
                <Area type="monotone" dataKey="high" stackId="1" stroke="#F97316" fill="url(#th)" strokeWidth={2}/>
                <Area type="monotone" dataKey="medium" stackId="1" stroke="#EAB308" fill="#EAB308" fillOpacity={0.06} strokeWidth={1.5}/>
                <Area type="monotone" dataKey="low" stackId="1" stroke="#10B981" fill="#10B981" fillOpacity={0.04} strokeWidth={1.5}/>
              </AreaChart>
            </ResponsiveContainer>
          ):<div className="flex items-center justify-center h-[220px] text-gray-300 text-sm">Run scans to populate threat data</div>}
        </div>
        <div className="card-static p-5">
          <h3 className="text-[13px] font-semibold text-gray-700 mb-4 flex items-center gap-2"><Target size={14} className="text-blue-500"/>Top Threat Types</h3>
          {sevData.some(d=>d.value>0)?(<>
            <ResponsiveContainer width="100%" height={170}><PieChart><Pie data={sevData} cx="50%" cy="50%" innerRadius={45} outerRadius={72} paddingAngle={3} dataKey="value" strokeWidth={0}>
              {sevData.map((e,i)=><Cell key={i} fill={e.color}/>)}</Pie><Tooltip content={Tip}/></PieChart></ResponsiveContainer>
            <div className="space-y-1.5 mt-2">{sevData.map(d=>(
              <div key={d.name} className="flex items-center justify-between text-[11px]">
                <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded" style={{background:d.color}}/><span className="text-gray-500 capitalize">{d.name}</span></div>
                <span className="text-gray-400 font-mono font-medium">{d.value}</span></div>
            ))}</div>
          </>):<div className="flex items-center justify-center h-[200px] text-gray-300 text-sm">No threat data</div>}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="card-static p-5 lg:col-span-2">
          <h3 className="text-[13px] font-semibold text-gray-700 mb-4 flex items-center gap-2"><Bell size={14} className="text-blue-500"/>Recent Alerts</h3>
          {alerts.length>0?(
            <div className="space-y-2 max-h-[250px] overflow-y-auto pr-1">{alerts.map(a=>(
              <div key={a.id} className="flex items-start gap-3 p-3 rounded-xl border border-gray-100 hover:bg-blue-50/50 hover:border-blue-100 transition-all cursor-pointer group">
                {a.severity==="critical"?<XCircle size={14} className="text-red-500 mt-0.5 shrink-0"/>:a.severity==="high"?<AlertTriangle size={14} className="text-orange-500 mt-0.5 shrink-0"/>:<Info size={14} className="text-blue-500 mt-0.5 shrink-0"/>}
                <div className="flex-1 min-w-0"><p className="text-[12px] text-gray-600 leading-relaxed group-hover:text-gray-800 transition-colors">{a.message}</p>
                  <div className="flex items-center gap-2 mt-1.5 text-[10px] text-gray-400">
                    <span>{new Date(a.created_at).toLocaleTimeString('en',{hour:'2-digit',minute:'2-digit'})}</span>
                    <span className="w-1 h-1 rounded-full bg-gray-200"/><span>{a.source}</span></div></div>
                <Badge severity={a.severity}/>
              </div>
            ))}</div>
          ):<p className="text-sm text-gray-300 text-center py-10">No alerts yet</p>}
        </div>
        <div className="card-static p-5">
          <h3 className="text-[13px] font-semibold text-gray-700 mb-4 flex items-center gap-2"><MonitorDot size={14} className="text-emerald-500"/>System Status</h3>
          {["Firewall","IDS/IPS","Endpoint Protection","SIEM","Network Monitor"].map(s=>(
            <div key={s} className="flex items-center justify-between py-2.5 border-b border-gray-50 last:border-0">
              <span className="text-[12px] text-gray-600">{s}</span>
              <span className="text-[10px] text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded-md border border-emerald-100 font-semibold">Online</span></div>
          ))}<p className="text-[10px] text-gray-300 mt-3">Last Updated: {new Date().toLocaleTimeString()}</p>
        </div>
      </div>

      <div className="card-static p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-[13px] font-semibold text-gray-700 flex items-center gap-2"><ScanLine size={14} className="text-blue-500"/>Recent Scans</h3>
          <button onClick={()=>setActiveTab("attack")} className="text-[11px] text-blue-600 hover:text-blue-700 flex items-center gap-1 font-medium transition-colors">View all<ChevronRight size={12}/></button>
        </div>
        {scanList.length>0?(
          <table className="w-full text-[12px]"><thead><tr className="text-[10px] text-gray-400 uppercase tracking-wider border-b border-gray-100">
            <th className="text-left py-2.5 font-medium">Target</th><th className="text-left py-2.5 font-medium">Type</th>
            <th className="text-left py-2.5 font-medium">Status</th><th className="text-left py-2.5 font-medium">Severity</th>
            <th className="text-right py-2.5 font-medium">Findings</th></tr></thead>
            <tbody>{scanList.map(s=><tr key={s.id} className="trow border-b border-gray-50">
              <td className="py-3 font-mono text-blue-600 text-[11px]">{s.target}</td><td className="py-3 text-gray-500 capitalize">{s.scan_type}</td>
              <td className="py-3"><div className="flex items-center gap-2"><Dot status={s.status}/><span className="text-gray-500 capitalize">{s.status}</span></div></td>
              <td className="py-3">{s.severity?<Badge severity={s.severity}/>:<span className="text-gray-300">—</span>}</td>
              <td className="py-3 text-right text-gray-600 font-mono font-medium">{s.total_findings}</td></tr>)}</tbody></table>
        ):<p className="text-sm text-gray-300 text-center py-10">No scans yet</p>}
      </div>
    </div>
  );
}

/* ═══ ATTACK SIM ════════════════════════════════════════════ */
function AttackView(){
  const [target,setTarget]=useState("");const [scanType,setScanType]=useState("network");
  const [scanning,setScanning]=useState(false);const [progress,setProgress]=useState(0);
  const [scanId,setScanId]=useState(null);const [result,setResult]=useState(null);
  const [list,setList]=useState([]);const [tab,setTab]=useState("ports");const [err,setErr]=useState("");const poll=useRef(null);
  useEffect(()=>{scans.list({limit:20}).then(setList).catch(()=>{});return()=>{if(poll.current)clearInterval(poll.current)};},[]);
  const start=async()=>{if(!target)return;setErr("");setScanning(true);setProgress(0);setResult(null);
    try{const r=await scans.create(target,scanType);setScanId(r.scan_id);poll.current=setInterval(async()=>{try{const st=await scans.status(r.scan_id);setProgress(st.progress);
      if(st.status==="completed"||st.status==="failed"){clearInterval(poll.current);setScanning(false);if(st.status==="completed")setResult(await scans.get(r.scan_id));else setErr("Scan failed");
        setList(await scans.list({limit:20}));}}catch{}},1500);}catch(e){setErr(e.message);setScanning(false);}};
  const stop=async()=>{if(scanId)await scans.cancel(scanId).catch(()=>{});if(poll.current)clearInterval(poll.current);setScanning(false);};
  const types=[{id:"network",label:"Network",icon:Network,d:"Hosts & services"},{id:"port",label:"Port Scan",icon:Server,d:"Open ports"},{id:"vulnerability",label:"Vuln Scan",icon:Bug,d:"Known CVEs"},{id:"webapp",label:"Web App",icon:Globe,d:"OWASP Top 10"}];
  return(
    <div className="space-y-5 fade-in">
      <div className="card-static p-5 space-y-5">
        <div><label className="text-[11px] text-gray-400 uppercase tracking-wider font-medium block mb-2">Target</label>
          <div className="flex gap-3"><div className="flex-1 relative"><Crosshair size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-400"/>
            <input className="input-field !pl-10 font-mono" value={target} onChange={e=>setTarget(e.target.value)} placeholder="IP address, CIDR range, or hostname"/></div>
            {!scanning?<button onClick={start} disabled={!target} className="px-5 py-2.5 rounded-xl text-sm font-semibold flex items-center gap-2 btn-primary"><Play size={14}/>Launch Scan</button>
              :<button onClick={stop} className="px-5 py-2.5 rounded-xl text-sm font-semibold flex items-center gap-2 bg-gradient-to-r from-red-600 to-red-500 text-white shadow-lg shadow-red-500/15"><Square size={14}/>Abort</button>}</div></div>
        <div><label className="text-[11px] text-gray-400 uppercase tracking-wider font-medium block mb-2">Scan Type</label>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">{types.map(st=>(
            <button key={st.id} onClick={()=>setScanType(st.id)} className={`p-4 rounded-xl border text-left transition-all ${
              scanType===st.id?"border-blue-300 bg-blue-50 shadow-sm":"border-gray-200 hover:border-gray-300 hover:bg-gray-50"}`}>
              <st.icon size={16} className={scanType===st.id?"text-blue-600":"text-gray-400"}/><div className={`text-[13px] font-medium mt-2 ${scanType===st.id?"text-blue-700":"text-gray-500"}`}>{st.label}</div>
              <div className="text-[10px] text-gray-400 mt-0.5">{st.d}</div></button>))}</div></div>
        {scanning&&<div><div className="flex justify-between text-[11px] mb-2"><span className="text-gray-400">Scanning...</span><span className="text-blue-600 font-mono font-medium">{progress}%</span></div>
          <div className="w-full h-1.5 bg-gray-100 rounded-full overflow-hidden"><div className="h-full rounded-full bg-gradient-to-r from-blue-600 to-cyan-500 transition-all duration-500" style={{width:`${progress}%`}}/></div></div>}
        {err&&<div className="text-[12px] text-red-600 bg-red-50 border border-red-200 rounded-xl px-4 py-2.5 flex items-center gap-2"><XCircle size={14}/>{err}</div>}
      </div>
      {result&&<div className="card-static overflow-hidden fade-in">
        <div className="p-5 border-b border-gray-100 flex items-center justify-between">
          <div><div className="flex items-center gap-3"><span className="font-mono text-[10px] text-gray-400">{result.id.slice(0,8)}</span>{result.severity&&<Badge severity={result.severity}/>}</div>
            <p className="text-[13px] text-gray-600 mt-1">Target: <span className="font-mono text-blue-600">{result.target}</span></p></div>
          <div className="text-right"><div className="text-3xl font-bold text-gray-900">{result.total_findings}</div><div className="text-[10px] text-gray-400">findings</div></div></div>
        <div className="flex border-b border-gray-100">{[{id:"ports",l:"Ports",c:result.ports?.length||0},{id:"vulns",l:"Vulnerabilities",c:result.vulnerabilities?.length||0}].map(t=>(
          <button key={t.id} onClick={()=>setTab(t.id)} className={`px-5 py-3 text-[13px] font-medium flex items-center gap-2 border-b-2 transition-all ${
            tab===t.id?"border-blue-600 text-blue-600 bg-blue-50/50":"border-transparent text-gray-400 hover:text-gray-600"}`}>
            {t.l}<span className={`text-[10px] px-1.5 py-0.5 rounded-md font-semibold ${tab===t.id?"bg-blue-100 text-blue-600":"bg-gray-100 text-gray-400"}`}>{t.c}</span></button>))}</div>
        <div className="p-5">{tab==="ports"?(result.ports?.length>0?
          <table className="w-full text-[12px]"><thead><tr className="text-[10px] text-gray-400 uppercase tracking-wider border-b border-gray-100">
            <th className="text-left py-2.5 font-medium">Port</th><th className="text-left py-2.5 font-medium">Service</th><th className="text-left py-2.5 font-medium">State</th>
            <th className="text-left py-2.5 font-medium">Version</th><th className="text-left py-2.5 font-medium">Risk</th></tr></thead>
            <tbody>{result.ports.map((p,i)=><tr key={i} className="trow border-b border-gray-50"><td className="py-3 font-mono text-blue-600">{p.port_number}</td>
              <td className="py-3 text-gray-600">{p.service_name||"—"}</td>
              <td className="py-3"><span className={`flex items-center gap-1.5 ${p.state==="open"?"text-emerald-600":"text-gray-400"}`}>{p.state==="open"?<Unlock size={11}/>:<Lock size={11}/>}{p.state}</span></td>
              <td className="py-3 text-gray-400 font-mono text-[10px]">{p.service_version||"—"}</td><td className="py-3">{p.risk_level?<Badge severity={p.risk_level}/>:"—"}</td></tr>)}</tbody></table>
          :<p className="text-gray-300 text-sm text-center py-10">No open ports</p>)
          :(result.vulnerabilities?.length>0?<div className="space-y-2">{result.vulnerabilities.map(v=>(
            <div key={v.id} className="p-4 rounded-xl border border-gray-100 hover:bg-blue-50/30 hover:border-blue-100 transition-all">
              <div className="flex items-center gap-3 mb-1">{v.cve_id&&<span className="font-mono text-[10px] text-gray-400">{v.cve_id}</span>}<Badge severity={v.severity}/>
                {v.cvss_score&&<span className="text-[10px] text-gray-400 font-mono">CVSS {v.cvss_score}</span>}</div>
              <h4 className="text-[13px] font-medium text-gray-800">{v.title}</h4>
              {v.description&&<p className="text-[11px] text-gray-400 mt-1 leading-relaxed">{v.description}</p>}</div>
          ))}</div>:<p className="text-gray-300 text-sm text-center py-10">No vulnerabilities</p>)}</div>
      </div>}
      {list.length>0&&<div className="card-static p-5 fade-in"><h3 className="text-[13px] font-semibold text-gray-700 mb-4 flex items-center gap-2"><Clock size={14} className="text-blue-500"/>Scan History</h3>
        <table className="w-full text-[12px]"><thead><tr className="text-[10px] text-gray-400 uppercase tracking-wider border-b border-gray-100">
          <th className="text-left py-2.5 font-medium">Target</th><th className="text-left py-2.5 font-medium">Type</th><th className="text-left py-2.5 font-medium">Status</th>
          <th className="text-left py-2.5 font-medium">Severity</th><th className="text-right py-2.5 font-medium">Findings</th></tr></thead>
          <tbody>{list.map(s=><tr key={s.id} className="trow border-b border-gray-50 cursor-pointer" onClick={()=>scans.get(s.id).then(setResult).catch(()=>{})}>
            <td className="py-3 font-mono text-blue-600 text-[11px]">{s.target}</td><td className="py-3 text-gray-500 capitalize">{s.scan_type}</td>
            <td className="py-3"><div className="flex items-center gap-2"><Dot status={s.status}/><span className="text-gray-500 capitalize">{s.status}</span></div></td>
            <td className="py-3">{s.severity?<Badge severity={s.severity}/>:<span className="text-gray-300">—</span>}</td>
            <td className="py-3 text-right text-gray-600 font-mono">{s.total_findings}</td></tr>)}</tbody></table></div>}
    </div>);
}

/* ═══ FORENSICS ═════════════════════════════════════════════ */
function ForensicsView(){
  const [cases,setCases]=useState([]);const [active,setActive]=useState(null);const [detail,setDetail]=useState(null);
  const [logs,setLogs]=useState([]);const [title,setTitle]=useState("");const [showNew,setShowNew]=useState(false);
  const [uploading,setUploading]=useState(false);const [res,setRes]=useState(null);const [loading,setLoading]=useState(true);const fr=useRef(null);
  useEffect(()=>{forensics.listCases().then(setCases).catch(()=>{}).finally(()=>setLoading(false));},[]);
  const create=async()=>{if(!title)return;const r=await forensics.createCase(title);setShowNew(false);setTitle("");setCases(await forensics.listCases());setActive(r.case_id);};
  const load=async(id)=>{setActive(id);setDetail(await forensics.getCase(id));setLogs(await forensics.getLogs(id,{limit:100}));};
  const up=async(e)=>{const f=e.target.files[0];if(!f||!active)return;setUploading(true);setRes(null);try{setRes(await forensics.uploadLogs(active,f));await load(active);}catch(e){setRes({error:e.message});}finally{setUploading(false);}};
  const yr=async(e)=>{const f=e.target.files[0];if(!f||!active)return;setUploading(true);try{setRes(await forensics.yaraScan(active,f));await load(active);}catch(e){setRes({error:e.message});}finally{setUploading(false);}};
  if(loading)return<Spinner/>;
  return(
    <div className="space-y-5 fade-in">
      <div className="flex items-center justify-between"><p className="text-[13px] text-gray-400">Analyze logs, detect malware, collect evidence</p>
        <button onClick={()=>setShowNew(true)} className="px-4 py-2 rounded-xl text-sm font-semibold flex items-center gap-2 btn-primary"><Fingerprint size={14}/>New Case</button></div>
      {showNew&&<div className="card-static p-5 fade-in"><div className="flex gap-3"><input className="input-field flex-1" value={title} onChange={e=>setTitle(e.target.value)} placeholder="Case title"/>
        <button onClick={create} className="px-4 py-2 rounded-xl text-sm font-semibold btn-primary">Create</button>
        <button onClick={()=>setShowNew(false)} className="px-4 py-2 rounded-xl text-sm font-medium btn-ghost">Cancel</button></div></div>}
      {cases.length>0?<div className="grid grid-cols-1 lg:grid-cols-3 gap-3">{cases.map(c=>(
        <div key={c.id} onClick={()=>load(c.id)} className={`card cursor-pointer fade-in ${active===c.id?"!border-blue-300 !bg-blue-50/50":""}`}>
          <div className="p-4"><div className="flex items-center justify-between mb-2"><span className="font-mono text-[10px] text-gray-400">{c.case_number}</span>
            <span className={`text-[10px] px-2 py-0.5 rounded-md capitalize border font-semibold ${c.status==="open"?"bg-emerald-50 text-emerald-600 border-emerald-200":"bg-amber-50 text-amber-600 border-amber-200"}`}>{c.status}</span></div>
            <h4 className="text-[13px] font-medium text-gray-800">{c.title}</h4>
            <div className="flex gap-4 mt-2 text-[10px] text-gray-400 font-medium"><span>{c.total_logs} logs</span><span>{c.anomaly_count} anomalies</span><span>{c.yara_match_count} YARA</span></div></div></div>
      ))}</div>:!showNew?<Empty icon={Search} msg="No forensic cases" action="Create First Case" onClick={()=>setShowNew(true)}/>:null}
      {active&&(<>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <Stat icon={FileText} label="Log Entries" value={detail?.total_logs??0} color="bg-blue-50 text-blue-600"/>
          <Stat icon={AlertTriangle} label="Anomalies" value={detail?.anomaly_count??0} color="bg-orange-50 text-orange-500"/>
          <Stat icon={Bug} label="YARA Matches" value={detail?.yara_match_count??0} color="bg-red-50 text-red-500"/>
          <Stat icon={Layers} label="Evidence" value={detail?.evidence?.length??0} color="bg-purple-50 text-purple-500"/></div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div onClick={()=>fr.current?.click()} className="card cursor-pointer group text-center py-8"><input ref={fr} type="file" className="hidden" onChange={up} accept=".log,.json,.csv,.txt"/>
            {uploading?<Loader2 size={24} className="mx-auto text-blue-500 animate-spin"/>:<Upload size={24} className="mx-auto text-gray-300 group-hover:text-blue-500 transition-colors"/>}
            <p className="text-[13px] text-gray-400 mt-2">{uploading?"Analyzing...":"Upload Logs"}</p></div>
          <div onClick={()=>{const i=document.createElement('input');i.type='file';i.onchange=yr;i.click();}} className="card cursor-pointer group text-center py-8">
            <Shield size={24} className="mx-auto text-gray-300 group-hover:text-red-500 transition-colors"/><p className="text-[13px] text-gray-400 mt-2">YARA Scan</p></div></div>
        {res&&!res.error&&<div className="bg-emerald-50 border border-emerald-200 rounded-xl p-4 text-[13px] text-emerald-700 fade-in"><CheckCircle size={14} className="inline mr-2"/>
          {res.entries_parsed!==undefined?`Parsed ${res.entries_parsed} entries, ${res.anomalies_detected} anomalies`:`${res.matches} YARA matches`}</div>}
        {detail?.yara_matches?.length>0&&<div className="card-static p-5 fade-in"><h3 className="text-[13px] font-semibold text-gray-700 mb-4">YARA Matches</h3>
          <div className="space-y-2">{detail.yara_matches.map(m=>(
            <div key={m.id} className="flex items-center gap-3 p-3 rounded-xl border border-gray-100 hover:bg-blue-50/50 transition-all"><Badge severity={m.severity}/>
              <div><span className="text-[13px] font-medium text-gray-800">{m.rule_name}</span>{m.confidence&&<span className="text-[10px] text-blue-600 ml-2 font-mono">{Math.round(m.confidence*100)}%</span>}
                <div className="text-[10px] text-gray-400 font-mono mt-0.5">{m.file_path}</div></div></div>))}</div></div>}
        {logs.length>0&&<div className="card-static p-5 fade-in"><h3 className="text-[13px] font-semibold text-gray-700 mb-4">Log Analysis</h3>
          <table className="w-full text-[12px]"><thead><tr className="text-[10px] text-gray-400 uppercase tracking-wider border-b border-gray-100">
            <th className="text-left py-2.5 font-medium">Timestamp</th><th className="text-left py-2.5 font-medium">Source</th><th className="text-left py-2.5 font-medium">Event</th>
            <th className="text-left py-2.5 font-medium">Severity</th><th className="text-left py-2.5 font-medium">Score</th></tr></thead>
            <tbody>{logs.map((e,i)=><tr key={i} className={`trow border-b border-gray-50 ${e.is_anomaly?"!bg-red-50/50":""}`}>
              <td className="py-3 font-mono text-[10px] text-gray-400 whitespace-nowrap">{new Date(e.timestamp).toLocaleString()}</td>
              <td className="py-3 font-mono text-[10px] text-blue-600">{e.source_ip||"—"}</td><td className="py-3 text-gray-600">{e.event_type}</td>
              <td className="py-3"><Badge severity={e.severity}/></td>
              <td className="py-3">{e.is_anomaly?<span className="text-[10px] text-red-600 font-mono bg-red-50 px-1.5 py-0.5 rounded border border-red-100">{e.anomaly_score?.toFixed(2)}</span>:<span className="text-gray-300">—</span>}</td>
            </tr>)}</tbody></table></div>}
      </>)}
    </div>);
}

/* ═══ RCA ═══════════════════════════════════════════════════ */
function RCAView(){
  const [incidents,setIncidents]=useState([]);const [active,setActive]=useState(null);const [detail,setDetail]=useState(null);
  const [showNew,setShowNew]=useState(false);const [title,setTitle]=useState("");const [sev,setSev]=useState("high");
  const [busy,setBusy]=useState(false);const [loading,setLoading]=useState(true);
  useEffect(()=>{rca.listIncidents().then(setIncidents).catch(()=>{}).finally(()=>setLoading(false));},[]);
  const create=async()=>{if(!title)return;const r=await rca.createIncident({title,severity:sev});setShowNew(false);setTitle("");setIncidents(await rca.listIncidents());load(r.incident_id);};
  const load=async(id)=>{setActive(id);setDetail(await rca.getIncident(id));};
  const correlate=async()=>{if(!active)return;setBusy(true);try{await rca.correlate(active);await load(active);}finally{setBusy(false);}};
  const analyze=async()=>{if(!active)return;setBusy(true);try{await rca.analyze(active);await load(active);}finally{setBusy(false);}};
  if(loading)return<Spinner/>;
  return(
    <div className="space-y-5 fade-in">
      <div className="flex items-center justify-between"><p className="text-[13px] text-gray-400">Correlate events, identify root causes, generate remediation</p>
        <button onClick={()=>setShowNew(true)} className="px-4 py-2 rounded-xl text-sm font-semibold flex items-center gap-2 btn-primary"><GitBranch size={14}/>New Incident</button></div>
      {showNew&&<div className="card-static p-5 space-y-3 fade-in"><input className="input-field" value={title} onChange={e=>setTitle(e.target.value)} placeholder="Incident title"/>
        <div className="flex gap-2">{["critical","high","medium","low"].map(s=>(
          <button key={s} onClick={()=>setSev(s)} className={`text-[11px] px-3 py-2 rounded-lg capitalize border font-medium transition-all ${
            sev===s?"border-blue-300 bg-blue-50 text-blue-600":"border-gray-200 text-gray-400 hover:border-gray-300"}`}>{s}</button>))}</div>
        <div className="flex gap-2"><button onClick={create} className="px-4 py-2 rounded-xl text-sm font-semibold btn-primary">Create</button>
          <button onClick={()=>setShowNew(false)} className="px-4 py-2 rounded-xl text-sm font-medium btn-ghost">Cancel</button></div></div>}
      {incidents.length>0?<div className="space-y-2">{incidents.map(inc=>(
        <div key={inc.id} onClick={()=>load(inc.id)} className={`card cursor-pointer fade-in ${active===inc.id?"!border-blue-300 !bg-blue-50/50":""}`}>
          <div className="p-4 flex items-center justify-between"><div className="flex items-center gap-3"><span className="font-mono text-[10px] text-gray-400">{inc.incident_number}</span><Badge severity={inc.severity}/>
            <span className="text-[13px] text-gray-800 font-medium">{inc.title}</span></div>
            <div className="flex items-center gap-4 text-[10px] text-gray-400 font-medium"><span>{inc.affected_hosts} hosts</span><span>{inc.attack_phases} phases</span><span className="capitalize">{inc.status}</span></div></div></div>
      ))}</div>:!showNew?<Empty icon={GitBranch} msg="No incidents" action="Create Incident" onClick={()=>setShowNew(true)}/>:null}
      {detail&&(<>
        <div className="flex gap-3">
          <button onClick={correlate} disabled={busy} className="px-4 py-2 rounded-xl text-sm font-medium flex items-center gap-2 btn-ghost">{busy?<Loader2 size={14} className="animate-spin"/>:<GitBranch size={14}/>}Correlate</button>
          <button onClick={analyze} disabled={busy} className="px-4 py-2 rounded-xl text-sm font-semibold flex items-center gap-2 btn-primary">{busy?<Loader2 size={14} className="animate-spin"/>:<Zap size={14}/>}AI Analysis</button></div>
        {detail.root_cause&&<div className="card-static p-5 border-l-4 border-l-red-400 fade-in"><h3 className="text-[13px] font-semibold text-gray-700 mb-2 flex items-center gap-2"><Flame size={14} className="text-red-500"/>Root Cause</h3>
          <p className="text-[13px] text-gray-600 leading-relaxed">{detail.root_cause}</p>
          {detail.ai_summary&&<p className="text-[12px] text-gray-400 mt-3 pt-3 border-t border-gray-100 leading-relaxed">{detail.ai_summary}</p>}</div>}
        {detail.timeline?.length>0&&<div className="card-static p-5 fade-in"><h3 className="text-[13px] font-semibold text-gray-700 mb-5 flex items-center gap-2"><Activity size={14} className="text-blue-500"/>Attack Timeline</h3>
          <div className="relative"><div className="absolute left-[19px] top-3 bottom-3 w-px bg-gradient-to-b from-red-300 via-orange-200 to-blue-200"/>
            <div className="space-y-0.5">{detail.timeline.map((ev,i)=>(
              <div key={i} className="relative flex gap-4 p-3 rounded-xl hover:bg-blue-50/50 transition-all">
                <div className="relative z-10 mt-1.5"><div className="w-2.5 h-2.5 rounded-full border-2 bg-white" style={{borderColor:SC[ev.severity]||"#9CA3AF"}}/></div>
                <div className="flex-1"><div className="flex items-center gap-3 flex-wrap">
                  <span className="text-[10px] font-mono text-gray-400">{new Date(ev.timestamp).toLocaleTimeString()}</span>
                  {ev.phase&&<span className="text-[9px] px-2 py-0.5 rounded-md border border-gray-200 text-gray-400 font-mono uppercase tracking-wider bg-gray-50">{ev.phase}</span>}
                  <Badge severity={ev.severity}/></div>
                  <p className="text-[13px] text-gray-700 mt-1.5">{ev.event}</p>
                  {ev.details&&<p className="text-[11px] text-gray-400 mt-1 leading-relaxed">{ev.details}</p>}</div></div>
            ))}</div></div></div>}
        {detail.remediations?.length>0&&<div className="card-static p-5 fade-in"><h3 className="text-[13px] font-semibold text-gray-700 mb-4 flex items-center gap-2"><Zap size={14} className="text-blue-500"/>Remediation Plan</h3>
          <div className="space-y-2">{detail.remediations.map(r=>{
            const bc={P0:"border-l-red-500 bg-red-50/30",P1:"border-l-orange-400 bg-orange-50/20",P2:"border-l-amber-400",P3:"border-l-gray-300"};
            const tc={P0:"text-red-600",P1:"text-orange-600",P2:"text-amber-600",P3:"text-gray-400"};
            return<div key={r.id} className={`p-4 rounded-xl border border-gray-100 border-l-4 ${bc[r.priority]||bc.P3} hover:shadow-sm transition-all`}>
              <div className="flex items-start gap-3"><span className={`text-[10px] font-mono font-bold mt-0.5 ${tc[r.priority]||tc.P3}`}>{r.priority}</span>
                <div className="flex-1"><p className="text-[13px] text-gray-700">{r.action}</p>
                  <div className="flex items-center gap-4 mt-2 text-[10px] text-gray-400 font-medium">{r.impact&&<span>{r.impact}</span>}{r.effort&&<span>{r.effort}</span>}
                    <span className={r.status==="completed"?"text-emerald-600 font-semibold":""}>{r.status}</span></div></div></div></div>;
          })}</div></div>}
      </>)}
    </div>);
}

/* ═══ REPORTS ═══════════════════════════════════════════════ */
function ReportsView(){
  const [busy,setBusy]=useState(false);const [type,setType]=useState("vulnerability");
  const [id,setId]=useState("");const [list,setList]=useState([]);const [err,setErr]=useState("");
  const gen=async()=>{if(!id)return;setBusy(true);setErr("");try{const r=await reports.generate(type,id);setList(p=>[{...r,at:new Date().toISOString()},...p]);}catch(e){setErr(e.message);}finally{setBusy(false);}};
  return(
    <div className="space-y-5 fade-in">
      <p className="text-[13px] text-gray-400">Generate comprehensive PDF security reports</p>
      <div className="card-static p-5 space-y-4">
        <div><label className="text-[11px] text-gray-400 uppercase tracking-wider font-medium block mb-2">Report Type</label>
          <div className="flex gap-2">{["vulnerability","incident","forensic"].map(t=>(
            <button key={t} onClick={()=>setType(t)} className={`px-4 py-2 rounded-xl text-[13px] capitalize border font-medium transition-all ${
              type===t?"border-blue-300 bg-blue-50 text-blue-600":"border-gray-200 text-gray-400 hover:border-gray-300 hover:bg-gray-50"}`}>{t}</button>))}</div></div>
        <div><label className="text-[11px] text-gray-400 uppercase tracking-wider font-medium block mb-2">Entity ID</label>
          <div className="flex gap-3"><input className="input-field flex-1 font-mono" value={id} onChange={e=>setId(e.target.value)} placeholder={`Paste the ${type==="vulnerability"?"scan":type} ID`}/>
            <button onClick={gen} disabled={!id||busy} className="px-5 py-2.5 rounded-xl text-sm font-semibold flex items-center gap-2 btn-primary">
              {busy?<Loader2 size={14} className="animate-spin"/>:<FileText size={14}/>}Generate</button></div></div>
        {err&&<div className="text-[12px] text-red-600 bg-red-50 border border-red-200 rounded-xl px-4 py-2.5 flex items-center gap-2"><XCircle size={14}/>{err}</div>}
      </div>
      {list.length>0&&<div className="space-y-2">{list.map((r,i)=>(
        <div key={i} className="card fade-in flex items-center justify-between p-4">
          <div className="flex items-center gap-3"><div className="w-9 h-9 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center"><FileText size={16} className="text-blue-600"/></div>
            <div><p className="text-[13px] text-gray-800 font-mono font-medium">{r.filename}</p><p className="text-[10px] text-gray-400 capitalize">{r.report_type} · {new Date(r.at).toLocaleString()}</p></div></div>
          <a href={reports.downloadUrl(r.filename)} target="_blank" rel="noreferrer" className="w-8 h-8 rounded-lg bg-gray-50 border border-gray-200 flex items-center justify-center text-gray-400 hover:text-blue-600 hover:border-blue-200 hover:bg-blue-50 transition-all"><Download size={14}/></a>
        </div>))}</div>}
    </div>);
}

/* ═══ APP SHELL ═════════════════════════════════════════════ */
export default function App(){
  const [logged,setLogged]=useState(false);
  const [tab,setTab]=useState("dashboard");const [sidebar,setSidebar]=useState(false);
  const [searchOpen,setSearchOpen]=useState(false);const [searchQ,setSearchQ]=useState("");
  const [settingsOpen,setSettingsOpen]=useState(false);const settingsRef=useRef(null);
  useEffect(()=>{const h=(e)=>{if(settingsRef.current&&!settingsRef.current.contains(e.target))setSettingsOpen(false);};
    document.addEventListener("mousedown",h);return()=>document.removeEventListener("mousedown",h);},[]);
  if(!logged)return<LoginScreen onLogin={()=>setLogged(true)}/>;
  const nav=[{id:"dashboard",label:"Overview",icon:LayoutDashboard},{id:"attack",label:"Attack Simulation",icon:Target},
    {id:"forensics",label:"Digital Forensics",icon:Fingerprint},{id:"rca",label:"Root Cause Analysis",icon:GitBranch},{id:"reports",label:"Reports",icon:FileText}];
  const titles={dashboard:"Security Operations Center",attack:"Attack Simulation",forensics:"Digital Forensics",rca:"Root Cause Analysis",reports:"Reports"};
  const user=auth.getUser();

  return(
    <div className="min-h-screen flex bg-[#F4F7FC]">
      {sidebar&&<div className="fixed inset-0 bg-black/20 z-30 lg:hidden" onClick={()=>setSidebar(false)}/>}

      {/* SIDEBAR */}
      <aside className={`fixed lg:static inset-y-0 left-0 z-40 w-[240px] bg-white border-r border-gray-200 flex flex-col transition-transform lg:translate-x-0 shadow-sm ${sidebar?"translate-x-0":"-translate-x-full"}`}>
        <div className="p-5 border-b border-gray-100"><div className="flex items-center gap-3"><Logo size={32}/>
          <div><h1 className="text-[13px] font-bold text-gray-900 tracking-tight">CyberSec Suite</h1>
            <p className="text-[9px] text-blue-500 uppercase tracking-[0.2em] font-semibold">AI-Powered SOC</p></div></div></div>
        <nav className="flex-1 p-3 space-y-0.5 mt-1">{nav.map(item=>(
          <button key={item.id} onClick={()=>{setTab(item.id);setSidebar(false);}}
            className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-[13px] font-medium transition-all ${
              tab===item.id?"bg-blue-50 text-blue-700 border border-blue-200 shadow-sm":"text-gray-500 hover:text-gray-700 hover:bg-gray-50 border border-transparent"
            }`}><item.icon size={16}/>{item.label}</button>
        ))}</nav>
        <div className="p-3 border-t border-gray-100"><button onClick={()=>{auth.logout();setLogged(false);}}
          className="w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-[13px] text-gray-400 hover:text-red-600 hover:bg-red-50 transition-all"><LogIn size={15}/>Sign Out</button></div>
      </aside>

      {/* MAIN */}
      <main className="flex-1 min-w-0">
        <header className="sticky top-0 z-20 bg-white/80 backdrop-blur-lg border-b border-gray-200 px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button onClick={()=>setSidebar(true)} className="lg:hidden p-2 rounded-xl hover:bg-gray-100 text-gray-500"><Menu size={18}/></button>
            <h2 className="text-[15px] font-semibold text-gray-900">{titles[tab]}</h2></div>
          <div className="flex items-center gap-4">
            <div className="hidden md:flex items-center gap-2 relative">
              {searchOpen?(
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-white border border-blue-300 shadow-sm">
                  <Search size={13} className="text-blue-500"/>
                  <input autoFocus value={searchQ} onChange={e=>setSearchQ(e.target.value)}
                    onKeyDown={e=>{if(e.key==="Escape"){setSearchOpen(false);setSearchQ("");}
                      if(e.key==="Enter"&&searchQ.trim()){const q=searchQ.toLowerCase();
                        if(q.includes("scan")||q.includes("attack"))setTab("attack");
                        else if(q.includes("forensic")||q.includes("log")||q.includes("yara"))setTab("forensics");
                        else if(q.includes("rca")||q.includes("incident")||q.includes("root"))setTab("rca");
                        else if(q.includes("report")||q.includes("pdf"))setTab("reports");
                        setSearchOpen(false);setSearchQ("");}}}
                    placeholder="Search threats, assets, users..." className="text-[12px] text-gray-800 bg-transparent outline-none w-48 placeholder:text-gray-400"/>
                  <button onClick={()=>{setSearchOpen(false);setSearchQ("");}} className="text-gray-400 hover:text-gray-600"><X size={13}/></button>
                </div>
              ):(
                <button onClick={()=>setSearchOpen(true)} className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-gray-50 border border-gray-200 hover:bg-gray-100 transition-colors">
                  <Search size={13} className="text-gray-400"/><span className="text-[11px] text-gray-400">Search threats, assets, users...</span></button>
              )}
            </div>
            <LiveClock/>
            <button className="relative p-2 rounded-xl hover:bg-gray-100 text-gray-500 transition-colors"><Bell size={17}/>
              <span className="absolute -top-0.5 -right-0.5 w-4 h-4 bg-red-500 rounded-full text-[9px] text-white flex items-center justify-center font-bold border-2 border-white">3</span></button>
            <div className="flex items-center gap-2 pl-3 border-l border-gray-200">
              <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-blue-600 to-cyan-500 flex items-center justify-center text-white text-[11px] font-bold shadow-sm">
                {(user?.role||"A").charAt(0).toUpperCase()}</div>
              <div className="hidden sm:block"><div className="text-[12px] font-semibold text-gray-800">Admin</div><div className="text-[10px] text-gray-400">Analyst</div></div></div>
            <div className="relative" ref={settingsRef}>
              <button onClick={()=>setSettingsOpen(!settingsOpen)} className={`p-2 rounded-xl transition-colors ${settingsOpen?"bg-gray-100 text-gray-700":"text-gray-400 hover:bg-gray-100 hover:text-gray-600"}`}><Settings size={16}/></button>
              {settingsOpen&&(
                <div className="absolute right-0 top-full mt-2 w-56 bg-white rounded-xl border border-gray-200 shadow-lg py-2 z-50 fade-in">
                  <div className="px-4 py-3 border-b border-gray-100">
                    <div className="text-[13px] font-semibold text-gray-800">{user?.username||"Admin"}</div>
                    <div className="text-[11px] text-gray-400">{user?.email||"Security Analyst"}</div>
                  </div>
                  <button onClick={()=>{setTab("dashboard");setSettingsOpen(false);}} className="w-full text-left px-4 py-2.5 text-[12px] text-gray-600 hover:bg-gray-50 flex items-center gap-2"><LayoutDashboard size={14}/>Dashboard</button>
                  <button onClick={()=>setSettingsOpen(false)} className="w-full text-left px-4 py-2.5 text-[12px] text-gray-600 hover:bg-gray-50 flex items-center gap-2"><User size={14}/>Profile</button>
                  <button onClick={()=>setSettingsOpen(false)} className="w-full text-left px-4 py-2.5 text-[12px] text-gray-600 hover:bg-gray-50 flex items-center gap-2"><Bell size={14}/>Notifications</button>
                  <div className="border-t border-gray-100 mt-1 pt-1">
                    <button onClick={()=>{auth.logout();setLogged(false);}} className="w-full text-left px-4 py-2.5 text-[12px] text-red-500 hover:bg-red-50 flex items-center gap-2"><LogIn size={14}/>Sign Out</button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </header>
        <div className="p-6 max-w-[1400px] mx-auto">
          {tab==="dashboard"&&<DashboardView setActiveTab={setTab}/>}
          {tab==="attack"&&<AttackView/>}
          {tab==="forensics"&&<ForensicsView/>}
          {tab==="rca"&&<RCAView/>}
          {tab==="reports"&&<ReportsView/>}
        </div>
      </main>
    </div>
  );
}
