import { useEffect, useRef, useState, useCallback } from 'react';
import {
  Shield,
  Menu,
  X,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Copy,
  MessageCircle,
  ChevronDown,
  ChevronUp,
  Trash2,
  Briefcase,
  Trophy,
  Package,
  ClipboardList,
} from 'lucide-react';

// ─── Types ───────────────────────────────────────────────────────────────────

interface ScanRecord {
  id: string;
  snippet: string;
  score: number;
  level: 'HIGH RISK' | 'SUSPICIOUS' | 'SAFE';
  timestamp: number;
}

interface AnalysisResult {
  score: number;
  level: 'HIGH RISK' | 'SUSPICIOUS' | 'SAFE';
  bullets: string[];
  highKeywords: string[];
  suspiciousKeywords: string[];
  safeKeywords: string[];
}

// ─── Scoring Logic ────────────────────────────────────────────────────────────

// ─── Scoring Engine (spec-exact, case-insensitive) ───────────────────────────

const HIGH_RISK_KW: string[] = [
  'urgent', 'won', 'prize', 'otp', 'kyc', 'bank account', 'password',
  'claim', 'verify', 'free money', 'aadhaar', 'aadhar', 'bitcoin',
  'arrest warrant', 'advance fee',
  // extended high-risk
  'lottery', 'lucky draw', 'winner', 'claim now', 'account suspended',
  'account blocked', 'upi pin', 'cvv', 'net banking', 'pan card',
  'police case', 'court notice', 'legal action', 'income tax notice',
  'warrant', 'immediately', 'expires today', 'act now', 'final warning',
  'click here', 'login now', 'verify your account', 'bit.ly', 'tinyurl',
];

const SUSPICIOUS_KW: string[] = [
  'job offer', 'whatsapp', 'telegram', 'earn daily', 'guaranteed',
  'work from home', 'no experience', 'registration fee', 'per day',
  // extended suspicious
  'part time', 'online job', 'earn weekly', 'data entry', 'typing job',
  'double money', 'high returns', 'risk free', 'profit daily', 'crypto',
  'forex', 'instant loan', 'pre-approved', 'refer and earn', 'spin and win',
];

const SAFE_KW: string[] = [
  '.gov.in', 'upsc', 'linkedin.com', 'internshala', 'official', 'naukri.com',
  '.nic.in', '.edu.in', 'uidai.gov.in', 'incometax.gov.in',
];

const FAKE_BRAND_PATTERNS = [
  'sbi-kyc', 'paytm-offer', 'amaz0n', 'yono-sbi',
  'sbi-update', 'hdfc-kyc', 'icici-kyc', 'paytm-kyc',
  'amazon-refund', 'flipkart-offer', 'google-prize',
];

const URL_REGEX = /https?:\/\/\S+|www\.\S+/gi;
const PHONE_REGEX = /(\+91[\s-]?)?[6-9]\d{9}/g;
const CAPS_REGEX = /\b[A-Z]{2,}\b/g;
const EXCLAIM_REGEX = /!/g;
const MONEY_REGEX = /₹|lakh|crore|lakhs|crores/gi;

function analyzeText(text: string): AnalysisResult {
  const lower = text.toLowerCase();
  let score = 0;
  const foundHigh: string[] = [];
  const foundSuspicious: string[] = [];
  const foundSafe: string[] = [];
  const reasons: string[] = [];

  // HIGH RISK +3 each
  HIGH_RISK_KW.forEach((kw) => {
    if (lower.includes(kw.toLowerCase())) {
      score += 3;
      if (!foundHigh.includes(kw)) foundHigh.push(kw);
    }
  });

  // SUSPICIOUS +2 each
  SUSPICIOUS_KW.forEach((kw) => {
    if (lower.includes(kw.toLowerCase())) {
      score += 2;
      if (!foundSuspicious.includes(kw)) foundSuspicious.push(kw);
    }
  });

  // SAFE -2 each
  SAFE_KW.forEach((kw) => {
    if (lower.includes(kw.toLowerCase())) {
      score -= 2;
      if (!foundSafe.includes(kw)) foundSafe.push(kw);
    }
  });

  // AUTO +3: fake brand URLs
  const hasFakeBrand = FAKE_BRAND_PATTERNS.some(p => lower.includes(p));
  if (hasFakeBrand) {
    score += 3;
    reasons.push('Fake brand URL detected (e.g. sbi-kyc, amaz0n, paytm-offer) — classic phishing domain impersonating a trusted brand.');
  }

  // AUTO +2: real URL found
  const urlMatches = text.match(URL_REGEX);
  if (urlMatches && !hasFakeBrand) {
    score += 2;
    reasons.push(`Suspicious URL found: "${urlMatches[0].slice(0, 40)}" — always verify links before clicking.`);
  }

  // AUTO +2: ALL CAPS 3+ words
  const capsWords = text.match(CAPS_REGEX) || [];
  if (capsWords.length >= 3) {
    score += 2;
    reasons.push(`${capsWords.length} ALL-CAPS words detected — a common pressure tactic used in scam messages.`);
  }

  // AUTO +2: 3+ exclamation marks
  const exclaimCount = (text.match(EXCLAIM_REGEX) || []).length;
  if (exclaimCount >= 3) {
    score += 2;
    reasons.push(`${exclaimCount} exclamation marks found — excessive urgency is a hallmark of scam messages.`);
  }

  // AUTO +2: phone number
  if (PHONE_REGEX.test(text)) {
    score += 2;
    reasons.push('Phone number detected — scammers often embed contact numbers to lure victims into calling.');
  }

  // AUTO +2: ₹ / lakh / crore
  if (MONEY_REGEX.test(text)) {
    score += 2;
    reasons.push('Money-related terms (₹/lakh/crore) detected — financial bait is a primary scam trigger.');
  }

  // Clamp score 0–10
  score = Math.max(0, Math.min(10, score));

  // Thresholds: 6+ = HIGH RISK, 3–5 = SUSPICIOUS, 0–2 = SAFE
  const level: AnalysisResult['level'] =
    score >= 6 ? 'HIGH RISK' : score >= 3 ? 'SUSPICIOUS' : 'SAFE';

  // Build 3 bullet reasons
  const bullets: string[] = [];

  if (foundHigh.length > 0) {
    bullets.push(`High-risk keywords detected: ${foundHigh.slice(0, 3).map(k => `"${k}"`).join(', ')} — hallmarks of phishing, KYC fraud, or lottery scams.`);
  }
  if (foundSuspicious.length > 0) {
    bullets.push(`Suspicious terms found: ${foundSuspicious.slice(0, 3).map(k => `"${k}"`).join(', ')} — commonly used in fake job offers or investment fraud.`);
  }
  if (foundSafe.length > 0) {
    bullets.push(`Trusted indicators present: ${foundSafe.slice(0, 2).map(k => `"${k}"`).join(', ')} — reduces overall risk score.`);
  }

  // Fill from auto-detected reasons
  for (const r of reasons) {
    if (bullets.length >= 3) break;
    bullets.push(r);
  }

  // Fallback bullets
  if (bullets.length === 0) {
    if (level === 'SAFE') {
      bullets.push('No known scam keywords or patterns detected in this message.');
    } else {
      bullets.push('The message contains patterns commonly associated with fraudulent intent.');
    }
  }
  while (bullets.length < 3) {
    if (level === 'HIGH RISK') {
      const extras = [
        'Never share OTPs, passwords, or bank details with anyone — no legitimate organisation asks for these.',
        'Report this message immediately at cybercrime.gov.in or call 1930.',
      ];
      bullets.push(extras[bullets.length - 1] ?? extras[0]);
    } else if (level === 'SUSPICIOUS') {
      const extras = [
        'Verify the sender through official channels before responding or clicking any link.',
        'Do not pay any registration fee or advance amount to unknown parties.',
      ];
      bullets.push(extras[bullets.length - 1] ?? extras[0]);
    } else {
      const extras = [
        'Always double-check unexpected messages even if they appear legitimate.',
        'Stay alert — scammers constantly evolve their tactics to bypass detection.',
      ];
      bullets.push(extras[bullets.length - 1] ?? extras[0]);
    }
  }

  return {
    score,
    level,
    bullets: bullets.slice(0, 3),
    highKeywords: foundHigh,
    suspiciousKeywords: foundSuspicious,
    safeKeywords: foundSafe,
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function timeAgo(ts: number): string {
  const diff = Date.now() - ts;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function loadHistory(): ScanRecord[] {
  try {
    return JSON.parse(localStorage.getItem('rakshak_history') || '[]');
  } catch { return []; }
}

function saveHistory(records: ScanRecord[]) {
  localStorage.setItem('rakshak_history', JSON.stringify(records.slice(0, 5)));
}

// ─── Counter Hook ─────────────────────────────────────────────────────────────

function useCountUp(target: number, active: boolean, duration = 2000) {
  const [value, setValue] = useState(0);
  useEffect(() => {
    if (!active) return;
    let start: number | null = null;
    const step = (ts: number) => {
      if (!start) start = ts;
      const progress = Math.min((ts - start) / duration, 1);
      setValue(Math.floor(progress * target));
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [active, target, duration]);
  return value;
}

// ─── Stat Card ────────────────────────────────────────────────────────────────

function StatCard({ label, target, suffix, active }: { label: string; target: number; suffix: string; active: boolean }) {
  const val = useCountUp(target, active);
  return (
    <div style={{ background: '#112236', border: '1px solid #1E3A5F' }}
      className="rounded-xl p-6 text-center flex flex-col gap-1">
      <div className="text-3xl font-bold" style={{ color: '#00B4FF', fontFamily: 'var(--font-heading)' }}>
        {val.toLocaleString()}{suffix}
      </div>
      <div className="text-sm" style={{ color: '#8BA3BE' }}>{label}</div>
    </div>
  );
}

// ─── Risk Meter ───────────────────────────────────────────────────────────────

function RiskMeter({ score, animate }: { score: number; animate: boolean }) {
  const pct = (score / 10) * 100;
  return (
    <div className="w-full">
      <div className="flex justify-between text-xs mb-1" style={{ color: '#8BA3BE' }}>
        <span>0 — Safe</span>
        <span>Risk Score: {score}/10</span>
        <span>10 — Critical</span>
      </div>
      <div className="w-full h-4 rounded-full overflow-hidden" style={{ background: '#1E3A5F' }}>
        <div
          className="h-full rounded-full transition-all"
          style={{
            width: animate ? `${pct}%` : '0%',
            transitionDuration: '1s',
            transitionTimingFunction: 'ease-out',
            background: 'linear-gradient(to right, #22C55E, #F59E0B, #FF4C4C)',
          }}
        />
      </div>
    </div>
  );
}

// ─── Scam Card ────────────────────────────────────────────────────────────────

const SCAM_CARDS = [
  {
    icon: Shield,
    color: '#00B4FF',
    title: 'KYC Fraud',
    desc: 'Fraudsters pose as bank officials demanding urgent KYC updates via SMS or WhatsApp, tricking victims into sharing Aadhaar, PAN, or OTPs to "prevent account suspension".',
    flags: ['Asks for OTP or Aadhaar number', 'Claims account will be blocked', 'Sends unofficial links'],
  },
  {
    icon: Briefcase,
    color: '#F59E0B',
    title: 'Job Scams',
    desc: 'Fake job offers promise high salaries for simple work-from-home tasks. Victims are asked to pay a "registration fee" or "security deposit" that is never returned.',
    flags: ['Upfront payment required', 'No interview process', 'Unrealistic salary promises'],
  },
  {
    icon: Trophy,
    color: '#22C55E',
    title: 'Lottery Scams',
    desc: 'You receive a message claiming you\'ve won a lottery or prize you never entered. To claim it, you must pay "processing fees" or share bank details.',
    flags: ['You "won" without entering', 'Asks for processing fee', 'Creates urgency to claim'],
  },
  {
    icon: Package,
    color: '#FF4C4C',
    title: 'Customs Scams',
    desc: 'Scammers call pretending to be customs or courier officials, claiming a parcel in your name contains illegal items. They demand payment to "settle" the case.',
    flags: ['Unexpected parcel notification', 'Threatens legal action', 'Demands immediate payment'],
  },
];

function ScamCard({ card, visible, delay }: { card: typeof SCAM_CARDS[0]; visible: boolean; delay: number }) {
  const Icon = card.icon;
  const [hovered, setHovered] = useState(false);
  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      className="rounded-xl p-6 flex flex-col gap-3 h-full"
      style={{
        background: hovered ? `linear-gradient(135deg, ${card.color}12, #112236)` : '#112236',
        border: `1px solid ${hovered ? card.color + '55' : '#1E3A5F'}`,
        boxShadow: hovered ? `0 0 32px ${card.color}22, 0 8px 24px rgba(0,0,0,0.3)` : '0 2px 8px rgba(0,0,0,0.2)',
        opacity: visible ? 1 : 0,
        transform: visible ? 'translateY(0) scale(1)' : 'translateY(36px) scale(0.94)',
        transition: `opacity 0.6s ease ${delay}ms, transform 0.6s ease ${delay}ms, border 0.3s ease, box-shadow 0.3s ease, background 0.3s ease`,
      }}
    >
      <div className="flex items-center gap-3">
        <div className="p-2.5 rounded-xl transition-all duration-300"
          style={{
            background: hovered ? card.color + '33' : card.color + '18',
            boxShadow: hovered ? `0 0 16px ${card.color}44` : 'none',
          }}>
          <Icon size={22} style={{ color: card.color }} />
        </div>
        <h3 className="font-bold text-lg" style={{ fontFamily: 'var(--font-heading)', color: '#F5F5F5' }}>{card.title}</h3>
      </div>
      <p className="text-sm leading-relaxed" style={{ color: '#8BA3BE' }}>{card.desc}</p>
      <div>
        <p className="text-xs font-semibold mb-2" style={{ color: card.color }}>Red flags:</p>
        <ul className="flex flex-col gap-1.5">
          {card.flags.map((f, fi) => (
            <li key={f} className="flex items-start gap-2 text-xs"
              style={{
                color: '#8BA3BE',
                opacity: visible ? 1 : 0,
                transform: visible ? 'translateX(0)' : 'translateX(-12px)',
                transition: `opacity 0.5s ease ${delay + 200 + fi * 80}ms, transform 0.5s ease ${delay + 200 + fi * 80}ms`,
              }}>
              <span className="mt-0.5 shrink-0" style={{ color: card.color }}>▸</span> {f}
            </li>
          ))}
        </ul>
      </div>
      {/* Bottom accent */}
      <div className="h-px rounded-full mt-1" style={{
        background: `linear-gradient(to right, ${card.color}, transparent)`,
        width: hovered ? '100%' : '40%',
        transition: 'width 0.4s ease',
      }} />
    </div>
  );
}

// ─── Toast ────────────────────────────────────────────────────────────────────

function Toast({ message, visible }: { message: string; visible: boolean }) {
  return (
    <div
      className="fixed bottom-6 right-6 z-50 px-5 py-3 rounded-xl text-sm font-medium shadow-lg transition-all duration-300"
      style={{
        background: '#22C55E',
        color: '#fff',
        opacity: visible ? 1 : 0,
        transform: visible ? 'translateY(0)' : 'translateY(16px)',
        pointerEvents: 'none',
      }}
    >
      {message}
    </div>
  );
}

// ─── How It Works (animated) ─────────────────────────────────────────────────

const HOW_STEPS = [
  {
    step: '01',
    title: 'Paste Message',
    desc: 'Copy any suspicious SMS, WhatsApp message, email, or link and paste it into the analyzer.',
    icon: '📋',
    color: '#00B4FF',
  },
  {
    step: '02',
    title: 'AI Analysis',
    desc: 'Rakshak AI scans for hundreds of known scam patterns, keywords, and red flags used by fraudsters.',
    icon: '🔍',
    color: '#7C3AED',
  },
  {
    step: '03',
    title: 'Get Results',
    desc: 'Receive an instant risk score, detailed explanation, and actionable steps to protect yourself.',
    icon: '🛡️',
    color: '#22C55E',
  },
];

function HowStepCard({ item, index, visible }: { item: typeof HOW_STEPS[0]; index: number; visible: boolean }) {
  const [hovered, setHovered] = useState(false);
  const [tilt, setTilt] = useState({ x: 0, y: 0 });
  const cardRef = useRef<HTMLDivElement>(null);

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const rect = cardRef.current?.getBoundingClientRect();
    if (!rect) return;
    const x = ((e.clientY - rect.top) / rect.height - 0.5) * 28;
    const y = -((e.clientX - rect.left) / rect.width - 0.5) * 28;
    setTilt({ x, y });
  };

  const handleMouseLeave = () => {
    setHovered(false);
    setTilt({ x: 0, y: 0 });
  };

  return (
    <div
      ref={cardRef}
      className="flex-1 flex flex-col items-center text-center gap-4 relative z-10 cursor-pointer"
      onMouseEnter={() => setHovered(true)}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      style={{
        opacity: visible ? 1 : 0,
        transform: visible
          ? hovered
            ? `translateY(-12px) scale(1.04) perspective(600px) rotateX(${tilt.x}deg) rotateY(${tilt.y}deg)`
            : 'translateY(0) scale(1) perspective(600px) rotateX(0deg) rotateY(0deg)'
          : 'translateY(40px) scale(0.92)',
        transition: visible
          ? 'transform 0.15s ease, opacity 0.6s ease'
          : `opacity 0.6s ease ${index * 180}ms, transform 0.6s ease ${index * 180}ms`,
        willChange: 'transform',
      }}
    >
      {/* Glowing icon box */}
      <div
        style={{
          width: 80, height: 80,
          borderRadius: 18,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 2,
          background: hovered
            ? `linear-gradient(135deg, ${item.color}40, ${item.color}18)`
            : `linear-gradient(135deg, ${item.color}22, ${item.color}08)`,
          border: `2px solid ${hovered ? item.color + 'cc' : item.color + '55'}`,
          boxShadow: hovered
            ? `0 0 40px ${item.color}66, 0 0 80px ${item.color}22, inset 0 0 20px ${item.color}11`
            : `0 0 20px ${item.color}22`,
          transition: 'all 0.3s ease',
        }}
      >
        <span style={{ fontSize: 30, filter: hovered ? `drop-shadow(0 0 8px ${item.color})` : 'none', transition: 'filter 0.3s ease' }}>{item.icon}</span>
        <span style={{ fontSize: 11, fontWeight: 700, color: item.color, fontFamily: 'var(--font-heading)', letterSpacing: '0.06em' }}>{item.step}</span>
      </div>

      {/* Card body */}
      <div
        className="w-full rounded-2xl p-6 flex flex-col gap-3"
        style={{
          background: hovered ? `linear-gradient(135deg, ${item.color}10, rgba(17,34,54,0.95))` : 'rgba(17,34,54,0.85)',
          border: `1px solid ${hovered ? item.color + '66' : item.color + '28'}`,
          backdropFilter: 'blur(16px)',
          boxShadow: hovered
            ? `0 20px 60px ${item.color}22, 0 0 0 1px ${item.color}22`
            : '0 4px 20px rgba(0,0,0,0.3)',
          transition: 'all 0.3s ease',
        }}
      >
        <h3 className="font-bold text-lg" style={{ fontFamily: 'var(--font-heading)', color: hovered ? '#fff' : '#F5F5F5', transition: 'color 0.2s' }}>{item.title}</h3>
        <p className="text-sm leading-relaxed" style={{ color: hovered ? '#b0cce0' : '#8BA3BE', transition: 'color 0.2s' }}>{item.desc}</p>

        {/* Animated bottom bar */}
        <div style={{
          height: 2,
          borderRadius: 2,
          background: `linear-gradient(to right, ${item.color}, ${item.color}44, transparent)`,
          width: hovered ? '100%' : visible ? '45%' : '0%',
          transition: hovered ? 'width 0.4s ease' : 'width 0.8s ease 0.5s',
          marginTop: 4,
        }} />
      </div>
    </div>
  );
}

function HowItWorks() {
  const refs = useRef<(HTMLDivElement | null)[]>([]);
  const [visible, setVisible] = useState([false, false, false]);
  const titleRef = useRef<HTMLDivElement>(null);
  const [titleVisible, setTitleVisible] = useState(false);

  useEffect(() => {
    const obs = new IntersectionObserver(([e]) => { if (e.isIntersecting) setTitleVisible(true); }, { threshold: 0.2 });
    if (titleRef.current) obs.observe(titleRef.current);
    return () => obs.disconnect();
  }, []);

  useEffect(() => {
    const observers: IntersectionObserver[] = [];
    refs.current.forEach((el, i) => {
      if (!el) return;
      const obs = new IntersectionObserver(([e]) => {
        if (e.isIntersecting) {
          setTimeout(() => setVisible(prev => { const n = [...prev]; n[i] = true; return n; }), i * 180);
        }
      }, { threshold: 0.15 });
      obs.observe(el);
      observers.push(obs);
    });
    return () => observers.forEach(o => o.disconnect());
  }, []);

  return (
    <section id="how-it-works" className="max-w-6xl mx-auto px-4 py-20">
      {/* Title */}
      <div ref={titleRef} style={{ transition: 'opacity 0.7s ease, transform 0.7s ease', opacity: titleVisible ? 1 : 0, transform: titleVisible ? 'translateY(0)' : 'translateY(24px)' }}>
        <h2 className="text-3xl font-bold text-center mb-3" style={{ fontFamily: 'var(--font-heading)', color: '#F5F5F5' }}>
          How It{' '}
          <span style={{ background: 'linear-gradient(135deg,#00B4FF,#7C3AED)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>Works</span>
        </h2>
        <p className="text-center text-sm mb-14" style={{ color: '#8BA3BE' }}>Three simple steps to stay safe online</p>
      </div>

      {/* Steps */}
      <div className="flex flex-col md:flex-row items-stretch gap-6 md:gap-6 relative">
        {/* Connector line desktop */}
        <div className="hidden md:block absolute top-10 left-[calc(16.66%+40px)] right-[calc(16.66%+40px)] h-px"
          style={{ background: 'linear-gradient(to right,#00B4FF44,#7C3AED44,#22C55E44)', zIndex: 0 }} />

        {HOW_STEPS.map((item, i) => (
          <div key={i} ref={el => { refs.current[i] = el; }} className="flex-1">
            <HowStepCard item={item} index={i} visible={visible[i]} />
          </div>
        ))}
      </div>
    </section>
  );
}

// ─── Quiz Data ────────────────────────────────────────────────────────────────

const QUIZ_QUESTIONS = [
  { msg: '"Congratulations! You have WON ₹50,000 in the KBC Lottery! Click here to claim: bit.ly/kbc-prize"', answer: 'scam', explanation: 'Lottery scams use urgency + fake prize money + shortened URLs to steal your details.' },
  { msg: '"Your SBI account KYC is expired. Update immediately at sbi-kyc-update.com or your account will be blocked."', answer: 'scam', explanation: 'Banks NEVER ask you to update KYC via unofficial links. This is a phishing site.' },
  { msg: '"UPSC Civil Services 2026 notification released. Apply at upsc.gov.in before May 15."', answer: 'legit', explanation: 'Official .gov.in domain, no urgency tactics, no personal info requested — this is legitimate.' },
  { msg: '"Work from home! Earn ₹5,000/day. No experience needed. Pay ₹500 registration fee on WhatsApp."', answer: 'scam', explanation: 'Asking for a registration fee upfront is a classic job scam red flag.' },
  { msg: '"Your Aadhaar-linked mobile number will be deactivated in 24 hours. Call 9876543210 to verify."', answer: 'scam', explanation: 'UIDAI never calls or texts asking you to verify Aadhaar via phone. This is impersonation fraud.' },
  { msg: '"Internshala Summer Internship Fair 2026 — Register free at internshala.com/fair"', answer: 'legit', explanation: 'Internshala is a trusted platform. Official domain, free registration, no red flags.' },
  { msg: '"URGENT: Your Paytm wallet is suspended. Send OTP to 8800XXXXXX to reactivate immediately!!!"', answer: 'scam', explanation: 'Multiple exclamation marks, urgency, OTP request — textbook phishing attempt.' },
  { msg: '"Income Tax Refund of ₹18,420 approved. Submit bank details at incometax.gov.in to receive."', answer: 'legit', explanation: 'Official incometax.gov.in domain. However, always verify refunds by logging in directly — never via SMS links.' },
  { msg: '"Earn ₹2,000 daily by liking YouTube videos. Join our Telegram group: t.me/earnfast2026"', answer: 'scam', explanation: 'Task-based earning scams on Telegram are among the most common frauds targeting Indian youth.' },
  { msg: '"Dear customer, your Amazon order #402-XXXXX has been shipped. Track at amazon.in/track"', answer: 'legit', explanation: 'Official amazon.in domain, no urgency, no personal info requested — this is a legitimate notification.' },
];

// ─── Confetti Particle ────────────────────────────────────────────────────────

function ConfettiParticle({ color, x }: { color: string; x: number }) {
  return (
    <div style={{
      position: 'absolute',
      top: 0,
      left: `${x}%`,
      width: 8,
      height: 8,
      borderRadius: 2,
      background: color,
      animation: 'confettiFall 0.9s ease-out forwards',
      pointerEvents: 'none',
    }} />
  );
}

// ─── Quiz Modal ───────────────────────────────────────────────────────────────

function QuizModal({ open, onClose, onEarnToken }: { open: boolean; onClose: () => void; onEarnToken: () => void }) {
  const [qIndex, setQIndex] = useState(0);
  const [score, setScore] = useState(0);
  const [answered, setAnswered] = useState<'correct' | 'wrong' | null>(null);
  const [shake, setShake] = useState(false);
  const [confetti, setConfetti] = useState<{ id: number; color: string; x: number }[]>([]);
  const [done, setDone] = useState(false);
  const [tokensEarned, setTokensEarned] = useState(0);

  const reset = () => { setQIndex(0); setScore(0); setAnswered(null); setShake(false); setConfetti([]); setDone(false); setTokensEarned(0); };

  const handleAnswer = (choice: 'scam' | 'legit') => {
    if (answered) return;
    const correct = choice === QUIZ_QUESTIONS[qIndex].answer;
    if (correct) {
      setAnswered('correct');
      setScore(s => s + 1);
      setTokensEarned(t => t + 1);
      onEarnToken();
      // Confetti burst
      const pieces = Array.from({ length: 18 }, (_, i) => ({
        id: Date.now() + i,
        color: ['#00B4FF', '#7C3AED', '#22C55E', '#F59E0B', '#FF4C4C'][i % 5],
        x: Math.random() * 100,
      }));
      setConfetti(pieces);
      setTimeout(() => setConfetti([]), 1000);
    } else {
      setAnswered('wrong');
      setShake(true);
      setTimeout(() => setShake(false), 500);
    }
    setTimeout(() => {
      setAnswered(null);
      if (qIndex + 1 >= QUIZ_QUESTIONS.length) { setDone(true); }
      else { setQIndex(i => i + 1); }
    }, 1800);
  };

  const stars = score >= 9 ? 3 : score >= 6 ? 2 : score >= 3 ? 1 : 0;

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(4,8,16,0.85)', backdropFilter: 'blur(8px)' }}
      onClick={(e) => { if (e.target === e.currentTarget) { onClose(); reset(); } }}
    >
      <style>{`
        @keyframes confettiFall { 0%{transform:translateY(-10px) rotate(0deg);opacity:1} 100%{transform:translateY(80px) rotate(720deg);opacity:0} }
        @keyframes quizShake { 0%,100%{transform:translateX(0)} 20%{transform:translateX(-10px)} 40%{transform:translateX(10px)} 60%{transform:translateX(-8px)} 80%{transform:translateX(8px)} }
        @keyframes quizIn { from{opacity:0;transform:scale(0.92) translateY(24px)} to{opacity:1;transform:scale(1) translateY(0)} }
        @keyframes starPop { 0%{transform:scale(0) rotate(-20deg);opacity:0} 70%{transform:scale(1.3) rotate(5deg);opacity:1} 100%{transform:scale(1) rotate(0deg);opacity:1} }
      `}</style>

      <div
        className="relative w-full max-w-lg rounded-2xl p-6 flex flex-col gap-5 overflow-hidden"
        style={{
          background: 'rgba(8,16,30,0.97)',
          border: '1px solid rgba(0,180,255,0.2)',
          boxShadow: '0 0 60px rgba(0,180,255,0.15), 0 24px 64px rgba(0,0,0,0.6)',
          animation: shake ? 'quizShake 0.4s ease-out' : 'quizIn 0.4s cubic-bezier(0.34,1.56,0.64,1) both',
        }}
      >
        {/* Confetti */}
        {confetti.map(p => <ConfettiParticle key={p.id} color={p.color} x={p.x} />)}

        {/* Close */}
        <button onClick={() => { onClose(); reset(); }} style={{ position: 'absolute', top: 14, right: 14, background: 'none', border: 'none', color: '#4A6A85', cursor: 'pointer', fontSize: 20, lineHeight: 1 }}>✕</button>

        {!done ? (
          <>
            {/* Header */}
            <div className="flex items-center justify-between">
              <div>
                <h3 className="font-bold text-lg" style={{ fontFamily: 'var(--font-heading)', color: '#F0F6FF' }}>🧠 Scam or Legit?</h3>
                <p className="text-xs mt-0.5" style={{ color: '#4A6A85' }}>Earn 1 token per correct answer</p>
              </div>
              <div className="text-right">
                <span className="text-xs font-semibold" style={{ color: '#00B4FF' }}>Q {qIndex + 1} / {QUIZ_QUESTIONS.length}</span>
                <div className="text-xs mt-0.5" style={{ color: '#22C55E' }}>🪙 +{tokensEarned} earned</div>
              </div>
            </div>

            {/* Progress bar */}
            <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.06)' }}>
              <div style={{
                height: '100%',
                width: `${((qIndex) / QUIZ_QUESTIONS.length) * 100}%`,
                background: 'linear-gradient(90deg, #00B4FF, #7C3AED)',
                borderRadius: 999,
                transition: 'width 0.5s ease',
              }} />
            </div>

            {/* Message card */}
            <div className="rounded-xl p-4" style={{ background: 'rgba(0,180,255,0.05)', border: '1px solid rgba(0,180,255,0.12)' }}>
              <p className="text-sm leading-relaxed" style={{ color: '#C8E0F0', fontStyle: 'italic' }}>
                "{QUIZ_QUESTIONS[qIndex].msg}"
              </p>
            </div>

            {/* Feedback */}
            {answered && (
              <div className="rounded-xl p-3 text-sm" style={{
                background: answered === 'correct' ? 'rgba(34,197,94,0.1)' : 'rgba(255,76,76,0.1)',
                border: `1px solid ${answered === 'correct' ? 'rgba(34,197,94,0.3)' : 'rgba(255,76,76,0.3)'}`,
                color: answered === 'correct' ? '#22C55E' : '#FF4C4C',
              }}>
                {answered === 'correct' ? '✅ Correct! +1 token earned.' : '❌ Wrong!'}{' '}
                <span style={{ color: '#8BA3BE' }}>{QUIZ_QUESTIONS[qIndex].explanation}</span>
              </div>
            )}

            {/* Buttons */}
            <div className="grid grid-cols-2 gap-3">
              {(['scam', 'legit'] as const).map(choice => (
                <button
                  key={choice}
                  onClick={() => handleAnswer(choice)}
                  disabled={!!answered}
                  className="py-3 rounded-xl font-bold text-sm transition-all duration-200"
                  style={{
                    background: answered
                      ? choice === QUIZ_QUESTIONS[qIndex].answer
                        ? choice === 'scam' ? 'rgba(255,76,76,0.25)' : 'rgba(34,197,94,0.25)'
                        : 'rgba(255,255,255,0.04)'
                      : choice === 'scam'
                        ? 'rgba(255,76,76,0.12)'
                        : 'rgba(34,197,94,0.12)',
                    border: `1.5px solid ${choice === 'scam' ? 'rgba(255,76,76,0.4)' : 'rgba(34,197,94,0.4)'}`,
                    color: choice === 'scam' ? '#FF4C4C' : '#22C55E',
                    cursor: answered ? 'not-allowed' : 'pointer',
                    fontFamily: 'var(--font-heading)',
                    opacity: answered && choice !== QUIZ_QUESTIONS[qIndex].answer ? 0.4 : 1,
                    transform: answered && choice === QUIZ_QUESTIONS[qIndex].answer ? 'scale(1.03)' : 'scale(1)',
                  }}
                >
                  {choice === 'scam' ? '🚨 SCAM' : '✅ LEGIT'}
                </button>
              ))}
            </div>
          </>
        ) : (
          /* Results screen */
          <div className="flex flex-col items-center gap-5 py-4 text-center">
            <div className="text-5xl" style={{ animation: 'starPop 0.5s ease both' }}>
              {score >= 9 ? '🏆' : score >= 6 ? '🥈' : score >= 3 ? '🥉' : '😅'}
            </div>
            <div>
              <h3 className="font-bold text-2xl mb-1" style={{ fontFamily: 'var(--font-heading)', color: '#F0F6FF' }}>
                {score} / {QUIZ_QUESTIONS.length} Correct
              </h3>
              <p className="text-sm" style={{ color: '#7A9BB5' }}>
                {score >= 9 ? 'Scam Detector Pro! 🔥' : score >= 6 ? 'Good awareness! Keep learning.' : score >= 3 ? 'Stay alert — scammers are clever.' : 'Practice more to stay safe!'}
              </p>
            </div>
            {/* Stars */}
            <div className="flex gap-2">
              {[1, 2, 3].map(s => (
                <span key={s} style={{ fontSize: 32, opacity: s <= stars ? 1 : 0.2, animation: s <= stars ? `starPop 0.4s ease ${s * 0.15}s both` : 'none' }}>⭐</span>
              ))}
            </div>
            <div className="rounded-xl px-5 py-3" style={{ background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.25)' }}>
              <p className="text-sm font-semibold" style={{ color: '#22C55E' }}>🪙 +{tokensEarned} tokens added to your wallet!</p>
            </div>
            <div className="flex gap-3 w-full">
              <button onClick={() => { reset(); }} className="flex-1 py-3 rounded-xl font-bold text-sm" style={{ background: 'rgba(0,180,255,0.12)', border: '1px solid rgba(0,180,255,0.3)', color: '#00B4FF', cursor: 'pointer', fontFamily: 'var(--font-heading)' }}>
                🔄 Try Again
              </button>
              <button onClick={() => { onClose(); reset(); }} className="flex-1 py-3 rounded-xl font-bold text-sm" style={{ background: 'linear-gradient(135deg,#00B4FF,#7C3AED)', border: 'none', color: '#fff', cursor: 'pointer', fontFamily: 'var(--font-heading)' }}>
                ✅ Done
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Hero Analyze Button ──────────────────────────────────────────────────────

function HeroAnalyzeButton({ loading, onClick }: { loading: boolean; onClick: () => void }) {
  const [hovered, setHovered] = useState(false);
  const [pos, setPos] = useState({ x: 0, y: 0 });
  const btnRef = useRef<HTMLButtonElement>(null);

  const handleMouseMove = (e: React.MouseEvent<HTMLButtonElement>) => {
    const rect = btnRef.current?.getBoundingClientRect();
    if (!rect) return;
    const x = ((e.clientX - rect.left) / rect.width - 0.5) * 12;
    const y = ((e.clientY - rect.top) / rect.height - 0.5) * 12;
    setPos({ x, y });
  };

  return (
    <button
      ref={btnRef}
      onClick={onClick}
      disabled={loading}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => { setHovered(false); setPos({ x: 0, y: 0 }); }}
      onMouseMove={handleMouseMove}
      className="w-full py-4 rounded-xl font-bold text-base relative overflow-hidden"
      style={{
        background: loading
          ? '#1E3A5F'
          : hovered
            ? 'linear-gradient(135deg, #00C8FF, #7C3AED)'
            : 'linear-gradient(135deg, #00B4FF, #0080CC)',
        color: loading ? '#8BA3BE' : '#fff',
        border: 'none',
        cursor: loading ? 'not-allowed' : 'pointer',
        fontFamily: 'var(--font-heading)',
        letterSpacing: '0.04em',
        transform: loading ? 'none' : `translate(${pos.x}px, ${pos.y}px) scale(${hovered ? 1.03 : 1})`,
        boxShadow: loading
          ? 'none'
          : hovered
            ? '0 0 40px rgba(0,180,255,0.7), 0 0 80px rgba(0,180,255,0.3), 0 8px 24px rgba(0,0,0,0.3)'
            : '0 0 20px rgba(0,180,255,0.4), 0 4px 16px rgba(0,0,0,0.3)',
        transition: 'transform 0.15s ease, box-shadow 0.2s ease, background 0.2s ease',
        animation: loading ? 'none' : 'neonPulse 2.5s ease-in-out infinite',
      }}
    >
      {/* Shimmer overlay */}
      {!loading && (
        <div className="absolute inset-0 pointer-events-none" style={{
          background: 'linear-gradient(105deg, transparent 40%, rgba(255,255,255,0.15) 50%, transparent 60%)',
          backgroundSize: '200% 100%',
          animation: 'shimmerBtn 2.5s linear infinite',
        }} />
      )}
      <span className="relative z-10 flex items-center justify-center gap-2">
        {loading ? (
          <>
            <span className="inline-block w-4 h-4 rounded-full border-2 border-t-transparent" style={{ borderColor: '#4A6A85', borderTopColor: '#00B4FF', animation: 'spin 0.8s linear infinite' }} />
            Analyzing your message...
          </>
        ) : (
          <>🔍 Analyze Now</>
        )}
      </span>
    </button>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────

export default function RakshakAI() {
  // Navbar
  const [navVisible, setNavVisible] = useState(true);
  const [mobileOpen, setMobileOpen] = useState(false);
  const lastScrollY = useRef(0);

  // Hero
  const [inputText, setInputText] = useState('');
  const [inputError, setInputError] = useState(false);

  // Analysis
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [meterAnimate, setMeterAnimate] = useState(false);

  // Toast
  const [toastVisible, setToastVisible] = useState(false);
  const [toastMsg, setToastMsg] = useState('');

  // History
  const [history, setHistory] = useState<ScanRecord[]>(loadHistory);
  const [historyOpen, setHistoryOpen] = useState(false);

  // Tokens
  const [tokens, setTokens] = useState<number>(() => {
    const t = localStorage.getItem('rakshak_tokens');
    return t ? parseInt(t) : 3;
  });
  const [quizOpen, setQuizOpen] = useState(false);

  useEffect(() => { localStorage.setItem('rakshak_tokens', String(tokens)); }, [tokens]);

  // Scam cards visibility
  const scamRefs = useRef<(HTMLDivElement | null)[]>([]);
  const [scamVisible, setScamVisible] = useState([false, false, false, false]);

  // Scroll hide/show navbar
  useEffect(() => {
    const onScroll = () => {
      const y = window.scrollY;
      setNavVisible(y < lastScrollY.current || y < 80);
      lastScrollY.current = y;
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  // Stats
  const statsRef = useRef<HTMLDivElement>(null);
  const [statsActive, setStatsActive] = useState(false);

  // Stats IntersectionObserver
  useEffect(() => {
    if (!statsRef.current) return;
    const obs = new IntersectionObserver(([e]) => { if (e.isIntersecting) setStatsActive(true); }, { threshold: 0.3 });
    obs.observe(statsRef.current);
    return () => obs.disconnect();
  }, []);

  // Scam cards IntersectionObserver
  useEffect(() => {
    const observers: IntersectionObserver[] = [];
    scamRefs.current.forEach((el, i) => {
      if (!el) return;
      const obs = new IntersectionObserver(([e]) => {
        if (e.isIntersecting) setScamVisible((prev) => { const n = [...prev]; n[i] = true; return n; });
      }, { threshold: 0.15 });
      obs.observe(el);
      observers.push(obs);
    });
    return () => observers.forEach((o) => o.disconnect());
  }, []);

  const showToast = useCallback((msg: string) => {
    setToastMsg(msg);
    setToastVisible(true);
    setTimeout(() => setToastVisible(false), 3000);
  }, []);

  const handleAnalyze = () => {
    if (!inputText.trim()) { setInputError(true); return; }
    if (tokens <= 0) { setQuizOpen(true); return; }
    setInputError(false);
    setResult(null);
    setMeterAnimate(false);
    setLoading(true);
    setTokens(t => Math.max(0, t - 1));
    setTimeout(() => {
      const res = analyzeText(inputText);
      setResult(res);
      setLoading(false);
      setTimeout(() => setMeterAnimate(true), 100);
      // Save to history
      const record: ScanRecord = {
        id: Date.now().toString(),
        snippet: inputText.slice(0, 40),
        score: res.score,
        level: res.level,
        timestamp: Date.now(),
      };
      const updated = [record, ...loadHistory()].slice(0, 5);
      saveHistory(updated);
      setHistory(updated);
      // Scroll to result
      setTimeout(() => document.getElementById('result-card')?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 200);
    }, 1500);
  };

  const handleCopyReport = () => {
    if (!result) return;
    const report = `RAKSHAK AI — SCAM ANALYSIS REPORT\n\nRisk Level: ${result.level}\nRisk Score: ${result.score}/10\n\nFindings:\n${result.bullets.map((b, i) => `${i + 1}. ${b}`).join('\n')}\n\nAnalyzed on: ${new Date().toLocaleString('en-IN')}\nPowered by Rakshak AI — rakshak.ai`;
    navigator.clipboard.writeText(report).then(() => showToast('✓ Report copied to clipboard!'));
  };

  const handleWarnFriend = () => {
    if (!result) return;
    const msg = encodeURIComponent(`⚠️ *SCAM ALERT from Rakshak AI*\n\nI analyzed a suspicious message and it scored *${result.score}/10* — *${result.level}*.\n\nPlease be careful and do not respond to unknown messages asking for OTP, bank details, or personal information.\n\nStay safe! 🛡️\n— Analyzed via Rakshak AI`);
    window.open(`https://wa.me/?text=${msg}`, '_blank');
  };

  const handleClearHistory = () => {
    if (window.confirm('Clear all scan history?')) {
      localStorage.removeItem('rakshak_history');
      setHistory([]);
    }
  };

  const scrollTo = (id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' });
    setMobileOpen(false);
  };

  const levelColor = result?.level === 'HIGH RISK' ? '#FF4C4C' : result?.level === 'SUSPICIOUS' ? '#F59E0B' : '#22C55E';
  const levelBg = result?.level === 'HIGH RISK' ? '#FF4C4C22' : result?.level === 'SUSPICIOUS' ? '#F59E0B22' : '#22C55E22';
  const LevelIcon = result?.level === 'HIGH RISK' ? XCircle : result?.level === 'SUSPICIOUS' ? AlertTriangle : CheckCircle;

  return (
    <>
      <title>Rakshak AI — India's Scam Detector</title>
      <meta name="description" content="Free AI-powered scam detector for Indian users. Analyze suspicious messages, links, and phone numbers instantly." />
      <meta property="og:title" content="Rakshak AI — India's Scam Detector" />
      <meta property="og:description" content="Paste any suspicious message and get an instant risk analysis. Built for India." />
      <meta property="og:type" content="website" />
      <meta name="theme-color" content="#0D1B2A" />

      {/* Quiz Modal */}
      <QuizModal
        open={quizOpen}
        onClose={() => setQuizOpen(false)}
        onEarnToken={() => setTokens(t => t + 1)}
      />

      <div style={{ background: '#0D1B2A', minHeight: '100vh', color: '#F5F5F5', fontFamily: 'var(--font-sans)' }}>

        {/* ── NAVBAR ── */}
        <nav
          className="fixed top-0 left-0 right-0 z-50 transition-transform duration-300"
          style={{
            background: 'rgba(13,27,42,0.85)',
            backdropFilter: 'blur(12px)',
            borderBottom: '1px solid #1E3A5F',
            transform: navVisible ? 'translateY(0)' : 'translateY(-100%)',
          }}
        >
          <div className="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
            <div className="flex items-center gap-2 cursor-pointer" onClick={() => scrollTo('home')}>
              <Shield size={26} style={{ color: '#00B4FF' }} />
              <span className="font-bold text-xl" style={{ color: '#00B4FF', fontFamily: 'var(--font-heading)' }}>Rakshak AI</span>
            </div>
            {/* Desktop nav */}
            <div className="hidden md:flex items-center gap-8">
              {[['Home', 'home'], ['How It Works', 'how-it-works'], ['Scams', 'scams'], ['About', 'about']].map(([label, id]) => (
                <button key={id} onClick={() => scrollTo(id)}
                  className="text-sm transition-colors hover:text-white"
                  style={{ color: '#8BA3BE', background: 'none', border: 'none', cursor: 'pointer' }}>
                  {label}
                </button>
              ))}
            </div>
            {/* Mobile hamburger */}
            <button className="md:hidden p-2" style={{ background: 'none', border: 'none', color: '#8BA3BE', cursor: 'pointer' }}
              onClick={() => setMobileOpen(!mobileOpen)}>
              {mobileOpen ? <X size={22} /> : <Menu size={22} />}
            </button>
          </div>
          {/* Mobile menu */}
          {mobileOpen && (
            <div className="md:hidden px-4 pb-4 flex flex-col gap-3" style={{ borderTop: '1px solid #1E3A5F' }}>
              {[['Home', 'home'], ['How It Works', 'how-it-works'], ['Scams', 'scams'], ['About', 'about']].map(([label, id]) => (
                <button key={id} onClick={() => scrollTo(id)}
                  className="text-left py-2 text-sm"
                  style={{ color: '#8BA3BE', background: 'none', border: 'none', cursor: 'pointer' }}>
                  {label}
                </button>
              ))}
            </div>
          )}
        </nav>

        {/* ── HERO ── */}
        <section id="home" className="relative overflow-hidden pt-16 min-h-screen flex items-center">

          {/* Animated mesh background */}
          <div className="absolute inset-0" style={{ background: '#080C14' }} />
          <div className="absolute inset-0 pointer-events-none overflow-hidden">
            {/* Drifting orbs */}
            <div className="absolute rounded-full" style={{ width: 600, height: 600, top: '-10%', left: '-15%', background: 'radial-gradient(circle, rgba(0,180,255,0.12) 0%, transparent 70%)', animation: 'orbFloat1 18s ease-in-out infinite' }} />
            <div className="absolute rounded-full" style={{ width: 500, height: 500, top: '20%', right: '-10%', background: 'radial-gradient(circle, rgba(124,58,237,0.1) 0%, transparent 70%)', animation: 'orbFloat2 22s ease-in-out infinite' }} />
            <div className="absolute rounded-full" style={{ width: 400, height: 400, bottom: '0%', left: '30%', background: 'radial-gradient(circle, rgba(0,180,255,0.07) 0%, transparent 70%)', animation: 'orbFloat3 16s ease-in-out infinite' }} />
            {/* Grid overlay */}
            <div className="absolute inset-0" style={{ backgroundImage: 'linear-gradient(rgba(0,180,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,180,255,0.03) 1px, transparent 1px)', backgroundSize: '60px 60px' }} />
            {/* Grain texture */}
            <div className="absolute inset-0 opacity-30" style={{ backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='0.04'/%3E%3C/svg%3E")`, backgroundRepeat: 'repeat', backgroundSize: '200px 200px' }} />
          </div>

          <style>{`
            @keyframes orbFloat1 { 0%,100%{transform:translate(0,0) scale(1)} 33%{transform:translate(60px,-40px) scale(1.1)} 66%{transform:translate(-30px,50px) scale(0.9)} }
            @keyframes orbFloat2 { 0%,100%{transform:translate(0,0) scale(1)} 40%{transform:translate(-70px,40px) scale(1.15)} 70%{transform:translate(50px,-30px) scale(0.88)} }
            @keyframes orbFloat3 { 0%,100%{transform:translate(0,0) scale(1)} 50%{transform:translate(40px,-60px) scale(1.1)} }
            @keyframes scanLine { 0%{top:-4px;opacity:0} 5%{opacity:1} 95%{opacity:1} 100%{top:100%;opacity:0} }
            @keyframes neonPulse { 0%,100%{box-shadow:0 0 12px rgba(0,180,255,0.5),0 0 24px rgba(0,180,255,0.25)} 50%{box-shadow:0 0 30px rgba(0,180,255,0.9),0 0 60px rgba(0,180,255,0.5),0 0 100px rgba(0,180,255,0.2)} }
            @keyframes shimmerBtn { 0%{background-position:-200% center} 100%{background-position:200% center} }
            @keyframes badgePulse { 0%,100%{box-shadow:0 0 0 0 rgba(0,180,255,0.4)} 50%{box-shadow:0 0 0 8px rgba(0,180,255,0)} }
            @keyframes floatY { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-8px)} }
            @keyframes typeIn { from{opacity:0;transform:translateY(16px)} to{opacity:1;transform:translateY(0)} }
            @keyframes countUp { from{opacity:0;transform:scale(0.8)} to{opacity:1;transform:scale(1)} }
          `}</style>

          <div className="relative w-full max-w-4xl mx-auto px-4 py-20 flex flex-col items-center gap-8 text-center">

            {/* Badge */}
            <div
              className="inline-flex items-center gap-2 px-4 py-2 rounded-full text-xs font-semibold"
              style={{
                background: 'rgba(0,180,255,0.08)',
                border: '1px solid rgba(0,180,255,0.3)',
                color: '#00B4FF',
                animation: 'badgePulse 3s ease-in-out infinite, typeIn 0.6s ease both',
                fontFamily: 'var(--font-heading)',
                letterSpacing: '0.05em',
              }}
            >
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#00B4FF', display: 'inline-block', boxShadow: '0 0 8px #00B4FF' }} />
              🇮🇳 India's #1 AI-Powered Scam Detector
            </div>

            {/* Headline */}
            <div style={{ animation: 'typeIn 0.7s ease 0.1s both' }}>
              <h1
                className="font-bold leading-tight"
                style={{
                  fontFamily: 'var(--font-heading)',
                  fontSize: 'clamp(2.4rem, 6vw, 4.5rem)',
                  lineHeight: 1.1,
                  color: '#F0F6FF',
                }}
              >
                Your Digital{' '}
                <span style={{
                  background: 'linear-gradient(135deg, #00B4FF 0%, #7C3AED 100%)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                  backgroundClip: 'text',
                  display: 'inline-block',
                  animation: 'floatY 4s ease-in-out infinite',
                }}>
                  Rakshak
                </span>
                <br />Against Online Scams
              </h1>
            </div>

            {/* Subtext */}
            <p
              className="max-w-xl text-base md:text-lg leading-relaxed"
              style={{ color: '#7A9BB5', animation: 'typeIn 0.7s ease 0.2s both' }}
            >
              Paste any suspicious SMS, WhatsApp message, email, or link.
              Our AI scans for <span style={{ color: '#00B4FF', fontWeight: 600 }}>500+ scam patterns</span> and gives you an instant verdict.
            </p>

            {/* Trust chips */}
            <div className="flex flex-wrap justify-center gap-3" style={{ animation: 'typeIn 0.7s ease 0.3s both' }}>
              {[
                { icon: '🔒', label: '100% Private' },
                { icon: '⚡', label: 'Instant Results' },
                { icon: '🆓', label: 'Always Free' },
                { icon: '🇮🇳', label: 'Built for India' },
              ].map(({ icon, label }) => (
                <span key={label} className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium"
                  style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', color: '#8BA3BE' }}>
                  {icon} {label}
                </span>
              ))}
            </div>

            {/* ── Glass Input Card ── */}
            <div
              className="w-full max-w-2xl rounded-2xl p-6 flex flex-col gap-4"
              style={{
                background: 'rgba(10,20,38,0.8)',
                border: '1px solid rgba(0,180,255,0.15)',
                backdropFilter: 'blur(24px)',
                boxShadow: '0 8px 48px rgba(0,0,0,0.4), 0 0 0 1px rgba(0,180,255,0.05)',
                animation: 'typeIn 0.7s ease 0.4s both',
              }}
            >
              {/* Textarea with scan line */}
              <div className="relative rounded-xl overflow-hidden">
                <textarea
                  value={inputText}
                  onChange={(e) => { setInputText(e.target.value); if (e.target.value) setInputError(false); }}
                  placeholder="Paste suspicious message, link, or phone number here..."
                  rows={5}
                  className="w-full rounded-xl p-4 text-sm resize-none outline-none transition-all duration-200"
                  style={{
                    background: 'rgba(6,14,26,0.9)',
                    border: `1.5px solid ${inputError ? '#FF4C4C' : 'rgba(0,180,255,0.2)'}`,
                    color: '#F0F6FF',
                    fontFamily: 'var(--font-sans)',
                    lineHeight: 1.7,
                    boxShadow: inputError ? '0 0 0 3px rgba(255,76,76,0.15)' : 'inset 0 2px 8px rgba(0,0,0,0.3)',
                  }}
                  onFocus={(e) => { if (!inputError) e.target.style.borderColor = 'rgba(0,180,255,0.6)'; e.target.style.boxShadow = '0 0 0 3px rgba(0,180,255,0.1), inset 0 2px 8px rgba(0,0,0,0.3)'; }}
                  onBlur={(e) => { if (!inputError) e.target.style.borderColor = 'rgba(0,180,255,0.2)'; e.target.style.boxShadow = 'inset 0 2px 8px rgba(0,0,0,0.3)'; }}
                />
                {/* Scan line animation while loading */}
                {loading && (
                  <div className="absolute left-0 right-0 h-0.5 pointer-events-none" style={{
                    background: 'linear-gradient(90deg, transparent, #00B4FF, #7C3AED, transparent)',
                    boxShadow: '0 0 12px #00B4FF, 0 0 24px rgba(0,180,255,0.5)',
                    animation: 'scanLine 1.6s linear infinite',
                    position: 'absolute',
                  }} />
                )}
              </div>

              {inputError && (
                <p className="text-xs text-left -mt-2" style={{ color: '#FF4C4C' }}>⚠ Please paste a message before analyzing.</p>
              )}

              {/* Analyze button */}
              <HeroAnalyzeButton loading={loading} onClick={handleAnalyze} />

              {/* Token + Quiz row */}
              <div className="flex items-center gap-3">
                {/* Token pill */}
                <div className="flex items-center gap-2 px-3 py-2 rounded-xl flex-shrink-0"
                  style={{ background: 'rgba(0,180,255,0.07)', border: '1px solid rgba(0,180,255,0.18)' }}>
                  <span style={{ fontSize: 16 }}>🪙</span>
                  <span className="text-sm font-bold" style={{ color: '#00B4FF', fontFamily: 'var(--font-heading)' }}>{tokens}</span>
                  <span className="text-xs" style={{ color: '#4A6A85' }}>token{tokens !== 1 ? 's' : ''}</span>
                </div>

                {/* Quiz CTA button */}
                <button
                  onClick={() => setQuizOpen(true)}
                  className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl font-semibold text-sm transition-all duration-200"
                  style={{
                    background: 'linear-gradient(135deg, rgba(124,58,237,0.18), rgba(0,180,255,0.12))',
                    border: '1.5px solid rgba(124,58,237,0.45)',
                    color: '#C084FC',
                    cursor: 'pointer',
                    fontFamily: 'var(--font-heading)',
                    letterSpacing: '0.02em',
                  }}
                  onMouseEnter={e => {
                    (e.currentTarget as HTMLButtonElement).style.background = 'linear-gradient(135deg, rgba(124,58,237,0.32), rgba(0,180,255,0.2))';
                    (e.currentTarget as HTMLButtonElement).style.borderColor = 'rgba(124,58,237,0.8)';
                    (e.currentTarget as HTMLButtonElement).style.boxShadow = '0 0 20px rgba(124,58,237,0.35)';
                    (e.currentTarget as HTMLButtonElement).style.color = '#E0AAFF';
                  }}
                  onMouseLeave={e => {
                    (e.currentTarget as HTMLButtonElement).style.background = 'linear-gradient(135deg, rgba(124,58,237,0.18), rgba(0,180,255,0.12))';
                    (e.currentTarget as HTMLButtonElement).style.borderColor = 'rgba(124,58,237,0.45)';
                    (e.currentTarget as HTMLButtonElement).style.boxShadow = 'none';
                    (e.currentTarget as HTMLButtonElement).style.color = '#C084FC';
                  }}
                >
                  🧠 Earn Tokens — Take the Quiz
                  <span style={{ fontSize: 16 }}>→</span>
                </button>
              </div>
            </div>

            {/* Scroll hint */}
            <div style={{ animation: 'floatY 2.5s ease-in-out infinite', color: '#2A4A65', marginTop: 8 }}>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
                <path d="M12 5v14M5 12l7 7 7-7" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </div>
          </div>
        </section>

        {/* ── LOADING SPINNER ── */}
        {loading && (
          <div className="flex flex-col items-center justify-center py-12 gap-4">
            <div className="w-12 h-12 rounded-full border-4 border-t-transparent animate-spin" style={{ borderColor: '#1E3A5F', borderTopColor: '#00B4FF' }} />
            <p className="text-sm" style={{ color: '#8BA3BE' }}>Rakshak AI is analyzing your message...</p>
          </div>
        )}

        {/* ── RESULT CARD ── */}
        {result && !loading && (
          <div id="result-card" className="max-w-2xl mx-auto px-4 pb-8">
            <div
              className="rounded-2xl p-6 flex flex-col gap-5 transition-all duration-500"
              style={{ background: '#112236', border: `1px solid ${levelColor}44`, boxShadow: `0 0 32px ${levelColor}18` }}
            >
              {/* Badge */}
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg" style={{ background: levelBg }}>
                  <LevelIcon size={24} style={{ color: levelColor }} />
                </div>
                <div>
                  <div className="text-xs font-medium mb-0.5" style={{ color: '#8BA3BE' }}>Analysis Result</div>
                  <div className="text-xl font-bold" style={{ color: levelColor, fontFamily: 'var(--font-heading)' }}>{result.level}</div>
                </div>
              </div>

              {/* Risk Meter */}
              <RiskMeter score={result.score} animate={meterAnimate} />

              {/* Bullets */}
              <ul className="flex flex-col gap-2">
                {result.bullets.map((b, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm" style={{ color: '#C8D8E8' }}>
                    <span className="mt-0.5 shrink-0" style={{ color: levelColor }}>•</span>
                    {b}
                  </li>
                ))}
              </ul>

              {/* Action buttons */}
              <div className="flex flex-col sm:flex-row gap-3 pt-1">
                <button
                  onClick={handleCopyReport}
                  className="flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-semibold transition-all"
                  style={{ background: '#1E3A5F', color: '#00B4FF', border: '1px solid #00B4FF44', cursor: 'pointer' }}
                  onMouseEnter={(e) => { (e.currentTarget).style.boxShadow = '0 0 16px rgba(0,180,255,0.3)'; }}
                  onMouseLeave={(e) => { (e.currentTarget).style.boxShadow = 'none'; }}
                >
                  <Copy size={15} /> Copy Report
                </button>
                <button
                  onClick={handleWarnFriend}
                  className="flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-semibold transition-all"
                  style={{ background: '#22C55E', color: '#fff', border: 'none', cursor: 'pointer' }}
                  onMouseEnter={(e) => { (e.currentTarget).style.boxShadow = '0 0 20px rgba(34,197,94,0.45)'; }}
                  onMouseLeave={(e) => { (e.currentTarget).style.boxShadow = 'none'; }}
                >
                  <MessageCircle size={15} /> ⚡ Warn a Friend
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ── STATS BAR ── */}
        <div ref={statsRef} className="max-w-6xl mx-auto px-4 py-12">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard label="Scams Blocked" target={50000} suffix="+" active={statsActive} />
            <StatCard label="Accuracy Rate" target={98} suffix="%" active={statsActive} />
            <StatCard label="Users Protected" target={2000000} suffix="+" active={statsActive} />
            <StatCard label="Active Protection" target={24} suffix="/7" active={statsActive} />
          </div>
        </div>

        {/* ── SCAN HISTORY ── */}
        <div className="max-w-2xl mx-auto px-4 pb-12">
          <div className="rounded-2xl overflow-hidden" style={{ background: '#112236', border: '1px solid #1E3A5F' }}>
            <button
              onClick={() => setHistoryOpen(!historyOpen)}
              className="w-full flex items-center justify-between px-6 py-4"
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#F5F5F5' }}
            >
              <div className="flex items-center gap-2 font-semibold" style={{ fontFamily: 'var(--font-heading)' }}>
                <ClipboardList size={18} style={{ color: '#00B4FF' }} />
                Recent Scans
                {history.length > 0 && (
                  <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: '#00B4FF22', color: '#00B4FF' }}>{history.length}</span>
                )}
              </div>
              {historyOpen ? <ChevronUp size={18} style={{ color: '#8BA3BE' }} /> : <ChevronDown size={18} style={{ color: '#8BA3BE' }} />}
            </button>

            {historyOpen && (
              <div className="px-6 pb-5 flex flex-col gap-3">
                {history.length === 0 ? (
                  <p className="text-sm text-center py-4" style={{ color: '#8BA3BE' }}>No scans yet. Analyze a message to get started.</p>
                ) : (
                  <>
                    {history.map((rec) => {
                      const c = rec.level === 'HIGH RISK' ? '#FF4C4C' : rec.level === 'SUSPICIOUS' ? '#F59E0B' : '#22C55E';
                      return (
                        <div key={rec.id} className="flex items-center justify-between gap-3 py-3 px-4 rounded-xl" style={{ background: '#0D1B2A', border: '1px solid #1E3A5F' }}>
                          <div className="flex-1 min-w-0">
                            <p className="text-sm truncate" style={{ color: '#C8D8E8' }}>{rec.snippet}{rec.snippet.length >= 40 ? '…' : ''}</p>
                            <p className="text-xs mt-0.5" style={{ color: '#8BA3BE' }}>{timeAgo(rec.timestamp)}</p>
                          </div>
                          <span className="text-xs font-semibold px-2.5 py-1 rounded-full shrink-0" style={{ background: c + '22', color: c }}>
                            {rec.level} · {rec.score}/10
                          </span>
                        </div>
                      );
                    })}
                    <button
                      onClick={handleClearHistory}
                      className="flex items-center justify-center gap-2 w-full py-2.5 rounded-xl text-sm font-medium mt-1 transition-all"
                      style={{ background: '#FF4C4C18', color: '#FF4C4C', border: '1px solid #FF4C4C33', cursor: 'pointer' }}
                    >
                      <Trash2 size={14} /> Clear History
                    </button>
                  </>
                )}
              </div>
            )}
          </div>
        </div>

        {/* ── HOW IT WORKS ── */}
        <HowItWorks />

        {/* ── KNOW YOUR SCAMS ── */}
        <section id="scams" className="max-w-6xl mx-auto px-4 py-16">
          <div style={{ transition: 'opacity 0.7s ease, transform 0.7s ease', opacity: scamVisible[0] ? 1 : 0, transform: scamVisible[0] ? 'translateY(0)' : 'translateY(20px)' }}>
            <h2 className="text-3xl font-bold text-center mb-3" style={{ fontFamily: 'var(--font-heading)', color: '#F5F5F5' }}>
              Know Your{' '}
              <span style={{ background: 'linear-gradient(135deg,#00B4FF,#7C3AED)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>Scams</span>
            </h2>
            <p className="text-center text-sm mb-10" style={{ color: '#8BA3BE' }}>Common frauds targeting Indian internet users</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5 items-stretch">
            {SCAM_CARDS.map((card, i) => (
              <div key={i} ref={(el) => { scamRefs.current[i] = el; }} className="h-full">
                <ScamCard card={card} visible={scamVisible[i]} delay={i * 120} />
              </div>
            ))}
          </div>
        </section>

        {/* ── ABOUT ── */}
        <section id="about" className="max-w-3xl mx-auto px-4 py-16 text-center">
          <div className="rounded-2xl p-8 flex flex-col gap-4" style={{ background: '#112236', border: '1px solid #1E3A5F' }}>
            <Shield size={40} style={{ color: '#00B4FF', margin: '0 auto' }} />
            <h2 className="text-2xl font-bold" style={{ fontFamily: 'var(--font-heading)', color: '#F5F5F5' }}>Built for a Safer India</h2>
            <p className="text-sm leading-relaxed" style={{ color: '#8BA3BE' }}>
              Rakshak AI was created to protect India's digital citizens from the growing threat of online fraud. With millions of Indians coming online every year, scammers are becoming more sophisticated. Our mission is to give every Indian a free, instant tool to verify suspicious messages before it's too late.
            </p>
            <div className="mt-2 p-4 rounded-xl text-sm" style={{ background: '#F59E0B11', border: '1px solid #F59E0B33', color: '#F59E0B' }}>
              ⚠ <strong>Disclaimer:</strong> This tool uses pattern matching and keyword analysis. Always verify suspicious communications through official channels. For cybercrime reporting, visit <strong>cybercrime.gov.in</strong>.
            </div>
          </div>
        </section>

        {/* ── FOOTER ── */}
        <footer style={{ borderTop: '1px solid #1E3A5F' }}>
          <div className="max-w-6xl mx-auto px-4 py-3 flex flex-col sm:flex-row items-center justify-between gap-1">
            <div className="flex items-center gap-2">
              <Shield size={14} style={{ color: '#00B4FF' }} />
              <span className="text-xs font-semibold" style={{ color: '#F5F5F5', fontFamily: 'var(--font-heading)' }}>Rakshak AI</span>
              <span className="text-xs" style={{ color: '#8BA3BE' }}>— Made for a Safer India 🇮🇳</span>
            </div>
            <span className="text-xs" style={{ color: '#8BA3BE' }}>© 2026 Rakshak AI</span>
          </div>
          <div className="w-full py-2 text-center text-xs" style={{ color: '#4A6A85', borderTop: '1px solid #1E3A5F33' }}>
            Made with <span style={{ color: '#FF4C4C' }}>♥</span> by{' '}
            <span style={{ background: 'linear-gradient(135deg,#00B4FF,#7C3AED)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text', fontWeight: 600, fontFamily: 'var(--font-heading)' }}>
              Shivani Bhati
            </span>
          </div>
        </footer>

        {/* Toast */}
        <Toast message={toastMsg} visible={toastVisible} />

        {/* Shimmer keyframe */}
        <style>{`
          @keyframes shimmer {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
          }
        `}</style>
      </div>
    </>
  );
}
