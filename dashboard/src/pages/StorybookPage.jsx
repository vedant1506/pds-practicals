import React, { useState } from 'react';
import { ChevronLeft, ChevronRight, BookOpen, Image as ImageIcon, ArrowRight, Cpu, Tag } from 'lucide-react';
import { PRACTICALS_STORY } from '../data/practicalsStory';

export default function StorybookPage() {
  const [activeId, setActiveId] = useState(1);
  const index = PRACTICALS_STORY.findIndex((p) => p.id === activeId);
  const practical = PRACTICALS_STORY[index];

  const goTo = (id) => {
    setActiveId(id);
    document.getElementById('storybook-top')?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <div className="flex h-full min-h-0 bg-[#090d16] text-slate-100">
      {/* Left mini sidebar: P1 - P10, exact practical names */}
      <aside className="w-64 shrink-0 border-r border-slate-800/80 bg-slate-950/80 flex flex-col min-h-0">
        <div className="p-3 border-b border-slate-800/80">
          <p className="text-[11px] font-bold tracking-wider text-slate-400 uppercase flex items-center gap-1.5">
            <BookOpen size={13} className="text-cyan-400" /> Practicals 1 to 10
          </p>
          <p className="text-[11px] text-slate-500 mt-1">Pick a practical</p>
        </div>
        <nav className="flex-1 overflow-y-auto p-2 space-y-1 custom-scrollbar">
          {PRACTICALS_STORY.map((p) => {
            const isActive = p.id === activeId;
            return (
              <button
                key={p.id}
                onClick={() => goTo(p.id)}
                title={p.shortTitle}
                className={`w-full text-left px-3 py-2.5 rounded-xl border text-xs transition-all ${
                  isActive
                    ? 'bg-slate-900 border-cyan-500/60 text-white font-semibold shadow-md'
                    : 'bg-transparent border-transparent text-slate-400 hover:bg-slate-900 hover:text-slate-200'
                }`}
              >
                <span className="flex items-start gap-2">
                  <span
                    className={`w-6 h-6 rounded-lg flex items-center justify-center text-[11px] font-bold shrink-0 mt-0.5 ${
                      isActive ? 'bg-cyan-500 text-slate-950' : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {p.id}
                  </span>
                  <span className="leading-snug whitespace-normal">{p.shortTitle}</span>
                </span>
              </button>
            );
          })}
        </nav>
        <div className="p-3 border-t border-slate-800/80 text-[10px] text-slate-500 text-center">
          {index + 1} of 10
        </div>
      </aside>

      {/* Main story content */}
      <div className="flex-1 overflow-y-auto min-h-0" id="storybook-top">
        <div className="max-w-3xl mx-auto p-4 md:p-8 space-y-6">
          {/* Title */}
          <div>
            <p className="text-[11px] font-bold tracking-widest text-cyan-400 uppercase">
              Practical {practical.id} of 10
            </p>
            <h2 className="text-xl md:text-2xl font-extrabold text-white mt-1">{practical.title}</h2>
            <p className="text-sm text-slate-300 mt-3 leading-relaxed bg-slate-900/70 border border-slate-800 rounded-2xl p-4">
              {practical.simpleWords}
            </p>
          </div>

          {/* Technical view */}
          <section className="bg-slate-900/60 border border-cyan-500/25 rounded-2xl p-4">
            <h3 className="text-xs font-bold text-cyan-300 uppercase tracking-wider flex items-center gap-1.5">
              <Cpu size={14} className="text-cyan-400" /> Technical view
            </h3>
            <ul className="mt-2 space-y-2">
              {practical.technical.map((t, i) => (
                <li key={i} className="flex gap-2.5 text-sm text-slate-200 leading-relaxed">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 shrink-0 mt-2" />
                  {t}
                </li>
              ))}
            </ul>
            <div className="mt-3 pt-3 border-t border-slate-800">
              <h4 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <Tag size={12} className="text-cyan-400" /> Key terms
              </h4>
              <div className="mt-2 space-y-1.5">
                {practical.terms.map((tm, i) => (
                  <p key={i} className="text-xs text-slate-300 leading-relaxed">
                    <span className="font-mono font-semibold text-cyan-300 bg-cyan-500/10 border border-cyan-500/30 rounded px-1.5 py-0.5 mr-1.5">
                      {tm.term}
                    </span>
                    {tm.meaning}
                  </p>
                ))}
              </div>
            </div>
          </section>

          {/* What we had */}
          <section className="bg-slate-900/60 border border-slate-800 rounded-2xl p-4">
            <h3 className="text-xs font-bold text-amber-300 uppercase tracking-wider">What we had at the start</h3>
            <p className="text-sm text-slate-200 mt-2 leading-relaxed">{practical.had}</p>
          </section>

          {/* What we did */}
          <section className="bg-slate-900/60 border border-slate-800 rounded-2xl p-4">
            <h3 className="text-xs font-bold text-cyan-300 uppercase tracking-wider">What we did</h3>
            <ul className="mt-2 space-y-2">
              {practical.did.map((step, i) => (
                <li key={i} className="flex gap-2.5 text-sm text-slate-200 leading-relaxed">
                  <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-300 text-[11px] font-bold flex items-center justify-center shrink-0 mt-0.5">
                    {i + 1}
                  </span>
                  {step}
                </li>
              ))}
            </ul>
          </section>

          {/* What we got */}
          <section className="bg-slate-900/60 border border-slate-800 rounded-2xl p-4">
            <h3 className="text-xs font-bold text-emerald-300 uppercase tracking-wider">What we got at the end</h3>
            <p className="text-sm text-slate-200 mt-2 leading-relaxed">{practical.got}</p>
            <div className="grid grid-cols-3 gap-2 mt-3">
              {practical.numbers.map((n, i) => (
                <div key={i} className="bg-slate-950/80 border border-slate-800 rounded-xl p-2.5 text-center">
                  <p className="text-[10px] text-slate-500 uppercase tracking-wide">{n.label}</p>
                  <p className="text-sm font-bold text-white mt-0.5">{n.value}</p>
                </div>
              ))}
            </div>
          </section>

          {/* Result images */}
          <section>
            <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
              <ImageIcon size={14} className="text-cyan-400" /> Result pictures from this practical
            </h3>
            {practical.images.length === 0 ? (
              <div className="mt-3 bg-slate-900/60 border border-slate-800 rounded-2xl p-4 text-sm text-slate-300 leading-relaxed">
                This last step has no chart. It packs all the earlier steps into one automatic machine.
                Its result is the final ready file itself: a normal file and a much smaller compressed file.
              </div>
            ) : (
              <div className="mt-3 space-y-4">
                {practical.images.map((img, i) => (
                  <figure key={i} className="bg-slate-950 border border-slate-800 rounded-2xl overflow-hidden">
                    <img src={img.src} alt={img.caption} className="w-full h-auto" loading="lazy" />
                    <figcaption className="px-4 py-3 text-xs text-slate-400 leading-relaxed border-t border-slate-800">
                      {img.caption}
                    </figcaption>
                  </figure>
                ))}
              </div>
            )}
          </section>

          {/* Why next */}
          <div className="bg-cyan-950/30 border border-cyan-500/30 rounded-2xl p-4 flex gap-2.5 items-start">
            <ArrowRight size={16} className="text-cyan-400 shrink-0 mt-0.5" />
            <p className="text-sm text-cyan-100 leading-relaxed">{practical.whyNext}</p>
          </div>

          {/* Prev / Next */}
          <div className="flex items-center justify-between pt-2 pb-8">
            <button
              onClick={() => index > 0 && goTo(PRACTICALS_STORY[index - 1].id)}
              disabled={index === 0}
              className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-xs font-semibold text-slate-200 disabled:opacity-40 hover:bg-slate-800 transition-all"
            >
              <ChevronLeft size={15} /> Previous
            </button>
            <span className="text-[11px] text-slate-500 font-mono">
              P{practical.id} / P10
            </span>
            <button
              onClick={() => index < PRACTICALS_STORY.length - 1 && goTo(PRACTICALS_STORY[index + 1].id)}
              disabled={index === PRACTICALS_STORY.length - 1}
              className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-xs font-semibold text-white disabled:opacity-40 hover:brightness-110 transition-all"
            >
              Next <ChevronRight size={15} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
