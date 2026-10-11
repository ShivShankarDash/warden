/**
 * Business Impact (Motion Canvas).
 * Part A (0.6s): local by design + most decisions settle without a model call (decision-path data
 * from the Warden dashboard). Part B (12.97s): public benchmark, judge off (README numbers).
 * Section length 21.78s (plan/timeline.json 'impact').
 */
import {Circle, Layout, Line, makeScene2D, Rect, Txt} from '@motion-canvas/2d';
import {all, createRef, easeInOutCubic, easeOutCubic, linear, sequence, createSignal, waitFor, chain, useTime} from '@motion-canvas/core';

const C = {
  bg: '#0a0e14', panel: '#111823', stroke: '#223047', ink: '#e8edf5', muted: '#8390a3',
  blue: '#2a78d6', blueL: '#86b6ef', green: '#3dbe7a', red: '#e5484d', amber: '#f5b83d',
};
const SANS = 'Inter', DISPLAY = 'Inter Display', MONO = 'JetBrains Mono';

const CUE2 = 12.97, END = 21.78;

// Decision path from the dashboard (memory, rules, classifier settle without the judge).
const PATH = [
  {name: 'Classifier', v: 40, color: C.blue},
  {name: 'Rules', v: 23, color: C.blueL},
  {name: 'Memory', v: 15, color: '#5a9be6'},
  {name: 'LLM judge', v: 22, color: C.amber},
];
// README benchmark, LLM judge disabled.
const BENCH = [
  {name: 'xTRam1 safe-guard', v: 91.6},
  {name: 'NotInject (benign)', v: 87.3},
  {name: 'deepset injections', v: 86.8},
  {name: 'Antijection eval', v: 84.4},
  {name: 'PromptSentinel', v: 72.6},
];

export default makeScene2D(function* (view) {
  view.fill(C.bg);

  // ---------- Part A
  const partA = createRef<Layout>();
  const kickA = createRef<Txt>();
  const headA = createRef<Txt>();
  const cardL = createRef<Rect>();
  const cardR = createRef<Rect>();
  const ring = createRef<Rect>();
  const msRule = createRef<Rect>();
  const msJudge = createRef<Rect>();
  const msRuleT = createRef<Txt>();
  const msJudgeT = createRef<Txt>();

  // donut arcs as Circle segments
  const arcs: ReturnType<typeof createRef<Circle>>[] = PATH.map(() => createRef<Circle>());
  const progress = createSignal(0);
  let acc = 0;
  const spans = PATH.map(p => {
    const s = acc; acc += p.v; return [s, acc];
  });
  const dots = Array.from({length: 9}, () => createRef<Circle>());

  view.add(
    <Layout ref={partA}>
      <Txt ref={kickA} text={'BUSINESS IMPACT'} fontFamily={SANS} fontWeight={600} fontSize={22} letterSpacing={3} fill={C.blueL} x={-880} y={-430} offsetX={-1} opacity={0} />
      <Txt ref={headA} text={'Private by design, cheap by default'} fontFamily={DISPLAY} fontWeight={700} fontSize={64} fill={C.ink} x={-880} y={-370} offsetX={-1} opacity={0} />

      <Rect ref={cardL} x={-450} y={90} width={820} height={600} radius={24} fill={C.panel} stroke={C.stroke} lineWidth={2} opacity={0}>
        <Txt text={'Your content stays in the building'} fontFamily={DISPLAY} fontWeight={700} fontSize={40} fill={C.ink} y={-230} />
        <Rect ref={ring} width={520} height={320} y={40} radius={28} stroke={C.blue} lineWidth={4} lineDash={[18, 12]} />
        <Txt text={'your machine'} fontFamily={MONO} fontSize={22} fill={C.blueL} y={-145} x={-150} />
        {dots.map((d, i) => (
          <Circle ref={d} size={22} fill={i % 3 === 0 ? C.red : C.blueL} x={-180 + (i % 3) * 180} y={-30 + Math.floor(i / 3) * 70} opacity={0} />
        ))}
        <Txt text={'detection runs locally · no text is uploaded'} fontFamily={SANS} fontWeight={500} fontSize={26} fill={C.muted} y={250} />
      </Rect>

      <Rect ref={cardR} x={450} y={90} width={820} height={600} radius={24} fill={C.panel} stroke={C.stroke} lineWidth={2} opacity={0}>
        <Txt text={'Most decisions skip the model call'} fontFamily={DISPLAY} fontWeight={700} fontSize={40} fill={C.ink} y={-230} />
        {PATH.map((p, i) => (
          <Circle ref={arcs[i]} size={280} x={-200} y={-35} lineWidth={44} stroke={p.color} lineCap={'butt'}
                  startAngle={-90 + spans[i][0] * 3.6} endAngle={() => -90 + Math.min(spans[i][1], Math.max(spans[i][0], progress() * 100)) * 3.6} />
        ))}
        <Txt text={() => `${Math.round(Math.min(78, progress() * 100))}%`} fontFamily={DISPLAY} fontWeight={700} fontSize={60} fill={C.ink} x={-200} y={-48} />
        <Txt text={'no LLM call'} fontFamily={SANS} fontWeight={500} fontSize={22} fill={C.muted} x={-200} y={2} />
        <Layout layout direction={"column"} gap={14} x={175} y={-40}>
          {PATH.map(p => (
            <Layout layout gap={14} alignItems={'center'}>
              <Rect width={18} height={18} radius={4} fill={p.color} />
              <Txt text={`${p.name}`} fontFamily={SANS} fontWeight={500} fontSize={24} fill={C.ink} width={170} />
              <Txt text={`${p.v}%`} fontFamily={MONO} fontSize={22} fill={C.muted} />
            </Layout>
          ))}
        </Layout>
        <Rect ref={msRule} x={-330} y={198} height={20} width={0} radius={10} fill={C.green} offsetX={-1} />
        <Txt ref={msRuleT} text={'rule match · ~15 ms'} fontFamily={MONO} fontSize={21} fill={C.green} x={-330} y={168} offsetX={-1} opacity={0} />
        <Rect ref={msJudge} x={-330} y={262} height={20} width={0} radius={10} fill={C.amber} offsetX={-1} />
        <Txt ref={msJudgeT} text={'LLM judge · ~1.4 s'} fontFamily={MONO} fontSize={21} fill={C.amber} x={-330} y={232} offsetX={-1} opacity={0} />
      </Rect>
      <Txt text={'decision-path share from the Warden dashboard on a local install'} fontFamily={SANS} fontSize={20} fill={'#4a5568'} x={450} y={420} />
    </Layout>,
  );

  yield* waitFor(0.3);
  yield* all(kickA().opacity(1, 0.6), headA().opacity(1, 0.7), headA().y(-370, 0.7, easeOutCubic));
  yield* all(cardL().opacity(1, 0.7), cardL().y(70, 0.7, easeOutCubic));
  yield* sequence(0.12, ...dots.map(d => d().opacity(1, 0.3)));
  // red dots try to leave and bounce off the boundary
  yield* all(
    ...dots.filter((_, i) => i % 3 === 0).map(d => chain(d().x(d().x() - 230, 0.6, easeInOutCubic), d().x(d().x(), 0.5, easeOutCubic))),
    ring().stroke(C.green, 0.5),
  );
  yield* all(cardR().opacity(1, 0.7), cardR().y(70, 0.7, easeOutCubic));
  yield* progress(1, 1.6, easeInOutCubic);
  yield* all(msRule().width(10, 0.5), msRuleT().opacity(1, 0.4));
  yield* all(msJudge().width(660, 1.4, linear), msJudgeT().opacity(1, 0.4));


  yield* waitFor(Math.max(0, CUE2 - 0.6 - useTime()));
  yield* partA().opacity(0, 0.6);

  // ---------- Part B
  const big = createRef<Txt>();
  const capB = createRef<Txt>();
  const kickB = createRef<Txt>();
  const pct = createSignal(0);
  const bars = BENCH.map(() => createRef<Rect>());
  const labels = BENCH.map(() => createRef<Txt>());
  view.add(
    <Layout>
      <Txt ref={kickB} text={'PUBLIC BENCHMARKS · LLM JUDGE OFF'} fontFamily={SANS} fontWeight={600} fontSize={22} letterSpacing={3} fill={C.blueL} x={-880} y={-430} offsetX={-1} opacity={0} />
      <Txt ref={big} text={() => `${pct().toFixed(1)}%`} fontFamily={DISPLAY} fontWeight={700} fontSize={220} fill={C.ink} x={-880} y={-150} offsetX={-1} opacity={0} />
      <Txt ref={capB} text={'classified correctly across five public datasets,\nroughly five samples in every six'} fontFamily={SANS} fontWeight={500} fontSize={32} lineHeight={46} fill={C.muted} x={-880} y={80} offsetX={-1} opacity={0} />
      {BENCH.map((b, i) => (
        <Layout x={120} y={-200 + i * 105}>
          <Txt ref={labels[i]} text={b.name} fontFamily={SANS} fontWeight={500} fontSize={26} fill={C.ink} offsetX={-1} y={-26} opacity={0} />
          <Rect width={680} height={18} radius={9} fill={'#16202e'} offsetX={-1} y={10} />
          <Rect ref={bars[i]} width={0} height={18} radius={9} fill={b.v >= 84 ? C.blue : '#5a7fb0'} offsetX={-1} y={10} />
          <Txt text={`${b.v}%`} fontFamily={MONO} fontSize={24} fill={C.muted} x={700} y={10} offsetX={-1} opacity={() => Math.min(1, bars[i]().width() / 300)} />
        </Layout>
      ))}
    </Layout>,
  );
  yield* all(kickB().opacity(1, 0.5), big().opacity(1, 0.5), pct(84.4, 1.6, easeOutCubic),
             sequence(0.15, ...BENCH.map((b, i) => all(labels[i]().opacity(1, 0.4), bars[i]().width(680 * b.v / 100, 1.0, easeOutCubic)))));
  yield* capB().opacity(1, 0.6);
  yield* waitFor(Math.max(0, END - 0.6 - useTime()));
  yield* all(...view.children().map(c => c.opacity(0, 0.6)));
});
