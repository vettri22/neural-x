"""
Multi-Signal Risk Fusion + Explainable Prevention Engine
==========================================================
Feature 3 of the NEURAL-X v4 upgrade.

This sits ON TOP of the existing URL Analysis + hybrid_scorer output (which
already fuses url_heuristic + reputation + domain_intel + content/journal
signals into `hybrid.final_score`) and adds the two NEW signals — Visual and
Behavioral — into one final, explainable, configurably-weighted score.

Design choices:
  - The existing URL Analysis feature and its hybrid score are NOT replaced.
    `hybrid.final_score` (or the plain url_result threat_score as a fallback)
    is used as the 'url_ml' signal here — this is exactly what the task
    description calls "URL/ML Risk".
  - Domain risk is taken from hybrid.sub_scores.domain_intel when available
    (already computed from WHOIS/SSL/age) — no duplicate domain logic.
  - Visual / Behavioral risk come from the new analyzer modules and may be
    `None` when a module was unavailable (never fabricated).
  - Weights are read from app.config['RISK_FUSION_WEIGHTS'] so they are
    configurable rather than hard-coded, and are re-normalized over
    whichever signals are actually available for this scan.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_WEIGHTS = {
    'url_ml': 0.30,
    'domain': 0.20,
    'visual': 0.20,
    'behavior': 0.30,
}

DEFAULT_THRESHOLDS = {
    'SAFE':       (0, 29),
    'LOW_MEDIUM': (30, 59),
    'HIGH':       (60, 79),
    'CRITICAL':   (80, 100),
}

LEVEL_LABELS = {
    'SAFE':       'SAFE',
    'LOW_MEDIUM': 'LOW/MEDIUM RISK',
    'HIGH':       'HIGH RISK',
    'CRITICAL':   'CRITICAL / PHISHING',
}

PREVENTION_ACTION = {
    'SAFE':       'allow',
    'LOW_MEDIUM': 'warn',
    'HIGH':       'block',
    'CRITICAL':   'block',
}


def _risk_level(score: float, thresholds: Dict[str, tuple]) -> str:
    for level, (lo, hi) in thresholds.items():
        if lo <= score <= hi:
            return level
    return 'CRITICAL' if score > 100 else 'SAFE'


def compute_final_risk(
    url_ml_score: Optional[float],
    domain_score: Optional[float],
    visual_result: Optional[Dict[str, Any]],
    behavior_result: Optional[Dict[str, Any]],
    weights: Optional[Dict[str, float]] = None,
    thresholds: Optional[Dict[str, tuple]] = None,
) -> Dict[str, Any]:
    """
    Fuse the four signals into one explainable final verdict.

    Any signal that is None/unavailable is EXCLUDED from the score and its
    weight is redistributed proportionally across the remaining available
    signals — a failed module never silently contributes a fabricated 0.

    Returns:
      {
        'final_score':        float (0-100),
        'risk_level':         'SAFE' | 'LOW_MEDIUM' | 'HIGH' | 'CRITICAL',
        'risk_level_display': human label,
        'prevention_action':  'allow' | 'warn' | 'block',
        'signals': {
            'url_ml':   {'score': .., 'weight': .., 'available': bool},
            'domain':   {...},
            'visual':   {...},
            'behavior': {...},
        },
        'reasons': List[str],   # merged, deduped, human-readable
        'weights_used': dict,
      }
    """
    weights    = dict(weights or DEFAULT_WEIGHTS)
    thresholds = thresholds or DEFAULT_THRESHOLDS
    visual_result   = visual_result or {}
    behavior_result = behavior_result or {}

    raw_signals = {
        'url_ml':   url_ml_score,
        'domain':   domain_score,
        'visual':   visual_result.get('visual_score') if visual_result.get('available') else None,
        'behavior': behavior_result.get('behavior_score') if behavior_result.get('available') else None,
    }

    available = {k: v for k, v in raw_signals.items() if v is not None}

    if not available:
        # Every signal failed — cannot produce a meaningful score.
        return {
            'final_score': None,
            'risk_level': 'UNKNOWN',
            'risk_level_display': 'UNKNOWN — ANALYSIS UNAVAILABLE',
            'prevention_action': 'warn',
            'signals': {
                k: {'score': None, 'weight': 0.0, 'available': False} for k in raw_signals
            },
            'reasons': ['All risk-analysis modules were unavailable for this scan.'],
            'weights_used': {},
        }

    total_weight = sum(weights.get(k, 0) for k in available) or 1.0
    normalized_weights = {k: weights.get(k, 0) / total_weight for k in available}

    final_score = sum(available[k] * normalized_weights[k] for k in available)
    final_score = round(max(0.0, min(100.0, final_score)), 1)

    level = _risk_level(final_score, thresholds)

    reasons: List[str] = []
    if raw_signals['url_ml'] is not None and raw_signals['url_ml'] >= 40:
        reasons.append(f"Suspicious URL/ML risk signal ({raw_signals['url_ml']:.0f}/100)")
    if raw_signals['domain'] is not None and raw_signals['domain'] >= 40:
        reasons.append(f"Elevated domain risk ({raw_signals['domain']:.0f}/100) — WHOIS/SSL/age concerns")
    reasons.extend(visual_result.get('indicators', []) if visual_result.get('available') else [])
    reasons.extend(behavior_result.get('indicators', []) if behavior_result.get('available') else [])

    # Drop the filler "no indicators" strings from sub-modules if we already
    # have real reasons; keep them only when nothing else was found.
    real_reasons = [r for r in reasons if not r.lower().startswith('no ')]
    if real_reasons:
        reasons = real_reasons
    elif not reasons:
        reasons = ['No significant risk indicators detected across available signals.']

    seen = set()
    deduped_reasons = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            deduped_reasons.append(r)

    signals_out = {}
    for k, raw in raw_signals.items():
        signals_out[k] = {
            'score': raw,
            'weight': round(normalized_weights.get(k, 0.0), 3),
            'available': raw is not None,
        }

    return {
        'final_score': final_score,
        'risk_level': level,
        'risk_level_display': LEVEL_LABELS.get(level, level),
        'prevention_action': PREVENTION_ACTION.get(level, 'warn'),
        'signals': signals_out,
        'reasons': deduped_reasons,
        'weights_used': {k: round(v, 3) for k, v in normalized_weights.items()},
    }
