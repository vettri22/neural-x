"""
Hybrid AI Threat Scoring Engine — v3
NEURAL-X AI Cyber Defense Platform

Combines: URL heuristics + reputation feeds + domain intelligence
          + journal/publisher verification + website classification
into a single explainable weighted confidence score.

Transparency contract:
  - score_basis always = 'heuristic-estimate'
  - Every sub-score is labelled with its evidence basis
  - Never claims validated ML accuracy
  - Verification conflicts surface in output
"""

import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Default weights (journal scan) ────────────────────────────────────────────
WEIGHTS_JOURNAL = {
    'url_heuristic':  0.20,
    'reputation':     0.15,
    'domain_intel':   0.20,
    'content':        0.20,
    'journal_rules':  0.25,
}

# ── Default weights (non-journal scan) ────────────────────────────────────────
WEIGHTS_URL = {
    'url_heuristic':  0.35,
    'reputation':     0.30,
    'domain_intel':   0.25,
    'content':        0.10,
    'journal_rules':  0.00,
}


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, v))


def _domain_sub_score(domain_info: Dict) -> Tuple[float, List[str]]:
    score, signals = 0.0, []
    age = domain_info.get('domain_age_days')
    ssl = domain_info.get('ssl', {})
    whois = domain_info.get('whois', {})

    if age is None:
        score += 30; signals.append('Unknown domain age')
    elif age < 30:
        score += 45; signals.append(f'Very new domain ({age} days)')
    elif age < 180:
        score += 25; signals.append(f'New domain ({age} days)')
    elif age < 365:
        score += 10; signals.append(f'Domain under 1 year ({age} days)')

    if not ssl.get('valid'):
        score += 25; signals.append('No valid SSL')
    elif ssl.get('days_remaining', 999) < 14:
        score += 10; signals.append(f'SSL expiring soon ({ssl.get("days_remaining")} days)')

    if not whois.get('available'):
        score += 15; signals.append('WHOIS unavailable')

    return _clamp(score), signals


def _reputation_sub_score(reputation: Dict) -> Tuple[float, List[str]]:
    score   = _clamp(reputation.get('reputation_score', 0.0))
    signals = list(reputation.get('risk_factors', []))
    return score, signals


def compute_hybrid_score(
    url_result:     Dict[str, Any],
    domain_info:    Dict[str, Any],
    reputation:     Dict[str, Any],
    journal_result: Optional[Dict[str, Any]] = None,
    content_score:  float = 0.0,
) -> Dict[str, Any]:
    """
    Unified hybrid threat score.

    If journal_result is provided, uses journal-tuned weights and incorporates:
      - journal_score (0-100 threat)
      - trust_dimensions breakdown
      - verification conflicts
      - website type classification

    Returns:
      final_score, phishing_probability, journal_authenticity,
      risk_category, sub_scores, weights_used, contributing_signals,
      explainability, conflicts, score_basis
    """
    weights = WEIGHTS_JOURNAL.copy() if journal_result else WEIGHTS_URL.copy()

    url_sub      = _clamp(url_result.get('threat_score', 0.0))
    rep_sub, rep_sigs  = _reputation_sub_score(reputation)
    dom_sub, dom_sigs  = _domain_sub_score(domain_info)
    content_sub  = _clamp(content_score)
    journal_sub  = _clamp(journal_result.get('journal_score', 0.0)) if journal_result else 0.0

    # If journal result comes with trust_dimensions, use publisher trust as content proxy
    if journal_result:
        dims = journal_result.get('trust_dimensions', {})
        if dims.get('content_quality') is not None:
            # Invert content quality to threat
            content_sub = _clamp(100.0 - dims['content_quality'])
        if dims.get('domain_trust') is not None:
            dom_sub = _clamp(100.0 - dims['domain_trust'])

    # No content data — redistribute weight
    if content_sub == 0.0 and weights.get('content', 0) > 0:
        extra = weights.pop('content')
        weights['url_heuristic']  = round(weights.get('url_heuristic', 0) + extra * 0.5, 3)
        weights['domain_intel']   = round(weights.get('domain_intel', 0)  + extra * 0.3, 3)
        weights['reputation']     = round(weights.get('reputation', 0)    + extra * 0.2, 3)

    final_score = (
        url_sub     * weights.get('url_heuristic', 0) +
        rep_sub     * weights.get('reputation', 0) +
        dom_sub     * weights.get('domain_intel', 0) +
        content_sub * weights.get('content', 0) +
        journal_sub * weights.get('journal_rules', 0)
    )
    final_score = _clamp(final_score)

    # For known-safe sites, floor the score
    if journal_result and journal_result.get('is_known_safe'):
        final_score = min(final_score, 5.0)

    phishing_prob = _clamp(url_sub * 0.55 + rep_sub * 0.45)
    journal_auth  = round(100.0 - journal_sub, 1) if journal_result else None

    # Risk category
    if final_score < 20:
        category = 'Safe'
    elif final_score < 45:
        category = 'Suspicious'
    elif final_score < 70:
        category = 'High Risk'
    else:
        category = 'Critical Threat'

    # Conflicts from journal result
    conflicts = journal_result.get('conflicts', []) if journal_result else []
    if conflicts and category == 'High Risk':
        category = 'Suspicious'   # conflict → can't confirm high risk

    # Aggregate signals (deduped)
    raw_sigs = (
        url_result.get('risk_factors', []) +
        rep_sigs + dom_sigs +
        (journal_result.get('risk_factors', []) if journal_result else [])
    )
    seen = set(); unique_sigs = []
    for s in raw_sigs:
        if s not in seen:
            seen.add(s); unique_sigs.append(s)

    # Trust dimensions from journal result (for display)
    trust_dims = {}
    if journal_result:
        trust_dims = journal_result.get('trust_dimensions', {})

    return {
        'final_score':          round(final_score, 1),
        'phishing_probability': round(phishing_prob, 1),
        'journal_authenticity': journal_auth,
        'risk_category':        category,
        'sub_scores': {
            'url_heuristic': round(url_sub, 1),
            'reputation':    round(rep_sub, 1),
            'domain_intel':  round(dom_sub, 1),
            'content':       round(content_sub, 1),
            'journal_rules': round(journal_sub, 1),
        },
        'trust_dimensions':  trust_dims,
        'weights_used':      {k: round(v, 3) for k, v in weights.items()},
        'contributing_signals': unique_sigs,
        'positive_signals':  journal_result.get('positive_signals', []) if journal_result else [],
        'conflicts':         conflicts,
        'website_type':      journal_result.get('website_type', '') if journal_result else '',
        'website_type_display': journal_result.get('website_type_display', '') if journal_result else '',
        'organisation':      journal_result.get('organisation', '') if journal_result else '',
        'country':           journal_result.get('country', '') if journal_result else '',
        'explainability':    _build_explanation(
            final_score, category, url_sub, rep_sub, dom_sub,
            journal_sub, journal_result, conflicts
        ),
        'score_basis': 'heuristic-estimate',
    }


def _build_explanation(score, category, url_sub, rep_sub, dom_sub,
                        journal_sub, journal_result, conflicts) -> str:
    parts = []
    wtype   = (journal_result or {}).get('website_type_display', '')
    org     = (journal_result or {}).get('organisation', '')
    is_safe = (journal_result or {}).get('is_known_safe', False)

    if wtype:
        parts.append(f'Website type: {wtype}.')
    if org:
        parts.append(f'Organisation: {org}.')

    if is_safe:
        parts.append('Recognised as a legitimate known platform — no threat indicators.')
        return ' '.join(parts)

    verdict_map = {
        'Safe':           'No significant threat indicators detected.',
        'Suspicious':     'Some suspicious signals detected — proceed with caution.',
        'High Risk':      'Multiple threat indicators detected — avoid interaction.',
        'Critical Threat':'Critical threat indicators — do not visit or interact.',
    }
    parts.append(verdict_map.get(category, ''))

    subs = [
        ('URL structure',       url_sub),
        ('Reputation feeds',    rep_sub),
        ('Domain intelligence', dom_sub),
        ('Journal rules',       journal_sub),
    ]
    dominant = max(subs, key=lambda x: x[1])
    if dominant[1] > 30:
        parts.append(f'Primary risk driver: {dominant[0]} ({dominant[1]:.0f}/100).')

    if journal_result:
        auth = 100.0 - journal_sub
        if auth > 80:
            parts.append(f'Journal authenticity: HIGH ({auth:.0f}/100).')
        elif auth > 55:
            parts.append(f'Journal authenticity: MODERATE ({auth:.0f}/100) — verify independently.')
        else:
            parts.append(f'Journal authenticity: LOW ({auth:.0f}/100) — likely predatory or fake.')

    if conflicts:
        parts.append(f'⚠ Verification conflict detected — results from different databases disagree.')

    parts.append(
        'All scores are heuristic estimates based on observable signals. '
        'Always verify independently.'
    )
    return ' '.join(parts)
