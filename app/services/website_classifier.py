"""
AI Website Classifier — Step 1 of NEURAL-X v3 pipeline.

Determines website TYPE before any verification runs.
This prevents running journal checks on Crossref, OpenAlex, DOAJ, etc.

Classification categories:
    academic_database  — OpenAlex, Crossref, DOAJ, PubMed, Scopus, WoS
    journal            — An actual journal publication
    publisher          — Publishing house (Elsevier, Springer, Wiley…)
    university         — .edu / .ac.xx / named university
    conference         — Academic conference/symposium website
    repository         — arXiv, Zenodo, institutional repos
    government         — .gov / .gc.ca / official government sites
    research_org       — Research institutes, foundations (ROR)
    unknown            — Cannot classify with confidence

Each classification carries:
    - website_type (str)
    - display_name (str) — human-readable label
    - confidence (float 0-1) — fraction of rules that matched
    - evidence (List[str]) — specific signals that led to the decision
    - should_run_journal_checks (bool) — False for academic_database / publisher
    - positive_trust_signals (List[str])
"""

import re
import logging
import urllib.parse
from typing import Dict, Any, List, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known-entity lookup tables  (apex domain → (type, display_name))
# ---------------------------------------------------------------------------

KNOWN_ACADEMIC_DATABASES: Dict[str, str] = {
    'openalex.org':        'OpenAlex — Open Scholarly Graph',
    'crossref.org':        'Crossref — DOI Registration Agency',
    'doaj.org':            'DOAJ — Directory of Open Access Journals',
    'pubmed.ncbi.nlm.nih.gov': 'PubMed — NCBI/NIH Literature Database',
    'ncbi.nlm.nih.gov':    'NCBI — National Center for Biotechnology Information',
    'scopus.com':          'Scopus — Elsevier Abstract & Citation Database',
    'webofscience.com':    'Web of Science — Clarivate Analytics',
    'europepmc.org':       'Europe PMC — European PubMed Central',
    'semanticscholar.org': 'Semantic Scholar — AI-Powered Research Tool',
    'core.ac.uk':          'CORE — Open Access Research Aggregator',
    'base-search.net':     'BASE — Bielefeld Academic Search Engine',
    'lens.org':            'The Lens — Open Patent and Scholarly Search',
    'dimensions.ai':       'Dimensions — Digital Science Research Database',
    'sherpa.ac.uk':        'SHERPA — Research & Publisher Policies',
    'orcid.org':           'ORCID — Open Researcher & Contributor ID',
    'ror.org':             'ROR — Research Organization Registry',
    'isni.org':            'ISNI — International Standard Name Identifier',
    'worldcat.org':        'WorldCat — OCLC Library Catalog',
}

KNOWN_PUBLISHERS: Dict[str, str] = {
    'elsevier.com':          'Elsevier',
    'sciencedirect.com':     'ScienceDirect (Elsevier)',
    'springer.com':          'Springer Nature',
    'springerlink.com':      'SpringerLink',
    'nature.com':            'Nature Portfolio (Springer Nature)',
    'wiley.com':             'Wiley',
    'onlinelibrary.wiley.com': 'Wiley Online Library',
    'tandfonline.com':       'Taylor & Francis Online',
    'taylorandfrancis.com':  'Taylor & Francis Group',
    'sagepub.com':           'SAGE Publications',
    'oxford.com':            'Oxford University Press',
    'oxfordjournals.org':    'Oxford Academic Journals',
    'cambridge.org':         'Cambridge University Press',
    'ieee.org':              'IEEE — Institute of Electrical and Electronics Engineers',
    'ieeexplore.ieee.org':   'IEEE Xplore Digital Library',
    'acm.org':               'ACM — Association for Computing Machinery',
    'dl.acm.org':            'ACM Digital Library',
    'aps.org':               'American Physical Society',
    'rsc.org':               'Royal Society of Chemistry',
    'acs.org':               'American Chemical Society',
    'pubs.acs.org':          'ACS Publications',
    'ama-assn.org':          'American Medical Association',
    'jamanetwork.com':       'JAMA Network (AMA)',
    'bmj.com':               'BMJ Publishing Group',
    'thelancet.com':         'The Lancet (Elsevier)',
    'nejm.org':              'New England Journal of Medicine',
    'cell.com':              'Cell Press (Elsevier)',
    'sciencemag.org':        'Science (AAAS)',
    'science.org':           'Science (AAAS)',
    'pnas.org':              'PNAS (National Academy of Sciences)',
    'plos.org':              'PLOS',
    'plosone.org':           'PLOS ONE',
    'frontiersin.org':       'Frontiers Media',
    'mdpi.com':              'MDPI',
    'hindawi.com':           'Hindawi (Wiley)',
    'biomedcentral.com':     'BioMed Central (Springer Nature)',
    'royalsocietypublishing.org': 'The Royal Society Publishing',
    'apa.org':               'American Psychological Association',
    'informs.org':           'INFORMS',
    'iospress.com':          'IOS Press',
    'degruyter.com':         'De Gruyter',
    'karger.com':            'Karger Publishers',
    'thieme.com':            'Thieme Publishers',
    'lippincott.com':        'Lippincott Williams & Wilkins',
    'lww.com':               'Wolters Kluwer Health',
    'wolterskluwer.com':     'Wolters Kluwer',
}

KNOWN_REPOSITORIES: Dict[str, str] = {
    'arxiv.org':     'arXiv — Open-access preprint server (Cornell)',
    'biorxiv.org':   'bioRxiv — Biology preprints (Cold Spring Harbor)',
    'medrxiv.org':   'medRxiv — Medical preprints (Cold Spring Harbor)',
    'ssrn.com':      'SSRN — Social Science Research Network',
    'zenodo.org':    'Zenodo — Open science repository (CERN)',
    'figshare.com':  'Figshare — Research data repository',
    'osf.io':        'OSF — Open Science Framework',
    'github.com':    'GitHub — Code repository',
    'dspace.org':    'DSpace — Institutional repository platform',
    'eprints.org':   'EPrints — Open access repository software',
    'hal.science':   'HAL — French open archives',
    'researchgate.net': 'ResearchGate — Academic social network & repository',
    'academia.edu':  'Academia.edu — Academic social network',
    'ora.ox.ac.uk':  'ORA — Oxford University Research Archive',
    'philpapers.org':'PhilPapers — Philosophy research database',
}

KNOWN_GOVERNMENT: Dict[str, str] = {
    'nih.gov':       'NIH — National Institutes of Health (Government)',  # explicit
    'nlm.nih.gov':   'NLM — National Library of Medicine',
    'nsf.gov':       'NSF — National Science Foundation',
    'nasa.gov':      'NASA — National Aeronautics and Space Administration',
    'cdc.gov':       'CDC — Centers for Disease Control',
    'who.int':       'WHO — World Health Organization',
    'un.org':        'United Nations',
    'europa.eu':     'European Union',
    'ec.europa.eu':  'European Commission',
    'ukri.org':      'UKRI — UK Research & Innovation',
    'rcuk.ac.uk':    'Research Councils UK',
}

KNOWN_RESEARCH_ORGS: Dict[str, str] = {
    'cern.ch':        'CERN — European Organization for Nuclear Research',
    'wellcome.org':   'Wellcome Trust',
    'gatesfoundation.org': 'Bill & Melinda Gates Foundation',
    'openaire.eu':    'OpenAIRE',
    'sparc.arl.org':  'SPARC — Scholarly Publishing and Academic Resources Coalition',
    'oaspa.org':      'OASPA — Open Access Scholarly Publishers Association',
    'cope.org':       'COPE — Committee on Publication Ethics',
    'stm-assoc.org':  'STM Association',
    'niso.org':       'NISO — National Information Standards Organization',
}

# Keyword patterns for heuristic classification
_JOURNAL_URL_PATTERNS = [
    r'journal', r'review', r'jrnl', r'annals', r'bulletin',
    r'transactions', r'proceedings', r'letters', r'advances',
]
_CONF_URL_PATTERNS = [
    r'conference', r'conf\d{2,4}', r'symposium', r'congress',
    r'workshop', r'summit', r'\bsig\b',
]
_UNIV_URL_PATTERNS = [r'university', r'college', r'institute', r'school\b']
_UNIV_TLDS = ['.edu', '.ac.uk', '.ac.in', '.ac.jp', '.ac.za', '.ac.nz',
              '.ac.au', '.edu.au', '.edu.in', '.edu.pk']


def _apex(domain: str) -> str:
    parts = domain.rstrip('.').split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else domain


def _domain_from_url(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url if '://' in url else 'https://' + url)
        host = parsed.netloc.split(':')[0].lower().lstrip('www.')
        return host
    except Exception:
        return url.lower()


# ---------------------------------------------------------------------------
# Main classifier
# ---------------------------------------------------------------------------

def classify_website(url: str) -> Dict[str, Any]:
    """
    Classify a URL into a website type using rule-based lookup + heuristics.

    Returns:
        {
          website_type: str,
          display_name: str,
          confidence: float (0.0–1.0),
          evidence: List[str],
          positive_trust_signals: List[str],
          should_run_journal_checks: bool,
          is_known_safe: bool,
          organisation: str | None,
        }
    """
    domain = _domain_from_url(url)
    apex   = _apex(domain)
    url_l  = url.lower()

    evidence: List[str]       = []
    trust_signals: List[str]  = []
    matched_rules: int        = 0
    total_rules: int          = 0

    # ── Helper to count rule hits ──────────────────────────────────────────
    def hit(cond: bool, ev: str, trust: str = None):
        nonlocal matched_rules, total_rules
        total_rules += 1
        if cond:
            matched_rules += 1
            evidence.append(ev)
            if trust:
                trust_signals.append(trust)
        return cond

    # ── 1. Exact-match known entity tables ─────────────────────────────────
    for table, wtype, should_journal in [
        (KNOWN_ACADEMIC_DATABASES, 'academic_database', False),
        (KNOWN_PUBLISHERS,         'publisher',         False),
        (KNOWN_REPOSITORIES,       'repository',        False),
        (KNOWN_GOVERNMENT,         'government',        False),
        (KNOWN_RESEARCH_ORGS,      'research_org',      False),
    ]:
        for key, display in table.items():
            key_apex = _apex(key)
            if apex == key_apex or domain == key or domain.endswith('.' + key_apex):
                return {
                    'website_type':            wtype,
                    'display_name':            display,
                    'confidence':              0.98,
                    'evidence':                [f'Exact match in NEURAL-X known-entity registry: {display}'],
                    'positive_trust_signals':  [
                        f'Domain is a recognised {wtype.replace("_"," ")}',
                        'Present in NEURAL-X curated trust registry',
                    ],
                    'should_run_journal_checks': should_journal,
                    'is_known_safe':           True,
                    'organisation':            display.split('—')[0].strip() if '—' in display else display,
                }

    # ── 2. TLD-based university detection ─────────────────────────────────
    is_edu_tld = any(domain.endswith(t) or f'{t}/' in url_l for t in _UNIV_TLDS)
    hit(is_edu_tld, f'Domain uses academic TLD ({domain})',
        'Academic institution TLD (.edu / .ac.xx)')

    is_gov_tld = domain.endswith('.gov') or domain.endswith('.mil') or '.gov.' in domain
    hit(is_gov_tld, 'Domain uses government TLD (.gov / .mil)', 'Government domain TLD')

    # ── 3. Keyword patterns ────────────────────────────────────────────────
    has_journal_kw  = any(re.search(p, domain + url_l) for p in _JOURNAL_URL_PATTERNS)
    has_conf_kw     = any(re.search(p, domain + url_l) for p in _CONF_URL_PATTERNS)
    has_univ_kw     = any(re.search(p, domain)         for p in _UNIV_URL_PATTERNS) or is_edu_tld

    hit(has_journal_kw, f'URL/domain contains journal-related keywords',
        'Journal-type keywords in URL')
    hit(has_conf_kw, f'URL/domain contains conference-related keywords',
        'Conference-type keywords in URL')
    hit(has_univ_kw, f'URL/domain contains university/college keywords',
        'University-type keywords in URL')

    # ── 4. Decide classification from signals ──────────────────────────────
    if is_gov_tld:
        wtype, display, should_journal = 'government', 'Government / Official Agency', False
    elif is_edu_tld or (has_univ_kw and not has_journal_kw):
        wtype, display, should_journal = 'university', 'University / Educational Institution', False
    elif has_conf_kw:
        wtype, display, should_journal = 'conference', 'Academic Conference / Symposium', True
    elif has_journal_kw:
        wtype, display, should_journal = 'journal', 'Academic Journal', True
    else:
        wtype, display, should_journal = 'unknown', 'Unknown Website', True

    confidence = round(matched_rules / max(total_rules, 1), 2)
    # Minimum confidence for keyword matches
    if matched_rules > 0:
        confidence = max(confidence, 0.45)

    return {
        'website_type':            wtype,
        'display_name':            display,
        'confidence':              confidence,
        'evidence':                evidence,
        'positive_trust_signals':  trust_signals,
        'should_run_journal_checks': should_journal,
        'is_known_safe':           False,
        'organisation':            None,
    }
