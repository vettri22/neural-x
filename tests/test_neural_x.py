<<<<<<< HEAD
"""
NEURAL-X Test Suite — v2
Tests all scan types including journal authenticity verification.
Run: pytest tests/ -v
"""

import json
import pytest
=======
"""NEURAL-X — Basic test suite"""

import pytest
import json
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
from app import create_app, db


@pytest.fixture
def app():
    app = create_app('testing')
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


<<<<<<< HEAD
# ── Smoke tests ──────────────────────────────────────────────────────────────

class TestHomePage:
    def test_homepage_loads(self, client):
        r = client.get('/')
        assert r.status_code == 200

    def test_scan_url_page(self, client):
        r = client.get('/scan/url')
        assert r.status_code == 200

    def test_scan_qr_page(self, client):
        r = client.get('/scan/qr')
        assert r.status_code == 200

    def test_scan_image_page(self, client):
        r = client.get('/scan/image')
        assert r.status_code == 200

    def test_scan_journal_page(self, client):
        """v2: journal verification page must exist."""
        r = client.get('/scan/journal')
        assert r.status_code == 200

    def test_history_page(self, client):
        r = client.get('/history/')
        assert r.status_code == 200

    def test_admin_page(self, client):
        r = client.get('/admin/')
        assert r.status_code == 200


# ── URL Analyzer unit tests ───────────────────────────────────────────────────

class TestURLAnalyzer:
    def test_safe_url(self):
        from app.services.url_analyzer import analyze_url
        r = analyze_url('https://www.google.com')
        assert 0 <= r['threat_score'] <= 100
        assert r['risk_category'] in ('Safe', 'Suspicious', 'High Risk', 'Critical Threat')

    def test_ip_url_scores_high(self):
        from app.services.url_analyzer import analyze_url
        r = analyze_url('http://192.168.1.1/login')
        assert r['threat_score'] >= 30

    def test_phishing_keywords(self):
        from app.services.url_analyzer import analyze_url
        r = analyze_url('http://paypal-verify-account-secure-login.xyz/update')
        assert r['threat_score'] > 20

    def test_result_structure(self):
        from app.services.url_analyzer import analyze_url
        r = analyze_url('https://example.com')
        assert 'threat_score' in r
        assert 'risk_category' in r
        assert 'risk_factors' in r
        assert 'recommendations' in r

    def test_score_capped(self):
        from app.services.url_analyzer import analyze_url
        r = analyze_url('http://192.168.1.1@paypal-secure-verify.xyz/login?update=1&confirm=1')
        assert r['threat_score'] <= 100


# ── Journal Analyzer unit tests ───────────────────────────────────────────────

class TestJournalAnalyzer:
    def test_result_structure(self):
        from app.services.journal_analyzer import analyze_journal
        r = analyze_journal('https://example.com')
        assert 'journal_score' in r
        assert 'authenticity_score' in r
        assert 'risk_category' in r
        assert 'risk_factors' in r
        assert 'recommendations' in r
        assert 'api_checks' in r
        assert 'content_findings' in r

    def test_score_range(self):
        from app.services.journal_analyzer import analyze_journal
        r = analyze_journal('https://example.com')
        assert 0 <= r['journal_score'] <= 100
        assert 0 <= r['authenticity_score'] <= 100

    def test_scores_inverse(self):
        from app.services.journal_analyzer import analyze_journal
        r = analyze_journal('https://example.com')
        assert abs(r['journal_score'] + r['authenticity_score'] - 100.0) < 1.0

    def test_is_journal_url(self):
        from app.services.journal_analyzer import is_journal_url
        assert is_journal_url('https://journal-of-science.com')
        assert is_journal_url('https://conference2025.org')
        assert not is_journal_url('https://amazon.com/product')

    def test_issn_pattern(self):
        from app.services.journal_analyzer import ISSN_PATTERN
        assert ISSN_PATTERN.search('ISSN 1234-5678')
        assert not ISSN_PATTERN.search('not an issn')

    def test_no_invented_scores(self):
        """Scores must never claim to be validated ML accuracy."""
        from app.services.journal_analyzer import analyze_journal
        r = analyze_journal('https://example.com')
        # score_basis is not required here, but if present it must be heuristic
        assert r.get('score_basis', 'heuristic-estimate') != 'validated-ml'


# ── Hybrid Scorer unit tests ──────────────────────────────────────────────────

class TestHybridScorer:
    def _dummy_url_result(self, score=30):
        return {
            'threat_score': score, 'risk_category': 'Suspicious',
            'risk_factors': ['test'], 'recommendations': [],
        }

    def _dummy_domain_info(self):
        return {'domain_age_days': 200, 'ssl': {'valid': True, 'days_remaining': 120}, 'whois': {'available': True}}

    def _dummy_reputation(self):
        return {'reputation_score': 20, 'risk_factors': []}

    def test_basic_output(self):
        from app.services.hybrid_scorer import compute_hybrid_score
        r = compute_hybrid_score(
            self._dummy_url_result(), self._dummy_domain_info(), self._dummy_reputation()
        )
        assert 'final_score' in r
        assert 'phishing_probability' in r
        assert 'risk_category' in r
        assert 'sub_scores' in r
        assert 'explainability' in r
        assert 'score_basis' in r

    def test_score_basis_is_heuristic(self):
        from app.services.hybrid_scorer import compute_hybrid_score
        r = compute_hybrid_score(
            self._dummy_url_result(), self._dummy_domain_info(), self._dummy_reputation()
        )
        assert r['score_basis'] == 'heuristic-estimate'

    def test_score_in_range(self):
        from app.services.hybrid_scorer import compute_hybrid_score
        r = compute_hybrid_score(
            self._dummy_url_result(score=80), self._dummy_domain_info(), self._dummy_reputation()
        )
        assert 0 <= r['final_score'] <= 100

    def test_with_journal_result(self):
        from app.services.hybrid_scorer import compute_hybrid_score
        jr = {'journal_score': 70, 'risk_category': 'High Risk', 'risk_factors': ['no ISSN']}
        r = compute_hybrid_score(
            self._dummy_url_result(), self._dummy_domain_info(),
            self._dummy_reputation(), journal_result=jr
        )
        assert r['journal_authenticity'] is not None
        assert abs(r['journal_authenticity'] - (100 - 70)) < 1.0


# ── API Endpoints ─────────────────────────────────────────────────────────────

class TestAPIEndpoints:
    def test_api_scan_url(self, client):
        r = client.post('/api/scan-url',
                        json={'url': 'https://example.com'},
                        content_type='application/json')
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data['status'] == 'success'
        assert 'threat_score' in data['data']

    def test_api_scan_url_missing_url(self, client):
        r = client.post('/api/scan-url', json={}, content_type='application/json')
        assert r.status_code == 400

    def test_api_scan_journal(self, client):
        """v2: journal API endpoint must exist and return expected keys."""
        r = client.post('/api/scan-journal',
                        json={'url': 'https://example.com'},
                        content_type='application/json')
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data['status'] == 'success'
        d = data['data']
        assert 'journal_score' in d
        assert 'authenticity_score' in d
        assert 'score_basis' in d
        assert d['score_basis'] == 'heuristic-estimate'

    def test_api_journal_check_get(self, client):
        r = client.get('/api/journal-check?url=https://example.com')
        assert r.status_code == 200
        data = json.loads(r.data)
        assert 'journal_score' in data['data']

    def test_api_stats(self, client):
        r = client.get('/api/stats')
        assert r.status_code == 200
        d = json.loads(r.data)['data']
        assert 'total_scans' in d
        assert 'journal' in d['by_type']

    def test_api_history(self, client):
        r = client.get('/api/history')
        assert r.status_code == 200
        d = json.loads(r.data)['data']
        assert 'items' in d
        assert 'total' in d


# ── Website Classifier tests (v3) ─────────────────────────────────────────────

class TestWebsiteClassifier:
    def test_openalex_is_academic_database(self):
        from app.services.website_classifier import classify_website
        r = classify_website('https://openalex.org')
        assert r['website_type'] == 'academic_database'
        assert r['should_run_journal_checks'] is False
        assert r['is_known_safe'] is True

    def test_crossref_is_academic_database(self):
        from app.services.website_classifier import classify_website
        r = classify_website('https://crossref.org')
        assert r['website_type'] == 'academic_database'
        assert r['is_known_safe'] is True

    def test_doaj_is_academic_database(self):
        from app.services.website_classifier import classify_website
        r = classify_website('https://doaj.org')
        assert r['website_type'] == 'academic_database'
        assert r['is_known_safe'] is True

    def test_elsevier_is_publisher(self):
        from app.services.website_classifier import classify_website
        r = classify_website('https://elsevier.com')
        assert r['website_type'] == 'publisher'
        assert r['is_known_safe'] is True
        assert r['should_run_journal_checks'] is False

    def test_springer_is_publisher(self):
        from app.services.website_classifier import classify_website
        r = classify_website('https://springer.com')
        assert r['website_type'] == 'publisher'

    def test_ror_is_academic_database(self):
        from app.services.website_classifier import classify_website
        r = classify_website('https://ror.org')
        assert r['website_type'] == 'academic_database'

    def test_arxiv_is_repository(self):
        from app.services.website_classifier import classify_website
        r = classify_website('https://arxiv.org')
        assert r['website_type'] == 'repository'
        assert r['is_known_safe'] is True

    def test_edu_tld_is_university(self):
        from app.services.website_classifier import classify_website
        r = classify_website('https://mit.edu')
        assert r['website_type'] == 'university'

    def test_gov_tld_is_government(self):
        from app.services.website_classifier import classify_website
        r = classify_website('https://nih.gov')
        assert r['website_type'] == 'government'
        assert r['is_known_safe'] is True

    def test_journal_keyword_detected(self):
        from app.services.website_classifier import classify_website
        r = classify_website('https://international-journal-of-science.xyz')
        assert r['website_type'] == 'journal'
        assert r['should_run_journal_checks'] is True

    def test_unknown_site(self):
        from app.services.website_classifier import classify_website
        r = classify_website('https://example.com')
        assert r['website_type'] == 'unknown'
        # should still allow journal checks on unknown sites
        assert r['should_run_journal_checks'] is True

    def test_result_has_required_keys(self):
        from app.services.website_classifier import classify_website
        r = classify_website('https://example.com')
        for key in ('website_type','display_name','confidence',
                    'evidence','positive_trust_signals',
                    'should_run_journal_checks','is_known_safe'):
            assert key in r, f'Missing key: {key}'

    def test_confidence_range(self):
        from app.services.website_classifier import classify_website
        for url in ['https://openalex.org','https://example.com','https://mit.edu']:
            r = classify_website(url)
            assert 0.0 <= r['confidence'] <= 1.0


# ── v3 Journal Analyzer tests ────────────────────────────────────────────────

class TestJournalAnalyzerV3:
    def test_known_safe_returns_early(self):
        from app.services.journal_analyzer import analyze_journal
        r = analyze_journal('https://openalex.org')
        assert r['is_known_safe'] is True
        assert r['journal_score'] <= 5.0
        assert r['risk_category'] == 'Safe'
        assert r['website_type'] == 'academic_database'

    def test_known_safe_has_no_risk_factors(self):
        from app.services.journal_analyzer import analyze_journal
        r = analyze_journal('https://crossref.org')
        assert len(r['risk_factors']) == 0

    def test_has_positive_signals(self):
        from app.services.journal_analyzer import analyze_journal
        r = analyze_journal('https://openalex.org')
        assert len(r.get('positive_signals', [])) > 0

    def test_has_trust_dimensions(self):
        from app.services.journal_analyzer import analyze_journal
        r = analyze_journal('https://example.com')
        assert 'trust_dimensions' in r
        dims = r['trust_dimensions']
        assert 'website_type' in dims
        assert 'publisher' in dims
        assert 'domain_trust' in dims

    def test_has_website_type(self):
        from app.services.journal_analyzer import analyze_journal
        r = analyze_journal('https://example.com')
        assert 'website_type' in r
        assert r['website_type'] in (
            'academic_database','publisher','university','government',
            'research_org','repository','journal','conference','unknown'
        )

    def test_conflicts_key_present(self):
        from app.services.journal_analyzer import analyze_journal
        r = analyze_journal('https://example.com')
        assert 'conflicts' in r
        assert isinstance(r['conflicts'], list)

    def test_score_basis_is_heuristic(self):
        from app.services.journal_analyzer import analyze_journal
        r = analyze_journal('https://example.com')
        assert r.get('score_basis') == 'heuristic-estimate'

    def test_not_verified_not_fake(self):
        """
        When external DBs return not_verified (connection issue),
        the journal must not be classified as Critical Threat on that basis alone.
        """
        from app.services.journal_analyzer import analyze_journal
        r = analyze_journal('https://example-legit-looking-journal.org')
        # Should not immediately jump to Critical Threat without positive evidence of fakeness
        # (exact category depends on domain age/ssl, but not_verified alone should not => Critical)
        api = r.get('api_checks', {})
        all_nv = all(db.get('status') in ('not_verified','disabled','skipped')
                     for db in api.values())
        if all_nv:
            assert r['risk_category'] != 'Critical Threat', (
                'Should not classify as Critical Threat when all DB checks are not_verified'
            )

    def test_api_v3_fields(self, client):
        r = client.post('/api/scan-journal',
                        json={'url': 'https://openalex.org'},
                        content_type='application/json')
        assert r.status_code == 200
        d = __import__('json').loads(r.data)['data']
        assert 'website_type' in d
        assert 'trust_dimensions' in d
        assert 'positive_signals' in d
        assert 'conflicts' in d
        assert 'classification_evidence' in d
        assert d['score_basis'] == 'heuristic-estimate'
        assert d['is_known_safe'] is True

    def test_api_v3_fields(self):
        """Standalone version without client fixture."""
        from app.services.journal_analyzer import analyze_journal
        r = analyze_journal('https://openalex.org')
        assert r['website_type'] == 'academic_database'
        assert r['trust_dimensions']['website_type'] >= 90
=======
# ── Route tests ────────────────────────────────────────────
def test_index(client):
    r = client.get('/')
    assert r.status_code == 200
    assert b'NEURAL-X' in r.data or b'neural' in r.data.lower()


def test_scan_url_get(client):
    r = client.get('/scan/url')
    assert r.status_code == 200


def test_scan_qr_get(client):
    r = client.get('/scan/qr')
    assert r.status_code == 200


def test_scan_image_get(client):
    r = client.get('/scan/image')
    assert r.status_code == 200


def test_history_get(client):
    r = client.get('/history/')
    assert r.status_code == 200


def test_admin_get(client):
    r = client.get('/admin/')
    assert r.status_code == 200


def test_api_stats(client):
    r = client.get('/api/stats')
    assert r.status_code == 200
    data = json.loads(r.data)
    assert data['status'] == 'success'
    assert 'total_scans' in data['data']


def test_api_history(client):
    r = client.get('/api/history')
    assert r.status_code == 200
    data = json.loads(r.data)
    assert data['status'] == 'success'


def test_api_scan_url_missing(client):
    r = client.post('/api/scan-url',
                    data=json.dumps({}),
                    content_type='application/json')
    assert r.status_code == 400


# ── Service unit tests ─────────────────────────────────────
def test_url_analyzer_safe():
    from app.services.url_analyzer import analyze_url
    result = analyze_url('https://www.google.com')
    assert result['threat_score'] < 45
    assert result['risk_category'] in ['Safe', 'Suspicious']


def test_url_analyzer_phishing():
    from app.services.url_analyzer import analyze_url
    result = analyze_url('http://paypal-secure-verify-account.tk/login?update=1')
    assert result['threat_score'] > 40


def test_url_analyzer_ip():
    from app.services.url_analyzer import analyze_url
    result = analyze_url('http://192.168.1.1/login')
    assert result['threat_score'] >= 30


def test_qr_classifier_url():
    from app.services.qr_analyzer import classify_qr_content
    r = classify_qr_content('https://www.example.com')
    assert r['content_type'] == 'url'
    assert r['is_url'] is True


def test_qr_classifier_wifi():
    from app.services.qr_analyzer import classify_qr_content
    r = classify_qr_content('WIFI:S:MyNetwork;T:WPA;P:mypassword;;')
    assert r['content_type'] == 'wifi'


def test_qr_classifier_phone():
    from app.services.qr_analyzer import classify_qr_content
    r = classify_qr_content('tel:+1234567890')
    assert r['content_type'] == 'phone'


def test_qr_classifier_email():
    from app.services.qr_analyzer import classify_qr_content
    r = classify_qr_content('mailto:test@example.com')
    assert r['content_type'] == 'email'


def test_qr_classifier_text():
    from app.services.qr_analyzer import classify_qr_content
    r = classify_qr_content('Hello, World!')
    assert r['content_type'] == 'text'
    assert r['is_url'] is False


def test_domain_extract():
    from app.services.domain_intel import extract_domain
    assert extract_domain('https://www.example.com/path') == 'example.com'
    assert extract_domain('http://sub.domain.co.uk') == 'domain.co.uk'


def test_classify_risk():
    from app.services.url_analyzer import classify_risk
    assert classify_risk(10) == 'Safe'
    assert classify_risk(30) == 'Suspicious'
    assert classify_risk(55) == 'High Risk'
    assert classify_risk(80) == 'Critical Threat'
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
