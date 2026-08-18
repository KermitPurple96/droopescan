from __future__ import print_function
from dscan.common.functions import version_gt
import json
import re

# Ordered so that the first matching category wins (e.g. an RCE achieved
# through path traversal is reported as RCE, the more actionable finding).
CATEGORIES = [
    ('RCE / Code execution', re.compile(r'remote code execution|code execution|deserializ|object injection', re.I)),
    ('SQL injection', re.compile(r'sql injection|\bsqli\b', re.I)),
    ('Authentication bypass / Privilege escalation', re.compile(r'privilege escalation|authentication bypass|auth.*bypass|access bypass|admin verification', re.I)),
    ('Path traversal / LFI', re.compile(r'path traversal|directory traversal|file inclusion|zip slip', re.I)),
    ('Access control / ACL', re.compile(r'\bacl\b|access control|access level', re.I)),
    ('CSRF', re.compile(r'\bcsrf\b|cross-site request forgery', re.I)),
    ('XSS', re.compile(r'\bxss\b|cross-site scripting|cross site scripting', re.I)),
    ('Information / path disclosure', re.compile(r'disclosure|exposure|leak', re.I)),
    ('Denial of Service', re.compile(r'denial of service|\bdos\b', re.I)),
]
OTHER_CATEGORY = 'Other'

# Categories severe enough to always call out individually in a summary,
# rather than just being counted.
CRITICAL_CATEGORIES = set([
    'RCE / Code execution',
    'SQL injection',
    'Authentication bypass / Privilege escalation',
])

def categorize(summary):
    """
    @param summary: a vulnerability's human-readable summary/title.
    @return: a rough category name, based on keyword matching. Best-effort;
        meant for grouping large result sets, not as an authoritative
        classification.
    """
    for name, pattern in CATEGORIES:
        if pattern.search(summary):
            return name

    return OTHER_CATEGORY

def group_by_category(vulns):
    """
    @param vulns: a list of vulnerability dicts (as returned by
        VulnerabilitiesFile.for_versions).
    @return: an OrderedDict-like list of (category, [vuln, ...]) tuples,
        sorted by number of vulnerabilities in the category, descending.
    """
    groups = {}
    for vuln in vulns:
        category = categorize(vuln['summary'])
        groups.setdefault(category, []).append(vuln)

    return sorted(groups.items(), key=lambda pair: len(pair[1]), reverse=True)

class VulnerabilitiesFile():
    """
    Loads a local database of known vulnerabilities for a CMS (as generated
    by dscan.common.update_api.osv_vulnerabilities_get) and matches installed
    versions against it.
    """

    vulnerabilities = None

    def __init__(self, json_file):
        """
        @param json_file: path to the JSON file.
        """
        with open(json_file) as f:
            data = json.load(f)

        self.vulnerabilities = data.get('vulnerabilities', [])

    def _version_affected(self, version, affected):
        for rng in affected:
            introduced = rng.get('introduced')
            fixed = rng.get('fixed')

            if introduced and version_gt(introduced, version):
                continue

            if fixed and not version_gt(fixed, version):
                continue

            return True

        return False

    def for_version(self, version):
        """
        @param version: a version string, e.g. '9.3.1'.
        @return: a list of vulnerability dicts (id, summary, cves, url,
            affected) that affect this version.
        """
        matches = []
        for vuln in self.vulnerabilities:
            if self._version_affected(version, vuln['affected']):
                matches.append(vuln)

        return matches

    def for_versions(self, versions):
        """
        @param versions: a list of version strings.
        @return: a list of vulnerability dicts affecting any of the given
            versions, sorted by id, without duplicates.
        """
        matches = {}
        for version in versions:
            for vuln in self.for_version(version):
                matches[vuln['id']] = vuln

        return sorted(matches.values(), key=lambda v: v['id'])
