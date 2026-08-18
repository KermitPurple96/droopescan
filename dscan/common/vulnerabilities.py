from __future__ import print_function
from dscan.common.functions import version_gt
import json

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
