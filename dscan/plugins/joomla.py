from cement.core import handler, controller
from dscan.common.update_api import GitRepo
from dscan.plugins import BasePlugin
import dscan.common.update_api as ua
import dscan.common.versions
import re
import requests

class Joomla(BasePlugin):
    can_enumerate_plugins = False
    can_enumerate_themes = False

    forbidden_url = "media/"
    regular_file_url = "media/system/js/validate.js"
    module_common_file = ""

    # Since Joomla 4.0, the CMS' front-end assets were rewritten (webpack
    # build, no more plain media/system/js/*), so none of the files
    # fingerprinted above (nor in versions.xml) exist any more. This
    # manifest, however, has reliably shipped with an explicit <version>
    # tag since at least Joomla 2.5, so it is used as a fallback for both
    # CMS identification and version detection.
    manifest_url = "administrator/manifests/files/joomla.xml"

    update_majors = ['1.5','1.6','1.7', '2.5', '3.0', '3.1', '3.2', '3.3',
            '3.4', '3.5', '3.6', '3.7', '3.8', '3.9', '3.10', '4.0', '4.1',
            '4.2', '4.3', '4.4', '5.0', '5.1', '5.2', '5.3', '5.4', '6.0',
            '6.1', '6.2']

    interesting_urls = [
        ("joomla.xml", "This CMS' default changelog."),
        ("administrator/manifests/files/joomla.xml", "Detailed version information."),
        ("administrator/", "Login page."),
        ("libraries/simplepie/README.txt", "SimplePie README."),
        ("LICENSE.txt", "License file."),
        ("plugins/system/cache/cache.xml", "Version attribute contains approx version"),
        ("README.txt", "Default readme file."),
        ("htaccess.txt", "Default .htaccess not renamed/enabled - recommended hardening not applied."),
        ("web.config.txt", "Default web.config not renamed/enabled - recommended hardening not applied."),
        ("robots.txt.dist", "Default robots.txt not renamed - recommended hardening not applied."),
        ("installation/", "Installer left in place - allows a full reinstall/takeover if reachable."),
        ("configuration.php.bak", "Backup of configuration.php - may leak DB credentials."),
        ("configuration.php~", "Editor backup of configuration.php - may leak DB credentials."),
        ("configuration.php.old", "Backup of configuration.php - may leak DB credentials."),
        ("configuration.php.save", "Backup of configuration.php - may leak DB credentials."),
    ]

    interesting_module_urls = [
    ]

    class Meta:
        # The label is important, choose the CMS name in lowercase.
        label = 'joomla'

    # This function is the entry point for the CMS.
    @controller.expose(help='joomla related scanning tools')
    def joomla(self):
        self.plugin_init()

    def enumerate_version_manifest(self, url, timeout=15, headers={}):
        """
        Reads the exact version straight out of the files_joomla update
        manifest, which (unlike the hash-fingerprinted files) is still
        present and accurate on Joomla 4/5/6.
        @param url: the installation's base URL.
        @param timeout: the number of seconds to wait prior to a timeout.
        @param headers: a dictionary to pass to requests.get()
        @return: the version string, or None if it could not be determined.
        """
        try:
            resp = self.session.get(url + self.manifest_url, timeout=timeout,
                    headers=headers)
        except requests.RequestException:
            return None

        if resp.status_code != 200:
            return None

        match = re.search(r'<version>([^<]+)</version>', resp.text)
        return match.group(1).strip() if match else None

    def enumerate_version(self, url, threads=10, verb='head', timeout=15,
            hide_progressbar=False, headers={}):
        version, is_empty = super(Joomla, self).enumerate_version(url,
                threads=threads, verb=verb, timeout=timeout,
                hide_progressbar=hide_progressbar, headers=headers)

        if is_empty:
            manifest_version = self.enumerate_version_manifest(url,
                    timeout=timeout, headers=headers)
            if manifest_version:
                return [manifest_version], False

        return version, is_empty

    def cms_identify(self, url, timeout=15, headers={}):
        is_cms = super(Joomla, self).cms_identify(url, timeout=timeout,
                headers=headers)

        if not is_cms:
            is_cms = self.enumerate_version_manifest(url, timeout=timeout,
                    headers=headers) is not None

        return is_cms

    def update_version_check(self):
        """
        @return: True if new tags have been made in the github repository.
        """
        return ua.github_tags_newer('joomla/joomla-cms/', self.versions_file,
                update_majors=self.update_majors)

    def update_version(self):
        """
        @return: updated VersionsFile
        """
        gr, versions_file, new_tags = ua.github_repo_new('joomla/joomla-cms/',
                'joomla/joomla-cms/', self.versions_file, self.update_majors)

        hashes = {}
        for version in new_tags:
            if 'alpha' in version or 'beta' in version:
                print("Skipping alpha or beta version %s" % version)
                continue 

            gr.tag_checkout(version)
            hashes[version] = gr.hashes_get(versions_file)

        versions_file.update(hashes, gr.tags_dates_get())
        return versions_file

    def update_plugins_check(self):
        return False

    def update_plugins(self):
        pass

    def update_vulnerabilities(self):
        """
        @return: a list of known vulnerabilities, as returned by
            ua.joomla_security_centre_get.
        """
        return ua.joomla_security_centre_get()

def load(app=None):
    handler.register(Joomla)

