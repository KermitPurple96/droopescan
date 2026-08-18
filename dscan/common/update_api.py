from __future__ import print_function
try:
    from bs4 import BeautifulSoup
except:
    pass

from dscan.common.exceptions import MissingMajorException
from dscan.common.functions import version_gt
from dscan.common.versions import VersionsFile
from datetime import datetime, timedelta
import dscan
import dscan.common.functions as functions
import dscan.common.versions as v
import json
import os
import os.path
import re
import requests
import subprocess

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

GH = 'https://github.com/'
UW = './.update-workspace/'
OSV_API = 'https://api.osv.dev/v1/query'
JOOMLA_SECURITY_CENTRE = 'https://developer.joomla.org/security-centre.html'

def github_tags_get(github_repo):
    """
    Get all tag names from a github repository using `git ls-remote`, which
    does not require cloning the repository or scraping the (frequently
    changing) tags webpage.
    @param github_repo: the github repository, e.g. 'drupal/drupal/'.
    @return: a list of tag names.
    """
    github_repo = _github_normalize(github_repo)
    repo_url = '%s%s' % (GH, github_repo)

    output = subprocess.check_output(['git', 'ls-remote', '--tags', repo_url])
    if isinstance(output, bytes):
        output = output.decode()

    tags = []
    for line in output.split('\n'):
        line = line.strip()
        if not line:
            continue

        ref = line.split('\t')[-1]
        if not ref.startswith('refs/tags/'):
            continue

        tag = ref[len('refs/tags/'):]
        if tag.endswith('^{}'):
            tag = tag[:-len('^{}')]

        tags.append(tag)

    return tags

def _osv_summary(vuln):
    if vuln.get('summary'):
        return vuln['summary'].strip()

    details = vuln.get('details', '')
    header = re.search(r'^####\s*(.+)$', details, re.M)
    if header:
        return header.group(1).strip()

    return details.strip().split('\n')[0][:200]

def _osv_sa_id(vuln):
    for ref in vuln.get('references', []):
        match = re.search(r'/(sa-core-[\w-]+)', ref.get('url', ''), re.I)
        if match:
            return match.group(1).upper()

    return None

def _osv_cves(vuln):
    aliases = sorted(set(a for a in vuln.get('aliases', []) if a.startswith('CVE-')))
    if aliases:
        return aliases

    return sorted(set(re.findall(r'CVE-\d{4}-\d+', vuln.get('details', ''))))

def _osv_fallback_url(vuln):
    for ref in vuln.get('references', []):
        if ref.get('type') == 'ADVISORY':
            return ref['url']

    if vuln.get('references'):
        return vuln['references'][0]['url']

    return 'https://osv.dev/vulnerability/' + vuln['id']

def _osv_affected_ranges(vuln, package_name):
    ranges = set()
    for affected in vuln.get('affected', []):
        if affected.get('package', {}).get('name') != package_name:
            continue

        for rng in affected.get('ranges', []):
            introduced = None
            fixed = None
            for event in rng.get('events', []):
                if 'introduced' in event and event['introduced'] != '0':
                    introduced = event['introduced']
                if 'fixed' in event:
                    fixed = event['fixed']

            ranges.add((introduced, fixed))

    return ranges

def osv_vulnerabilities_get(package_name, ecosystem='Packagist'):
    """
    Fetches known vulnerabilities for a package from OSV.dev
    (https://osv.dev), normalises them and merges records which refer to the
    same upstream advisory (OSV frequently splits a single advisory into one
    bundling record plus one record per CVE).
    @param package_name: the package name as known to the ecosystem, e.g.
        'drupal/core'.
    @param ecosystem: the OSV ecosystem the package belongs to.
    @return: a list of dicts, each with keys 'id' (advisory id), 'summary',
        'cves' (list), 'url' and 'affected' (list of {'introduced', 'fixed'}).
    """
    resp = requests.post(OSV_API, json={
        'package': {'name': package_name, 'ecosystem': ecosystem}
    })
    resp.raise_for_status()
    vulns = resp.json().get('vulns', [])

    groups = defaultdict(list)
    for vuln in vulns:
        key = _osv_sa_id(vuln) or vuln['id']
        groups[key].append(vuln)

    merged = []
    for key, group in groups.items():
        ranges = set()
        cves = set()
        summaries = []
        for vuln in group:
            ranges |= _osv_affected_ranges(vuln, package_name)
            cves |= set(_osv_cves(vuln))
            summary = _osv_summary(vuln)
            if summary and summary not in summaries:
                summaries.append(summary)

        if not ranges:
            continue

        is_sa = key.startswith('SA-CORE')
        primary = next((vuln for vuln in group if vuln['id'].startswith('DRUPAL-CORE')), group[0])
        summary = _osv_summary(primary)
        if len(summaries) > 1 and not primary.get('summary'):
            summary = '; '.join(summaries[:5])

        merged.append({
            'id': key,
            'summary': summary,
            'cves': sorted(cves),
            'url': ('https://www.drupal.org/' + key.lower()) if is_sa
                else _osv_fallback_url(group[0]),
            'affected': [{'introduced': introduced, 'fixed': fixed}
                for introduced, fixed in sorted(ranges, key=lambda t: (t[0] or '', t[1] or ''))],
        })

    merged.sort(key=lambda vuln: vuln['id'])
    return merged

_JOOMLA_LINK_RE = re.compile(
        r'/security-centre/(\d+)-(\d{8})-(core|framework)-[a-z0-9-]+\.html')
_JOOMLA_VERSION_RE = r'\d+(?:\.\d+){1,3}(?:-[a-z]+\d*)?'
_JOOMLA_RANGE_RE = re.compile(
        r'(%s)\s*(?:-|through)\s*(%s)' % (_JOOMLA_VERSION_RE, _JOOMLA_VERSION_RE))
_JOOMLA_SINGLE_BRANCH_RE = re.compile(
        r'(%s)\s+and\s+all\s+(?:previous|earlier)' % _JOOMLA_VERSION_RE)

def _joomla_links_get(page_html):
    """
    @param page_html: HTML of a security-centre.html listing page.
    @return: a set of (id, date_code, href) tuples for 'core'/'framework'
        advisories linked from that page.
    """
    bs = BeautifulSoup(page_html, 'lxml')
    links = set()
    for a in bs.select('a[href*="/security-centre/"]'):
        match = _JOOMLA_LINK_RE.search(a.get('href', ''))
        if match:
            links.add((match.group(1), match.group(2), match.group(0)))

    return links

def _joomla_page_count(page_html):
    bs = BeautifulSoup(page_html, 'lxml')
    counter = bs.select_one('.com-content-category-blog__counter')
    if not counter:
        return 1

    match = re.search(r'Page \d+ of (\d+)', counter.get_text(strip=True))
    return int(match.group(1)) if match else 1

def _joomla_fields_get(body):
    fields = {}
    for li in body.select('ul > li'):
        strong = li.find('strong')
        if not strong:
            continue

        label = strong.get_text(strip=True).rstrip(':')
        fields[label] = li.get_text(strip=True)[len(strong.get_text(strip=True)):].strip()

    return fields

def _joomla_ranges_parse(versions_text, solution_text):
    """
    Parses the free-text 'Versions' (and, where needed, 'Solution') fields
    used by Joomla's security advisories into a list of {'introduced',
    'fixed'} dicts. The advisory template has changed over the years: modern
    advisories use clean comma-separated 'X.Y.Z-A.B.C' ranges, while older
    ones use prose such as '1.5.8 and all previous 1.5 releases'.
    @param versions_text: contents of the 'Versions' field.
    @param solution_text: contents of the 'Solution' field, used to recover
        an exact fixed version when the affected range is a prose fallback.
    @return: a list of {'introduced': str, 'fixed': str|None} dicts.
    """
    solution_versions = re.findall(_JOOMLA_VERSION_RE, solution_text or '')

    ranges = []
    for segment in versions_text.split(','):
        segment = segment.strip()
        if not segment:
            continue

        range_match = _JOOMLA_RANGE_RE.search(segment)
        if range_match:
            ranges.append([range_match.group(1), range_match.group(2)])
            continue

        branch_match = _JOOMLA_SINGLE_BRANCH_RE.search(segment)
        if branch_match:
            upper = branch_match.group(1)
            branch = '.'.join(upper.split('.')[0:2])
            ranges.append([branch + '.0', upper])
            continue

        single = re.findall(_JOOMLA_VERSION_RE, segment)
        if single:
            ranges.append([single[0], single[0]])

    affected = []
    for i, (introduced, upper) in enumerate(ranges):
        fixed = solution_versions[i] if i < len(solution_versions) else None
        if not fixed or not version_gt(fixed, introduced):
            # No reliable exact fixed version could be recovered (older
            # advisories don't always spell it out); fall back to treating
            # the upper bound of the affected range as (approximately) the
            # last vulnerable patch version.
            parts = re.split(r'(\d+)$', upper, maxsplit=1)
            if len(parts) == 3:
                fixed = parts[0] + str(int(parts[1]) + 1) + parts[2]
            else:
                fixed = None

        affected.append({'introduced': introduced, 'fixed': fixed})

    return affected

def _joomla_solution_get(body):
    header = body.find('h3', string=re.compile(r'Solution'))
    if not header:
        return None

    sibling = header.find_next_sibling()
    return sibling.get_text(' ', strip=True) if sibling else None

def _joomla_advisory_get(session, href):
    resp = session.get('https://developer.joomla.org' + href, timeout=30)
    resp.raise_for_status()

    bs = BeautifulSoup(resp.text, 'lxml')
    body = bs.select_one('.com-content-article__body')
    if not body:
        return None

    fields = _joomla_fields_get(body)
    versions_text = fields.get('Versions')
    if not versions_text:
        return None

    affected = _joomla_ranges_parse(versions_text, _joomla_solution_get(body))
    if not affected:
        return None

    title_el = bs.select_one('h2')
    summary = title_el.get_text(strip=True) if title_el else href

    cves = sorted(set(re.findall(r'CVE-\d{4}-\d+', fields.get('CVE Number', ''))))

    return {
        'summary': summary,
        'cves': cves,
        'url': 'https://developer.joomla.org' + href,
        'affected': affected,
    }

def joomla_security_centre_get(threads=8):
    """
    Scrapes the Joomla! Security Strike Team's advisory list
    (https://developer.joomla.org/security-centre.html) for all 'core' and
    'framework' advisories, since Joomla core vulnerabilities are barely
    represented in OSV.dev/GHSA (unlike Drupal, which has a dedicated feed).
    @param threads: how many advisory pages to fetch concurrently.
    @return: a list of dicts, each with keys 'id', 'summary', 'cves', 'url'
        and 'affected' (list of {'introduced', 'fixed'}), matching the
        format used by osv_vulnerabilities_get.
    """
    session = requests.Session()
    first_page = session.get(JOOMLA_SECURITY_CENTRE, timeout=30)
    first_page.raise_for_status()

    page_count = _joomla_page_count(first_page.text)

    links = _joomla_links_get(first_page.text)
    for start in range(25, page_count * 25, 25):
        page = session.get(JOOMLA_SECURITY_CENTRE, params={'start': start}, timeout=30)
        page.raise_for_status()
        links |= _joomla_links_get(page.text)

    def fetch(link):
        advisory_id, date_code, href = link
        try:
            advisory = _joomla_advisory_get(session, href)
        except requests.RequestException:
            return None

        if not advisory:
            return None

        advisory['id'] = 'JSST-%s' % date_code
        return advisory

    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = list(executor.map(fetch, sorted(links)))

    merged = {}
    for advisory in results:
        if not advisory:
            continue

        existing = merged.get(advisory['id'])
        if existing:
            existing['affected'].extend(advisory['affected'])
            existing['cves'] = sorted(set(existing['cves']) | set(advisory['cves']))
        else:
            merged[advisory['id']] = advisory

    return sorted(merged.values(), key=lambda vuln: vuln['id'])

def github_tags_newer(github_repo, versions_file, update_majors):
    """
    Get new tags from a github repository.
    @param github_repo: the github repository, e.g. 'drupal/drupal/'.
    @param versions_file: the file path where the versions database can be found.
    @param update_majors: major versions to update. If you want to update
        the 6.x and 7.x branch, you would supply a list which would look like
        ['6', '7']
    @return: a boolean value indicating whether an update is needed
    @raise MissingMajorException: A new version from a newer major branch is
        exists, but will not be downloaded due to it not being in majors.
    """
    vf = VersionsFile(versions_file)
    current_highest = vf.highest_version_major(update_majors)

    gh_versions = github_tags_get(github_repo)

    newer = _newer_tags_get(current_highest, gh_versions)

    return len(newer) > 0

def _tag_is_rubbish(tag, valid_version):
    """
    Returns whether a tag is "similar" to a valid version or whether it is
    rubbish.
    @param tag: the tag.
    @param valid_version: a valid version string for this CMS.
    @return: boolean.
    """
    return tag.count(".") != valid_version.count(".")

def _check_newer_major(current_highest, versions):
    """
    Utility function for checking whether a new version exists and is not going
    to be updated. This is undesirable because it could result in new versions
    existing and not being updated. Raising is prefering to adding the new
    version manually because that allows maintainers to check whether the new
    version works.
    @param current_highest: as returned by VersionsFile.highest_version_major()
    @param versions: a list of versions.
    @return: void
    @raise MissingMajorException: A new version from a newer major branch is
        exists, but will not be downloaded due to it not being in majors.
    """
    for tag in versions:
        update_majors = list(current_highest.keys())
        example_version_str = current_highest[update_majors[0]]
        if _tag_is_rubbish(tag, example_version_str):
            continue

        major = tag[0:len(update_majors[0])]
        if major not in current_highest:
            higher_version_present = False
            for major_highest in current_highest:
                if version_gt(major_highest, major):
                    higher_version_present = True
                    break

            if not higher_version_present:
                msg = 'Failed updating: Major %s has a new version and is not going to be updated.' % major
                raise MissingMajorException(msg)

def _newer_tags_get(current_highest, versions):
    """
    Returns versions from versions which are greater than than the highest
    version in each major. If a newer major is present in versions which is
    not present on current_highest, an exception will be raised.
    @param current_highest: as returned by VersionsFile.highest_version_major()
    @param versions: a list of versions.
    @return: a list of versions.
    @raise MissingMajorException: A new version from a newer major branch is
        exists, but will not be downloaded due to it not being in majors.
    """
    newer = []
    for major in current_highest:
        highest_version = current_highest[major]
        for version in versions:
            version = version.lstrip('v')
            if version.startswith(major) and version_gt(version,
                    highest_version):
                newer.append(version)

    _check_newer_major(current_highest, versions)

    return newer

def _github_normalize(github_repo):
    gr = github_repo.strip('/')
    return gr + "/"

def github_repo(github_repo, plugin_name):
    """
    Returns a GitRepo from a github repository after either cloning or fetching
    (depending on whether it exists)
    @param github_repo: the github repository path, e.g. 'drupal/drupal/'
    @param plugin_name: the current plugin's name (for namespace purposes).
    """
    github_repo = _github_normalize(github_repo)
    repo_url = '%s%s' % (GH, github_repo)

    gr = GitRepo(repo_url, plugin_name)
    gr.init()

    return gr

def github_repo_new(repo_url, plugin_name, versions_file, update_majors):
    """
    Convenience method which creates GitRepo and returns the created
    instance, as well as a VersionsFile and tags which need to be updated.
    @param repo_url: the github repository path, e.g. 'drupal/drupal/'
    @param plugin_name: the current plugin's name (for namespace purposes).
    @param versions_file: the path in disk to this plugin's versions.xml. Note
        that this path must be relative to the directory where the droopescan module
        is installed.
    @param update_majors: major versions to update. If you want to update
        the 6.x and 7.x branch, you would supply a list which would look like
        ['6', '7']
    @return: a tuple containing (GitRepo, VersionsFile, GitRepo.tags_newer()).
    The newer tags element may be empty if no new tags are found. While this
    theoretically should not happen, it happens in the particular case of
    Silverstripe's secondary framework repo.
    """
    gr = github_repo(repo_url, plugin_name)
    vf = v.VersionsFile(versions_file)
    new_tags = gr.tags_newer(vf, update_majors)

    return gr, vf, new_tags

def hashes_get(versions_file, base_path):
    """
    Gets hashes for currently checked out version.
    @param versions_file: a common.VersionsFile instance to check against.
    @param base_path: where to look for files. e.g. './.update-workspace/silverstripe/'
    @return: checksums {'file1': 'hash1'}
    """
    files = versions_file.files_get_all()
    result = {}
    for f in files:
        try:
            result[f] = functions.md5_file(base_path + f)
        except IOError:
            # Not all files exist for all versions.
            pass

    return result

def file_mtime(file_path):
    """
    Returns the file modified time. This is with regards to the last
    modification the file has had in the droopescan repo, rather than actual
    file modification time in the filesystem.
    @param file_path: file path relative to the executable.
    @return datetime.datetime object.
    """
    if not os.path.isfile(file_path):
        raise IOError('File "%s" does not exist.' % file_path)

    ut = subprocess.check_output(['git', 'log', '-1', '--format=%ct',
        file_path]).strip()

    return datetime.fromtimestamp(int(ut))

class PT():
    """
    Pagination types.

    Normal represents normal pagination, starts at page 0 and then 1, 2, 3
    and so on.

    Skip pagination represents paginations that require you to tell them how
    many elements to skip. They start at 0, and then 10, 20, 30 and so on,
    incrementing in per_page increments.
    """
    normal = 0
    skip = 1

def modules_get(url_tpl, per_page, css, max_modules=2000, pagination_type=PT.normal):
    """
    Gets a list of modules. Note that this function can also be used to get
    themes.
    @param url_tpl: a string such as
    https://drupal.org/project/project_module?page=%s. %s will be replaced with
    the page number.
    @param per_page: how many items there are per page.
    @param css: the elements matched by this selector will be returned by the
        iterator.
    @param max_modules: absolute maximum modules we will attempt to request.
    @param pagination_type: type of pagination. See the PaginationType enum
        for more information.
    @return: bs4.element.Tag
    @see: http://www.crummy.com/software/BeautifulSoup/bs4/doc/#css-selectors
    @see: http://www.crummy.com/software/BeautifulSoup/bs4/doc/#tag
    """
    page = 0
    elements = False
    done_so_far = 0

    max_potential_pages = max_modules / per_page
    print("Maximum pages: %s." % max_potential_pages)

    stop = False
    while elements == False or len(elements) == per_page:
        url = url_tpl % page

        r = requests.get(url)
        bs = BeautifulSoup(r.text, 'lxml')
        elements = bs.select(css)

        for element in elements:
            yield element
            done_so_far += 1

            if done_so_far >= max_modules:
                stop = True
                break

        if stop:
            break

        if pagination_type == PT.normal:
            print('Finished parsing page %s.' % page)
            page += 1
        elif pagination_type == PT.skip:
            print('Finished parsing page %s.' % (page / per_page))
            page += per_page
        else:
            assert False

def update_modules_check(plugin):
    """
    @param plugin: plugin instance to check.
    @return: True if it has been more than a year since last update or we have
        never updated.
    """
    today = datetime.today()
    try:
        mtime = file_mtime(plugin.plugins_file)
    except IOError:
        return True
    delta = today - mtime

    return delta > timedelta(days=365)

def multipart_parse_json(api_url, data):
    """
    Send a post request and parse the JSON response (potentially containing
    non-ascii characters).
    @param api_url: the url endpoint to post to.
    @param data: a dictionary that will be passed to requests.post
    """
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response_text = requests.post(api_url, data=data, headers=headers)\
        .text.encode('ascii', errors='replace')

    return json.loads(response_text.decode())

class GitRepo():
    """
    Base abstraction for working with git repositories.
    """

    _initialized = False
    _clone_url = None
    path = None

    def __init__(self, clone_url, plugin_name):
        """
        Default constructor.
        @param clone_url: the URL to clone the repo from.
        @param plugin_name: used to determine the clone location. The clone
            will be located at ./.update-workspace/<plugin_name>/. Slashes
            are permitted and will create subfolders.
        """
        self._clone_url = clone_url
        self.path = '%s%s/' % (UW, plugin_name)

    def init(self):
        """
        Performs a clone or a fetch, depending on whether the repository has
        been previously cloned or not.
        """
        if os.path.isdir(self.path):
            self.fetch()
        else:
            self.clone()

    def clone(self):
        """
        Clones a directory based on the clone_url and plugin_name given to the
        constructor. The clone will be located at self.path.
        """
        base_dir = '/'.join(self.path.split('/')[:-2])
        try:
            os.makedirs(base_dir, 0o700)
        except OSError:
            # Raises an error exception if the leaf directory already exists.
            pass

        self._cmd(['git', 'clone', self._clone_url, self.path], cwd=os.getcwd())

    def fetch(self):
        """
        Get objects and refs from a remote repository.
        """
        self._cmd(['git', 'fetch', '--all'])

    def tags_newer(self, versions_file, majors):
        """
        Checks this git repo tags for newer versions.
        @param versions_file: a common.VersionsFile instance to
            check against.
        @param majors: a list of major branches to check. E.g. ['6', '7']
        @raise MissingMajorException: A new version from a newer major branch is
            exists, but hasn't been downloaded due to it not being in majors.
        """
        highest = versions_file.highest_version_major(majors)
        all = self.tags_get()

        newer = _newer_tags_get(highest, all)

        return newer

    def tags_get(self):
        """
        @return: a list with all tags in this repository.
        """
        tags_content = subprocess.check_output(['git', 'tag'], cwd=self.path)
        if isinstance(tags_content, bytes):
            tags_content = tags_content.decode()
        tags = []
        for line in tags_content.split('\n'):
            tag = line.strip()
            if tag != '':
                tags.append(tag)

        return tags

    def tag_checkout(self, tag):
        """
        Checks out a tag.
        @param tag: the tag name.
        """
        self._cmd(['git', 'checkout', tag])

    def hashes_get(self, versions_file):
        """
        Gets hashes for currently checked out version.
        @param versions_file: a common.VersionsFile instance to
            check against.
        @return: sums {'file1':'hash1'}
        """
        return hashes_get(versions_file, self.path)

    def _cmd(self, *args, **kwargs):
        if 'cwd' not in kwargs:
            kwargs['cwd'] = self.path

        return_code = subprocess.call(*args, **kwargs)
        if return_code != 0:
            command = ' '.join(args[0])
            raise RuntimeError('Command "%s" failed with exit status "%s"' % (command, return_code))

