import sys
import platform
import subprocess
import os
import requests
import argparse
import json
import glob
import hashlib
import zipfile
import re
import shutil
import random
from zipfile import ZIP_DEFLATED
from pprint import pprint
from github import Github
import networkx as nx

from blackduck import Client

def line_num_for_phrase_in_file(phrase, filename):
    try:
        with open(filename,'r') as f:
            for (i, line) in enumerate(f):
                if phrase.lower() in line.lower():
                    return i
    except:
        return -1
    return -1

def remove_cwd_from_filename(path):
    cwd = os. getcwd()
    cwd = cwd + "/"
    new_filename = path.replace(cwd, "")
    return new_filename

def github_create_pull_request_comment(g, github_repo, pr, pr_commit, fix_pr_node):
    if (debug): print(f"DEBUG: Look up GitHub repo '{github_repo}'")
    repo = g.get_repo(github_repo)
    if (debug): print(repo)

    body = f'''
Synopsys Black Duck found the following vulerabilities in the component {fix_pr_node['componentName']}:

'''
    body = body + "\n".join(fix_pr_node['comments'])

    if (debug): print(f"DEBUG: Get issue for pull request #{pr.number}")
    issue = repo.get_issue(number = pr.number)
    if (debug): print(issue)

    if (debug): print(f"DEBUG: Create pull request review comment for pull request #{pr.number} with the following body:\n{body}")
    issue.create_comment(body)

def github_commit_file_and_create_fixpr(g, github_token, github_api_url, github_repo, github_branch, fix_pr_filename, local_filename, fix_pr_node):
    if (debug): print(f"DEBUG: Look up GitHub repo '{github_repo}'")
    repo = g.get_repo(github_repo)
    if (debug): print(repo)

    if (debug): print(f"DEBUG: Get HEAD commit from '{github_repo}'")
    commit = repo.get_commit('HEAD')
    if (debug): print(commit)

    new_branch_seed = '%030x' % random.randrange(16**30)
    #new_branch_seed = secrets.token_hex(15)
    new_branch_name = github_branch + "-snps-fix-pr-" + new_branch_seed
    if (debug): print(f"DEBUG: Create branch '{new_branch_name}'")
    ref = repo.create_git_ref("refs/heads/" + new_branch_name, commit.sha)
    if (debug): print(ref)

    fix_comments = "\n".join(fix_pr_node['comments'])
    commit_message = f"Update {fix_pr_node['componentName']} to fix the following known security vulnerabilities:\n\n" + fix_comments

    if (debug): print(f"DEBUG: Get SHA for file '{fix_pr_filename}'")
    file = repo.get_contents(fix_pr_filename)

    if (debug): print(f"DEBUG: Upload file '{fix_pr_filename}'")
    try:
        with open(local_filename, 'r') as fp:
            file_contents = fp.read()
    except:
        print(f"ERROR: Unable to open package file '{local_filename}'")
        sys.exit(1)

    if (debug): print(f"DEBUG: Update file '{fix_pr_filename}' with commit message '{commit_message}'")
    file = repo.update_file(fix_pr_filename, commit_message, file_contents, file.sha, branch=new_branch_name)

    pr_body = f'''
Pull request submitted by Synopsys Black Duck to upgrade {fix_pr_node['componentName']} from version {fix_pr_node['versionFrom']} to {fix_pr_node['versionTo']} in order to fix the known security vulnerabilities:

'''
    pr_body = pr_body + "\n".join(fix_pr_node['comments'])
    if (debug):
        print(f"DEBUG: Submitting pull request:")
        print(pr_body)
    pr = repo.create_pull(title=f"Black Duck: Upgrade {fix_pr_node['componentName']} to version {fix_pr_node['versionTo']} fix known security vulerabilities", body=pr_body, head=new_branch_name, base="master")


def detect_package_file(package_files, component_identifier, component_name):
    ptype = component_identifier.split(':')[0]
    name_version = component_identifier.split(':')[1]
    name = name_version.split('/')[0]

    for package_file in package_files:
        line = line_num_for_phrase_in_file("\"" + name + "\"", package_file)
        if (line > 0):
            return package_file, line

    return "Unknown"

def generate_fix_pr_npmjs(filename, filename_local, component_name, version_from, version_to):
    try:
        with open(filename) as jsonfile:
            data = json.load(jsonfile)
    except:
        print(f"ERROR: Unable to open package file '{filename}'")
        sys.exit(1)

    # TODO Is it more correct to only upgrade to compatible versions according to semver?
    # That doesn't seem aggressive enough
    if (debug): print(f"DEBUG: Searching {filename} for component '{component_name}' ...")
    for dependency in data['dependencies'].keys():
        if (dependency == component_name):
            if (debug): print(f"DEBUG:   Found '{component_name}' and it is version '{data['dependencies'][dependency]}', change to version {version_to}")
            data['dependencies'][dependency] = "^" + version_to

    # Attempt to preserve NPM formatting by not sorting and using indent=2
    if (debug): print(f"DEBUG:   Writing changes to {filename_local}")
    try:
        with open(filename_local, "w") as jsonfile:
            json.dump(data, jsonfile, indent=2)
    except:
        print(f"ERROR: Unable to write package file '{filename_local}'")
        sys.exit(1)

    return filename, filename_local

def read_json_object(filepath):
    with open(filepath) as jsonfile:
        data = json.load(jsonfile)
        return data

def zip_extract_files(zip_file, dir_name):
    print("Extracting content of {} into {}".format(zip_file, dir_name))
    with zipfile.ZipFile(zip_file, 'r') as zip_ref:
        zip_ref.extractall(dir_name)

def bdio_read(bdio_in, inputdir):
    zip_extract_files(bdio_in, inputdir)
    filelist = os.listdir(inputdir)
    for filename in filelist:
        #print ("processing {}".format(filename))
        if (filename.startswith("bdio-entry")):
            filepath_in = os.path.join(inputdir, filename)
            data = read_json_object(filepath_in)
            return data
        
def get_comps(bd, pv):
    comps = bd.get_json(pv + '/components?limit=5000')
    newcomps = []
    complist = []
    for comp in comps['items']:
        if 'componentVersionName' not in comp:
            continue
        cname = comp['componentName'] + '/' + comp['componentVersionName']
        if comp['ignored'] is False and cname not in complist:
            newcomps.append(comp)
            complist.append(cname)
    return newcomps

def get_projver(bd, projname, vername):
    params = {
        'q': "name:" + projname,
        'sort': 'name',
    }
    projects = bd.get_resource('projects', params=params, items=False)
    if projects['totalCount'] == 0:
        return ''
    # projects = bd.get_resource('projects', params=params)
    for proj in projects['items']:
        versions = bd.get_resource('versions', parent=proj, params=params)
        for ver in versions:
            if ver['versionName'] == vername:
                return ver['_meta']['href']
    print("ERROR: Version '{}' does not exist in project '{}'".format(projname, vername))
    return ''

# Parse command line arguments
parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                description='Generate GitHub SARIF file from Black Duck Rapid Scan')
parser.add_argument('--debug', default=0, help='set debug level [0-9]')
parser.add_argument('--url', required=True, help='Black Duck Base URL')
parser.add_argument('--output_directory', required=True, help='Rapid Scan output directory')
parser.add_argument('--output', required=True, help='File to output SARIF to')
parser.add_argument('--upgrademajor', default=False, action='store_true', help='Upgrade beyond current major version')
parser.add_argument('--fixpr', default=False, action='store_true', help='Create Fix PR for upgrade guidance')
parser.add_argument('--comment', default=False, action='store_true', help='Comment on the pull request being scanned')
parser.add_argument('--allcomps', default=False, action='store_true', help='Report on ALL components, not just newly introduced')

args = parser.parse_args()

debug = int(args.debug)
bd_apitoken = os.getenv("BLACKDUCK_TOKEN")
if (bd_apitoken == None or bd_apitoken == ""):
    print("ERROR: Please set BLACKDUCK_TOKEN in environment before running")
    sys.exit(1)
bd_url = args.url
bd_rapid_output_dir = args.output_directory
upgrade_major = args.upgrademajor
sarif_output_file = args.output
fix_pr = args.fixpr
comment_pr = args.comment
allcomps = args.allcomps

fix_pr_annotation = ""

bd = Client(token=bd_apitoken,
        base_url=bd_url,
        timeout=300)

# Parse deetctor output
# blackduck-output-38280/runs/2021-10-30-14-17-33-881/status/status.json
bd_rapid_output_status_glob = glob.glob(bd_rapid_output_dir + "/runs/*/status/status.json")
if (len(bd_rapid_output_status_glob) == 0):
    print("ERROR: Unable to find output scan files in: " + bd_rapid_output_dir + "/runs/*/status/status.json")
    sys.exit(1)

bd_rapid_output_status = bd_rapid_output_status_glob[0]

print("INFO: Parsing Black Duck Rapid Scan output from " + bd_rapid_output_status)
with open(bd_rapid_output_status) as f:
    output_status_data = json.load(f)

if (debug): print(f"DEBUG: Status dump: " + json.dumps(output_status_data, indent=4))

detected_package_files = []
for detector in output_status_data['detectors']:
    # Reverse order so that we get the priority from detect
    for explanation in reversed(detector['explanations']):
        if (str.startswith(explanation, "Found file: ")):
            package_file = explanation[len("Found file: "):]
            if (os.path.isfile(package_file)):
                detected_package_files.append(package_file)
                if (debug): print(f"DEBUG: Explanation: {explanation} File: {package_file}")

# Find project name and version to use in looking up baseline data
project_baseline_name = output_status_data['projectName']
project_baseline_version = output_status_data['projectVersion']

print(f"INFO: Running for project '{project_baseline_name}' version '{project_baseline_version}'")

# Look up baseline data
pvurl = get_projver(bd, project_baseline_name, project_baseline_version)
baseline_comp_cache = dict()
if (not allcomps):
    if (pvurl == ''):
        print(f"WARN: Unable to find project '{project_baseline_name}' version '{project_baseline_version}' - will not present incremental results")
    else:
        if (debug): print(f"DEBUG: Project Version URL: {pvurl}")
        baseline_comps = get_comps(bd, pvurl)
        #if (debug): print(f"DEBUG: Baseline components=" + json.dumps(baseline_comps, indent=4))
        # TODO Should really cache the component Id not the Name
        for comp in baseline_comps:
            baseline_comp_cache[comp['componentName']] = comp['componentVersionName']
        #if (debug): print(f"DEBUG: Baseline component cache=" + json.dumps(baseline_comp_cache, indent=4))
        if (debug): print(f"DEBUG: Generated baseline component cache")

# Parse BDIO file into network graph
bd_rapid_output_bdio_glob = glob.glob(bd_rapid_output_dir + "/runs/*/bdio/*.bdio")
if (len(bd_rapid_output_bdio_glob) == 0):
    print("ERROR: Unable to find output scan files in: " + bd_rapid_output_dir + "/runs/*/bdio/*.bdio")
    sys.exit(1)

bd_rapid_output_bdio = bd_rapid_output_bdio_glob[0]

bd_rapid_output_bdio_dir = glob.glob(bd_rapid_output_dir + "/runs/*/bdio")[0]
# TODO is there a case where there would be more than one BDIO file?
bdio_data = bdio_read(bd_rapid_output_bdio, bd_rapid_output_bdio_dir)
if (debug):
    print(f"DEBUG: BDIO Dump: "+ json.dumps(bdio_data, indent=4))

# Construct dependency graph
G = nx.DiGraph()
#G.add_edges_from(
#            [('project', 'express-handlebars'), ('project', 'nodemailer'), ('express-handlebars', 'anotherone'), ('express-handlebars', 'handlebars')])

if (debug): print("DEBUG: Create dependency graph...")
# Save project for later so we can find the direct dependencies
projects = []
for node in bdio_data['@graph']:
    parent = node['@id']
    #G.add_edge("Project", parent)
    if (debug): print(f"DEBUG: Parent {parent}")

    nx_node = None

    if "https://blackducksoftware.github.io/bdio#hasDependency" in node:
        if (isinstance(node['https://blackducksoftware.github.io/bdio#hasDependency'], list)):
            for dependency in node['https://blackducksoftware.github.io/bdio#hasDependency']:
                child = dependency['https://blackducksoftware.github.io/bdio#dependsOn']['@id']
                if (debug): print(f"DEBUG:   Dependency on {child}")
                nx_node = G.add_edge(parent, child)
        else:
            child = node['https://blackducksoftware.github.io/bdio#hasDependency']['https://blackducksoftware.github.io/bdio#dependsOn']['@id']
            if (debug): print(f"DEBUG:   (2) Dependency on {child}")
            nx_node = G.add_edge(parent, child)

        if node['@type'] == "https://blackducksoftware.github.io/bdio#Project":
            projects.append(parent)
            if (debug): print(f"DEBUG:   Project name is {parent}")
            G.add_node(parent, project=1)
            #G.add_edge("Project", parent)
            #nx.set_node_attributes(nx_node, 1, "project")
    else:
        print("Parent")
        nx_node = G.add_node(parent)


if (len(projects) == 0):
    print("ERROR: Unable to find base project in BDIO file")
    sys.exit(1)

# Parse the Rapid Scan output, assuming there is only one run in the directory
bd_rapid_output_file_glob = glob.glob(bd_rapid_output_dir + "/runs/*/scan/*.json")
if (len(bd_rapid_output_file_glob) == 0):
    print("ERROR: Unable to find output scan files in: " + bd_rapid_output_dir + "/runs/*/scan/*.json")
    sys.exit(1)

bd_rapid_output_file = bd_rapid_output_file_glob[0]
print("INFO: Parsing Black Duck Rapid Scan output from " + bd_rapid_output_file)
with open(bd_rapid_output_file) as f:
    output_data = json.load(f)

developer_scan_url = output_data[0]['_meta']['href'] + "?limit=5000"
if (debug): print("DEBUG: Developer scan href: " + developer_scan_url)

# Handle limited lifetime of developer runs gracefully
try:
    dev_scan_data = bd.get_json(developer_scan_url)
except:
    print(f"ERROR: Unable to fetch developer scan '{developer_scan_url}' - note that these are limited lifetime and this process must run immediately following the rapid scan")
    raise

# TODO: Handle error if can't read file
if (debug): print("DEBUG: Developer scan data: " + json.dumps(dev_scan_data, indent=4) + "\n")

# Prepare SARIF output structures
runs = []
run = dict()

component_match_types = dict()
components = dict()

tool_rules = []
results = []

fix_pr_data = []

for item in dev_scan_data['items']:
    if (debug):
        print(f"DEBUG: Component: {item['componentIdentifier']}")

        # If comparing to baseline, look up in cache and continue if already exists
        if (not allcomps and item['componentName'] in baseline_comp_cache):
            if (item['versionName'] == baseline_comp_cache[item['componentName']]):
                print(f"DEBUG:   Skipping component {item['componentName']} version {item['versionName']} because it was already seen in baseline")
                continue

    # Is this a direct dependency?
    dependency_type = "Direct"

    # Track the root dependencies
    dependency_paths = []

    if (debug): print(f"DEBUG: Looking for {item['componentIdentifier']}")
    node_name = re.sub(":", "/", item['componentIdentifier'], 1)
    node_name = "http:" + node_name
    if (debug): print(f"DEBUG: Looking for {node_name}")
    #print(G.nodes)
    ans = nx.ancestors(G, node_name)
    ans_list = list(ans)
    if (debug): print(f"DEBUG:   Ancestors are: {ans_list}")
    pred = nx.DiGraph.predecessors(G, node_name)
    pred_list = list(pred)
    if (debug): print(f"DEBUG:   Predecessors are: {ans_list}")
    #n = G.get_node(node_name)
    #if (debug): print(f"DEBUG:   Parent is: {n.parent}")
    if (len(ans_list) != 1):
        dependency_type = "Transitive"

        # If this is a transitive dependency, what are the flows?
        for proj in projects:
            dep_paths = nx.all_simple_paths(G, source=proj, target=node_name)
            if (debug): print(f"DEBUG: Paths to '{node_name}'")
            paths = []
            for path in dep_paths:
                path_modified = path
                path_modified.pop(0)
                # Subtract http:<domain>/
                path_modified_trimmed = [re.sub(r'http\:.*?\/', '', path_name) for path_name in path_modified]
                # Change / to @
                path_modified_trimmed = [re.sub(r'\/', '@', path_name) for path_name in path_modified_trimmed]
                pathstr = " -> ".join(path_modified_trimmed)
                if (debug): print(f"DEBUG:   path={pathstr}")
                dependency_paths.append(pathstr)

    # Get component upgrade advice
    if (debug): print(f"DEBUG: Search for component '{item['componentIdentifier']}'")
    params = {
            'q': [ item['componentIdentifier'] ]
            }
    search_results = bd.get_items('/api/components', params=params)
    # There should be exactly one result!
    # TODO: Error checking?
    for result in search_results:
        component_result = result
    if (debug): print("DEBUG: Component search result=" + json.dumps(component_result, indent=4) + "\n")

    # Get component upgrade data
    if (debug): print(f"DBEUG: Looking up upgrade guidance for component '{component_result['componentName']}'")
    component_upgrade_data = bd.get_json(component_result['version'] + "/upgrade-guidance")
    if (debug): print("DEBUG: Compponent upgrade data=" + json.dumps(component_upgrade_data, indent=4) + "\n")

    upgrade_version = None
    if (upgrade_major):
        if ("longTerm" in component_upgrade_data.keys()):
            upgrade_version = component_upgrade_data['longTerm']['versionName']
    else:
        if ("shortTerm" in component_upgrade_data.keys()):
            upgrade_version = component_upgrade_data['shortTerm']['versionName']

    # TODO: Process BDIO file from blackduck output directory to build
    # dependency graph, use NetworkX for Python, locate package node and
    # then use networkx.DiGraph.predecessors to access parents.
    #
    # Use hub-rest-api-python/examples/bdio_update_project_name.py as
    # a reference.

    package_file, package_line = detect_package_file(detected_package_files, item['componentIdentifier'], item['componentName'])

    # Note the details for generating a fix pr
    ptype = item['componentIdentifier'].split(':')[0]
    name_version = item['componentIdentifier'].split(':')[1]
    name = name_version.split('/')[0]
    current_version = name_version.split('/')[1]
    if (dependency_type == "Direct" and upgrade_version != None):
        fix_pr_node = dict()
        fix_pr_node['componentName'] = name
        fix_pr_node['versionFrom'] = component_upgrade_data['versionName']
        fix_pr_node['versionTo'] = upgrade_version
        fix_pr_node['scheme'] = ptype
        fix_pr_node['filename'] = remove_cwd_from_filename(package_file)
        fix_pr_node['comments'] = []

    # Loop through polciy violations and append to SARIF output data
    for vuln in item['policyViolationVulnerabilities']:
        if (upgrade_version != None):
            message = f"* {vuln['name']} - {vuln['vulnSeverity']} severity vulnerability violates policy '{vuln['violatingPolicies'][0]['policyName']}': *{vuln['description']}* Recommended to upgrade to version {upgrade_version}. {dependency_type} dependency."

        else:
            message = f"* {vuln['name']} - {vuln['vulnSeverity']} severity vulnerability violates policy '{vuln['violatingPolicies'][0]['policyName']}': *{vuln['description']}* No upgrade available at this time. {dependency_type} dependency."

        if (dependency_type == "Direct"):
            message = message + f" Fix in package file '{remove_cwd_from_filename(package_file)}'"
        else:
            if (len(dependency_paths) > 0):
                message = message + f" Find dependency in {dependency_paths[0]}"

        print("INFO: " + message)

        # Save message to include in Fix PR
        if (dependency_type == "Direct" and upgrade_version != None):
            fix_pr_node['comments'].append(message)

        result = dict()
        result['ruleId'] = vuln['name']
        message = dict()
        message['text'] = f"This file introduces a {vuln['vulnSeverity']} severity vulnerability in {component_result['componentName']}."
        result['message'] = message
        locations = []
        loc = dict()
        loc['file'] = remove_cwd_from_filename(package_file)
        # TODO: Can we reference the line number in the future, using project inspector?
        loc['line'] = 1

        tool_rule = dict()
        tool_rule['id'] = vuln['name']
        shortDescription = dict()
        shortDescription['text'] = f"{vuln['name']} - {vuln['vulnSeverity']} severity vulnerability in {component_result['componentName']}"
        tool_rule['shortDescription'] = shortDescription
        fullDescription = dict()
        fullDescription['text'] = f"This file introduces a {vuln['vulnSeverity']} severity vulnerability in {component_result['componentName']}"
        tool_rule['fullDescription'] = fullDescription
        rule_help = dict()
        rule_help['text'] = ""
        if (upgrade_version != None):
            rule_help['markdown'] = f"**{vuln['name']}:** *{vuln['description']}*\n\nRecommended to upgrade to version {upgrade_version}.\n\n"
        else:
            rule_help['markdown'] = f"**{vuln['name']}:** *{vuln['description']}*\n\nNo upgrade available at this time.\n\n"

        if (dependency_type == "Direct"):
            rule_help['markdown'] = rule_help['markdown'] + f"Fix in package file '{package_file}'"
        else:
            if (len(dependency_paths) > 0):
                rule_help['markdown'] = rule_help['markdown'] + f" Find dependency in **{dependency_paths[0]}**."

        tool_rule['help'] = rule_help
        defaultConfiguration = dict()

        if (vuln['vulnSeverity'] == "CRITITAL" or vuln['vulnSeverity'] == "HIGH"):
            defaultConfiguration['level'] = "error"
        elif (vuln['vulnSeverity'] == "MEDIUM"):
            defaultConfiguration['level'] = "warning"
        else:
            defaultConfiguration['level'] = "note"

        tool_rule['defaultConfiguration'] = defaultConfiguration
        properties = dict()
        properties['tags'] = []
        tool_rule['properties'] = properties
        tool_rules.append(tool_rule)

        location = dict()
        physicalLocation = dict()
        artifactLocation = dict()
        artifactLocation['uri'] = loc['file']
        physicalLocation['artifactLocation'] = artifactLocation
        region = dict()
        region['startLine'] = loc['line']
        physicalLocation['region'] = region
        location['physicalLocation'] = physicalLocation
        locations.append(location)
        result['locations'] = locations

        # Calculate fingerprint using simply the CVE/BDSA - the scope is the project in GitHub, so this should be fairly accurate for identifying a unique issue.
        # Guidance from https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#preventing-duplicate-alerts-using-fingerprints
        # and https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.html#_Toc16012611
        partialFingerprints = dict()
        primaryLocationLineHash = hashlib.sha224(b"{vuln['name']}").hexdigest()
        partialFingerprints['primaryLocationLineHash'] = primaryLocationLineHash
        result['partialFingerprints'] = partialFingerprints

        results.append(result)

        if (dependency_type == "Direct" and upgrade_version != None):
            fix_pr_data.append(fix_pr_node)

run['results'] = results
runs.append(run)

tool = dict()
driver = dict()
driver['name'] = "Synopsys Black Duck"
driver['organization'] = "Synopsys"
driver['rules'] = tool_rules
tool['driver'] = driver
run['tool'] = tool

code_security_scan_report = dict()
code_security_scan_report['runs'] = runs
code_security_scan_report['$schema'] = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
code_security_scan_report['version'] = "2.1.0"
code_security_scan_report['runs'] = runs

if (debug):
    print("DEBUG: SARIF Data structure=" + json.dumps(code_security_scan_report, indent=4))
try:
    with open(sarif_output_file, "w") as fp:
        json.dump(code_security_scan_report, fp, indent=4)
except:
    print(f"ERROR: Unable to write to SARIF output file '{sarif_output_file}'")
    sys.exit(1)

# Optionally generate Fix PR

fix_pr_components = dict()
if (fix_pr and len(fix_pr_data) > 0):
    github_token = os.getenv("GITHUB_TOKEN")
    github_repo = os.getenv("GITHUB_REPOSITORY")
    github_branch = os.getenv("GITHUB_REF")
    github_api_url = os.getenv("GITHUB_API_URL")

    if (github_token == None or github_repo == None or github_branch == None or github_api_url == None):
        print("ERROR: Cannot find GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_REF and/or GITHUB_API_URL in the environment - are you running from a GitHub action?")
        sys.exit(1)

    if (debug): print(f"DEBUG: Connect to GitHub at {github_api_url}")
    g = Github(github_token, base_url=github_api_url)

    print("DEBUG: Generating Fix Pull Request")

    for fix_pr_node in fix_pr_data:
        if (debug): print(f"DEBUG:  Fix '{fix_pr_node['componentName']}' version '{fix_pr_node['versionFrom']}' in file '{fix_pr_node['filename']}' using scheme '{fix_pr_node['scheme']}' to version '{fix_pr_node['versionTo']}'")

        if (fix_pr_node['scheme'] == "npmjs"):
            # For safety
            shutil.copy2("package.json", "package-orig.json")
            fix_pr_filename, local_filename = generate_fix_pr_npmjs(fix_pr_node['filename'], fix_pr_node['filename'] + ".local", fix_pr_node['componentName'], fix_pr_node['versionFrom'], fix_pr_node['versionTo'])
            fix_pr_filename = remove_cwd_from_filename(fix_pr_filename)
            github_commit_file_and_create_fixpr(g, github_token, github_api_url, github_repo, github_branch, fix_pr_filename, local_filename, fix_pr_node)
        else:
            print(f"INFO: Generating a Fix PR for packages of type '{fix_pr_node['scheme']}' is not supported yet")

# Optionally comment on the pull request this is for

if (comment_pr and len(fix_pr_data) > 0):
    github_token = os.getenv("GITHUB_TOKEN")
    github_repo = os.getenv("GITHUB_REPOSITORY")
    github_ref = os.getenv("GITHUB_REF")
    github_api_url = os.getenv("GITHUB_API_URL")
    github_sha = os.getenv("GITHUB_SHA")

    if (github_token == None or github_repo == None or github_ref == None or github_api_url == None or github_sha == None):
        print("ERROR: Cannot find GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_REF, GTIHUB_SHA and/or GITHUB_API_URL in the environment - are you running from a GitHub action?")
        sys.exit(1)

    if (debug): print(f"DEBUG: Connect to GitHub at {github_api_url}")
    g = Github(github_token, base_url=github_api_url)

    if (debug): print(f"DEBUG: Look up GitHub repo '{github_repo}'")
    repo = g.get_repo(github_repo)
    if (debug): print(repo)

    if (debug): print(f"DEBUG: Look up GitHub ref '{github_ref}'")
    # Remove leading refs/ as the API will prepend it on it's own
    # Actually look pu the head not merge ref to get the latest commit so
    # we can find the pull request
    ref = repo.get_git_ref(github_ref[5:].replace("/merge", "/head"))
    if (debug):
        print(ref)

    # Look for this pull request by finding the first commit, and then looking for a
    # PR that matches
    # TODO Safe to assume that there are at least one commit?
    github_sha = ref.object.sha
    #for commit in ref:
    #    if (commit['object']['type'] == "commit"):
    #        github_sha = commit['object']['sha']
    #        break

    #if (github_sha == None):
    #    print(f"ERROR: Unable to find any commits for ref '{github_ref}'")
    #    sys.exit(1)

    print(f"DEBUG: Found Git sha {github_sha} for ref '{github_ref}'")

    # TODO Should this handle other bases than master?
    pulls = repo.get_pulls(state='open', sort='created', base='master', direction="desc")
    pr = None
    pr_commit = None
    if (debug): print(f"DEBUG: Pull requests:")
    pull_number_for_sha = 0
    for pull in pulls:
        if (debug): print(f"DEBUG: Pull request number: {pull.number}")
        # Can we find the current commit sha?
        commits = pull.get_commits()
        for commit in commits.reversed:
            if (debug): print(f"DEBUG:   Commit sha: " + str(commit.sha))
            if (commit.sha == github_sha):
                if (debug): print(f"DEBUG:     Found")
                pull_number_for_sha = pull.number
                pr = pull
                pr_commit = commit
                break
        if (pull_number_for_sha != 0): break

    if (pull_number_for_sha == 0):
        print(f"ERROR: Unable to find pull request for commit '{github_sha}'")
        sys.exit(1)

    for fix_pr_node in fix_pr_data:
        if (debug): print(f"DEUBG: Comment on Pull Request #{pr.number} for commit {github_sha} for component '{fix_pr_node['componentName']}'")
        github_create_pull_request_comment(g, github_repo, pr, pr_commit, fix_pr_node)

if (len(fix_pr_data) == 0):
    print(f"INFO: No new components found, nothing to report")
