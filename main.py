#!/usr/bin/env python3.9
# This script helps to resize multiple VM in vRA at once and we can leverage this
# to play with all the actions that we can perform for a VM by vRA
# But I am focusing here in Just resizing as this would be the place
# where we play with vRA for multiple machine at once

import argparse
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import re
import getpass
import threading
import time
import sys

# The VRA_URL is the base URL for the VMware vRealize Automation (vRA) platform.
VRA_URL = 'https://vra101.corp.com/' # Replace with your proper vRA base url

# The API_TOKEN_URL is the API endpoint to obtain an refresh token for the vRA platform.
API_TOKEN_URL = 'csp/gateway/am/api/login?access_token'

# The ACCESS_TOKEN_URL is the API endpoint to obtain an access token for the vRA platform.
ACCESS_TOKEN_URL = 'iaas/api/login'

# The CATALOG_URL is the API endpoint to obtain information about catalog items in the vRA platform.
CATALOG_URL = 'catalog/api/items'

# The DEPLOYMENT_URL is the API endpoint to obtain information about deployments in the vRA platform.
DEPLOYMENT_URL = 'deployment/api/deployments'

# The RESOURCE_URL is the API endpoint to obtain information about resources in the vRA platform.
RESOURCE_URL = 'deployment/api/resources'

# The session object is created to make HTTP requests to the vRA platform with the headers set to JSON.
# We will be using same session object for fetching all tokens so declaring it global
session = requests.Session()
session.headers.update({'Content-Type': 'application/json'})

# Function to obtain refresh token from VRA server.
def get_refresh_token(username: str, password: str):
    try:
        response = session.post(f"{VRA_URL}{API_TOKEN_URL}", json={'username': username, 'password': password}, verify=False)
        response.raise_for_status()
        return response.json()['refresh_token']
    except Exception as err:
        print_error(f'Error obtaining request token : {err}')
        return None

# Retrieves an access token from vRealize Automation using a refresh token.
def get_access_token(refresh_token: str):
    try:
        response = session.post(f"{VRA_URL}{ACCESS_TOKEN_URL}", json={'refreshToken': refresh_token}, verify=False)
        response.raise_for_status()
        return response.json()['token']
    except Exception as err:
        print_error(f'Error obtaining access token : {err}')
        return None

# Gets the list of catalog items available in VRA.
def get_catalog_items(access_token: str):
    try:
        response = session.get(f"{VRA_URL}{CATALOG_URL}", headers={'Authorization': f'Bearer {access_token}'}, verify=False)
        response.raise_for_status()
        content = response.json()['content']
        catalog_items = []
        for catalog in content:
            for projectid in catalog['projectIds']:
                catalog_item = {
                    'id': catalog['id'],
                    'name': catalog['name'],
                    'projectId': projectid,
                }
                catalog_items.append(catalog_item)
        return catalog_items

    except Exception as err:
        print_error(f'Error getting catalog items : {err}')
        return None

# Resize a compute resource of a specific deployment using the specified payload and access token.
def resize(deployment_id: str, compute_resource_id: str, payload: dict, access_token: str):
    headers = {'Authorization': f'Bearer {access_token}'}
    url = f'{VRA_URL}{DEPLOYMENT_URL}/{deployment_id}/resources/{compute_resource_id}/requests'
    response = requests.post(url, json=payload, headers=headers, verify=False)
    response.raise_for_status()
    return response.json()

# Retrieves a list of deployments for the matched server names, owned by the specified user, or vrasystembuilder
# with details such as name, created date, status, expiration, and expense.
def get_deployments(access_token, user, servers):
    matched = []
    username = user
    servers_regex='|'.join(servers);

    try:
        response = requests.get(
            # The max for $top is capped at 200 by API, value above that still only returns 200 deployments.
            # resourceTypes filter doesn't seem to work at limiting resource returned.
            f"{VRA_URL}{DEPLOYMENT_URL}?ownedBy={username},vrasystembuilder&expand=resources&resourceTypes=Cloud.vSphere.Machine&search={servers_regex}&$top=200&$orderby=name",
            headers={"Authorization": f"Bearer {access_token}"},
            verify=False
        )
        response.raise_for_status()
        if 'content' in response.json():
            servername=None
            serverid=None
            for deployment in response.json()['content']:
                for resource in deployment['resources']:
                    if resource['type'] == 'Cloud.vSphere.Machine':
                        serverid=resource['id']
                        servername=resource['properties']['resourceName']
                        break

                # Skip getting deployment details if resourceName is not in servers list
                if servername is None or servername not in servers:
                    continue
                matched.append(
                    {
                        'id': deployment['id'],
                        'name': deployment['name'],
                        'createdAt': deployment['createdAt'],
                        'expiry': deployment['leaseExpireAt'] if 'expiry' in deployment else None,
                        'status': deployment['status'],
                        'expense': deployment['expense']['totalExpense'] if 'expense' in deployment else None,
                        'expenseAsOf': deployment['expense']['lastUpdatedTime'] if 'expense' in deployment else None,
                        'serverid': serverid,
                        'servername': servername,
                    }
                )
        else:
            print_error(f"No Servers Found for {username} with server names: {','.join(servers)}")
    except requests.exceptions.HTTPError as errh:
        print_error(f'HTTP Error\n{errh}')
    except requests.exceptions.ConnectionError as errc:
        print_error(f'Error Connecting\n{errc}')
    except requests.exceptions.Timeout as errt:
        print_error(f'Timeout Error\n{errt}')
    except requests.exceptions.RequestException as err:
        print_error(f'Something went wrong\n{err}')
    return matched

# Retrieves the deployment details for the given deployment ID using the access token provided.
def get_deployment_details(deployment_id: str, access_token: str):
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(f"{VRA_URL}{DEPLOYMENT_URL}/{deployment_id}/resources?resourceTypes=Cloud.vSphere.Machine", headers=headers, verify=False)
        response.raise_for_status()
        data = response.json()
        return data
    except requests.exceptions.HTTPError as errh:
        print_error(f'HTTP Error\n{errh}')
    except requests.exceptions.ConnectionError as errc:
        print_error(f'Error Connecting\n{errc}')
    except requests.exceptions.Timeout as errt:
        print_error(f'Timeout Error\n{errt}')
    except requests.exceptions.RequestException as err:
        print_error(f'Something went wrong\n{err}')

# Defines an argument parser for command line arguments,
# checks the validity of the arguments and returns the parsed arguments object.
def parse_args():
    try:
        parser = argparse.ArgumentParser(description = "This script helps to resize multiple VM in vRA at once")

        parser.add_argument('--servers', metavar='server', type=str, nargs='+', help='List of servers [ servers | filename | regex ]')
        parser.add_argument('--cpu', metavar='cpu', type=int, nargs='?', required=False, help='Number of CPUs')
        parser.add_argument('--core', metavar='core', type=int, nargs='?', required=False, help='Number of cores per CPU')
        parser.add_argument('--memory', metavar='memory', type=str, nargs='?', required=False, help='Total memory in MB | GiB ( 96G | 32M ) [ default MB for numeric values ]')
        parser.add_argument('--fetch', action='store_true', help='Get deployment details.')
        parser.add_argument('--learn', action='store_true', help='Learn how to pass the arguments with examples')

        args = parser.parse_args()
        # Check for the input if MB or GB is specified or
        # just if integer is specified consider it as MB
        if args.memory is not None:
            if isinstance(args.memory, int):
                args.memory = args.memory
            elif args.memory[-1] == 'M':
                args.memory = int(args.memory[:-1])
            elif args.memory[-1] == 'G':
                args.memory = int(args.memory[:-1]) * 1024
            else:
                raise argparse.ArgumentTypeError('Memory should be specified in either MB or GB.')

        if args.cpu is not None and (args.cpu < 1 or args.cpu > 24):
            raise argparse.ArgumentTypeError('CPU count must be between 1 and 24')
        if args.core is not None and (args.core < 1 or args.core > 24):
            raise argparse.ArgumentTypeError('Core count must be between 1 and 24')
        if args.memory is not None and (args.memory < 32 or args.memory > 262144):
            raise argparse.ArgumentTypeError('Total memory must be between 32MB and 256GB')

        if args.servers is None and not args.learn:
            raise ValueError("Either a filename or a list of servers must be provided")


        return args

    except argparse.ArgumentTypeError as err:
        print_error(f'Argument type error\n{str(err)}')
        sys.exit(1)

# Builds a payload for resizing a vSphere machine by taking the
# number of CPUs, number of cores per CPU, and total memory in MB as inputs.
def build_payload(cpu, core, memory):
    try:
        payload = {
            "actionId": "Cloud.vSphere.Machine.Resize",
            "inputs": {
                "cpuCount": cpu,
                "coreCount": core,
                "totalMemoryMB": memory
            }
        }
        return payload

    except Exception as err:
        print_error(f'Error building payload\n{str(err)}')
        sys.exit(1)

# Gets a list of servers based on the command line arguments provided.
def get_servers(args):
    servers = []
    try:
        if isinstance(args, list):
            for server in args:
                regex = r'^(.*?)\[((?:\d+|\*?)-?(?:\d+|\*?))(,((?:\d+|\*?)-?(?:\d+|\*?)))*([a-zA-Z0-9\[\]\-]*)\](.*?)$'
                servers += handle_servers(server, regex)
        else:
            regex = r'^(.*?)\[((?:\d+|[a-zA-Z])(?:-?(?:(?<!\])\d+|[a-zA-Z]))?)(,((?:\d+|[a-zA-Z])(?:-?(?:(?<!\])\d+|[a-zA-Z]))?))*\](.*)$'
            servers = handle_servers(args, regex)
    except Exception as err:
        print(f"An exception occurred: {err}")
    return servers

# Handles forming servers list either if it is passed as regex or the string or as a list in a file
def handle_servers(args, regex):
    servers = []
    if os.path.isfile(args):
        with open(args, 'r') as fileline:
            servers = [line.strip() for line in fileline if line.strip()]
    else:
        match = re.match(regex, args)
        if match:
            prefix = match.group(1)
            suffix = match.group(6)
            for server_match in match.group(2).split(','):
                if '-' in server_match:
                    start, end = server_match.split('-')
                    if start == '*':
                        start = 0
                    if end == '*':
                        end = 999999
                    for server_list in range(int(start), int(end) + 1):
                        servers.append(prefix + str(server_list) + suffix)
                else:
                    servers.append(prefix + server_match + suffix)
        else:
            servers += args.split(',')

    return map(lambda s: s.strip(), servers)

# Displays a spinner animation on the console while a resource is being resized.
def display_spinner(done_event, fetch):
    try:
        spinner = "|/-\\"
        i = 0
        while not done_event.is_set():
            i = (i + 1) % len(spinner)
            if fetch:
                print(f"\r{spinner[i]} Fetching ...", end="")
            else:
                print(f"\r{spinner[i]} Resizing ...", end="")
            time.sleep(0.1)
        print("\r" + " " * len(spinner) + "\r", end="")
    except Exception as err:
        print(f"An error occurred while displaying spinner : {err}")

# Displays the error occured at any process
def print_error(error):
    print("\r" + " " * len("|/-\\ Resizing ...") + "\r", end="")
    print('\033[31m' + f"{error}\n" + '\033[0m')
    return None

# Displays some sample commands that can be used
def learning_module():
    print('\nProviding with Sample Usage : \n')
    print(f"1 . resizevm.py --servers dev17527 dev17229 dev16919 dev17528\n"
          f"2 . resizevm.py --servers \"dev17527, dev17229, dev16919, dev17528\"\n"
          f"3 . resizevm.py --servers dev17527,dev17229,dev16919,dev17528\n"
          f"4 . resizevm.py --servers \"dev17527,dev17229,dev16919,dev17528\"\n"
          f"5 . resizevm.py --servers servers.txt\n"
          f"6 . resizevm.py --servers dev123[4-9]\n")
    return None

# Main function
def main():
    try:
        args = parse_args()

        if args is None:
            return
        if args.learn:
            learning_module()
            exit()

        user = input("Enter your username: ")
        password = getpass.getpass(prompt="Enter your password: ")
        print ("\n", end="")

        done_event = threading.Event()
        spinner_thread = threading.Thread(target=display_spinner, args=(done_event,args.fetch))
        spinner_thread.start()

        servers = get_servers(args.servers)
        refresh_token = get_refresh_token(user, password)
        access_token = get_access_token(refresh_token)

        found_servers= {}

        table = PrettyTable()
        table.field_names = ["Servers", "CPU", "Cores per Socket", "Memory(GiB)", "UpdateStatus"]

        try:
            deployments = get_deployments(access_token, user, servers)
        except Exception as err:
            print_error(f'Error getting deployments: {str(err)}')


        for deployment in deployments:
            try:
                details = get_deployment_details(deployment['id'], access_token)
                if details is None:
                    next;

                for resource in details['content']:
                    if resource['type']== 'Cloud.vSphere.Machine':
                       deployment['cpu_count']= resource['properties'].get('cpuCount', None)
                       deployment['core_count'] = resource['properties'].get('coreCount', None)
                       deployment['total_memory_MB'] = resource['properties'].get('totalMemoryMB', None)
                found_servers[deployment['servername']]=deployment
                servername=deployment['servername']
                update_status = 'N/A'
                print_args=[str(deployment['cpu_count']),str(deployment['core_count']),str(deployment['total_memory_MB']/1024)]

                if not args.fetch:
                    update_status='Skipped'
                    payload_args=[deployment['cpu_count'],deployment['core_count'],deployment['total_memory_MB']]
                    do_update=0
                    if args.cpu is not None and args.cpu != deployment['cpu_count']:
                        do_update=1
                        payload_args[0]=args.cpu
                        print_args[0] += f" => {args.cpu}"
                    if args.core is not None and args.core != deployment['core_count']:
                        do_update=1
                        payload_args[1]=args.core
                        print_args[1] += f" => {args.core}"
                    if args.memory is not None and args.memory != deployment['total_memory_MB']:
                        do_update=1
                        payload_args[2]=args.memory
                        print_args[2] += f" => {args.memory/1024}"

                    if do_update:
                        update_status='Updating'

                        try:
                            payload = build_payload(*payload_args)
                            resize (deployment['id'], deployment['serverid'], payload, access_token)
                        except Exception as err:
                            update_status='Failed'
                            print_error(f"Error resizing server {deployment['name']}\n{str(err)}")
                deployment['update_status']=update_status

                # Output memory in GiB
                table.add_row([servername, *print_args, update_status])

            except Exception as err:
                print_error(f"Error getting details for deployment {deployment['name']}\n{str(err)}")
                continue

        done_event.set()
        spinner_thread.join()
        missing_servers =  list(filter(lambda server: server not in found_servers, servers))
        print(table)

        if not args.fetch:
            match = list(filter(lambda server: found_servers[server]['update_status']=='Updating',found_servers.keys()));
            if match:
                print ('\033[37m\nResizing request sent. It will take at max of a minute to complete.\033[0m')
                print("\033[37m" + f"\nList of {len(match)} servers that are resizing: " + "\033[0m" + "\033[92m" + f"{','.join(match)}\n" + "\033[0m")
            match = list(filter(lambda server: found_servers[server]['update_status']=='Failed',found_servers.keys()))
            if match:
                print("\033[37m" + f"\nList of {len(match)} servers failed resizing request: " + "\033[m" + "\033[91;40m" + f"{','.join(match)}\n" + "\033[0m")
            match = list(filter(lambda server: found_servers[server]['update_status']=='Skipped',found_servers.keys()))
            if match:
                print("\033[37m" + f"\nList of {len(match)} servers skipping resize: " + "\033[m" + "\033[93m" + f"{','.join(match)}\n" + "\033[0m")

        if missing_servers:
            n = len(missing_servers)
            noun = "server" if n == 1 else "servers"
            print("\033[37m" + f"The following {n} {noun} could not be found: " + "\033[0m" + "\033[91;40m" + f"{','.join(missing_servers)}" + "\033[0m")
    except Exception as err:
        print_error(f'An error occurred\n{str(err)}')

if __name__ == "__main__":
    main()