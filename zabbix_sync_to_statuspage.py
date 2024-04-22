import argparse
import json
import logging
import time
import traceback
from enum import Enum
import yaml
import requests
from datetime import datetime

LOGGING_FORMAT = '%(asctime)s %(levelname)-8s %(message)s'
LOGGING_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'
DRY_RUN = False


# Enum for Zabbix Trigger Constants
class ZbxStatus(Enum):
    """
    Enum class representing Zabbix trigger statuses.
    """
    not_classified = 0
    operational = -1
    warning = 2
    average = 3
    high = 4
    disaster = 5


# Map Zabbix Trigger Status to Statuspage Severity.
ZBX_SP_MAPPING = {
    "not_classified": "under_maintenance",
    "operational": "operational",
    "warning": "degraded_performance",
    "average": "partial_outage",
    "high": "partial_outage",
    "disaster": "major_outage"
}


class ZabbixServiceInfo:
    def __init__(self, service_id, service_name, service_status, is_group_parent=False, linked_parent_id=0):
        """
        Represents information about a Zabbix service.
        :param service_id: The ID of the Zabbix service.
        :param service_name: The name of the Zabbix service.
        :param service_status: The status of the Zabbix service.
        :param is_group_parent: Indicates whether the service is a group parent.
        :param linked_parent_id: The ID of the linked parent (if any).
        """
        self.service_id = service_id
        self.service_name = service_name
        self.service_status = service_status
        self.is_group_parent = is_group_parent
        self.linked_parent_id = linked_parent_id


class StatusPageComponentInfo:
    def __init__(self, component_id, component_name, component_status, is_group, matched=False):
        """
        Represents information about a Statuspage component.
        :param component_id: The ID of the Statuspage component.
        :param component_name: The name of the Statuspage component.
        :param component_status: The status of the Statuspage component.
        :param is_group: Indicates whether the component is a group.
        :param matched: Indicates whether the component is matched with a Zabbix service.
        """
        self.component_id = component_id
        self.component_name = component_name
        self.component_status = component_status
        self.is_group = is_group
        self.matched = matched  # Found matching Zbx<->SP


class ZabbixService:
    def __init__(self, api_host, api_username, api_password):
        """
        Initializes a ZabbixService instance.
        :param api_host: The API host of the Zabbix instance.
        :param api_username: The username to authenticate to the Zabbix instance.
        :param api_password: The password to authenticate to the Zabbix instance.
        """
        self.zabbix_api_url = api_host + "zabbix/api_jsonrpc.php"
        self.api_username = api_username
        self.api_password = api_password
        self.session_key = None
        self._authenticate(self.api_username, self.api_password)

    def _authenticate(self, username, password):
        """
        Authenticate to Zabbix using username & password. Obtain a session key
        which persists for as long as was set in Zabbix Administrator Settings.
        :param username: Username to authenticate to a Zabbix Instance
        :param password: Password to authenticate to a Zabbix Instance
        """
        try:
            payload = {"jsonrpc": "2.0", "method": "user.login", "params": {"user": username, "password": password},
                       "id": 1}
            response = requests.post(self.zabbix_api_url, data=json.dumps(payload),
                                     headers={'Content-Type': 'application/json'}, timeout=10, verify=False)
            self.session_key = response.json()["result"]
            assert self.session_key is not None  # Ensure the session key is set.
            logging.info("Authentication to Zabbix was successful. Session key obtained")
        except Exception as exc:
            raise Exception("FATAL: Failed to authenticate to zabbix.\nException: {}".format(exc))

    def get_services(self, root_service_id, retry=False):
        """
        Gets Services under a root node with Zabbix API. Extracts information about each service and puts into
        a list of objects.
        :param root_service_id: Zabbix ID of a root service. Entries under this root node are considered for statuspage
        :param retry: Recursion Management. Whether a call to this function was made due to a retry
        :return: List of ZabbixServiceInfo objects
        """

        payload = {"jsonrpc": "2.0", "method": "service.get",
                   "params": {"output": "extend", "selectChildren": "extend", "selectParents": "extend"}, "id": 1,
                   "auth": self.session_key}
        res = requests.get(self.zabbix_api_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'},
                           timeout=10, verify=False)

        if res.status_code == 200:
            zbx_services = res.json()["result"]
        elif (res.status_code == 401 or res.status_code == 403) and not retry:
            logging.info("Query zabbix services response was {}. The session key may have expired. "
                         "Attempting to reauthenticate and trying again.".format(res.status_code))
            self._authenticate(self.api_username, self.api_password)
            return self.get_services(root_service_id, retry=True, verify=False)  # Retry with a reauthentication attempt
        else:
            res.raise_for_status()

        # Find root service, extract ID & match to their object. Any components/groups under this root are to sync.
        root_children = list(filter(lambda root_child: root_child['serviceid'] == str(root_service_id), zbx_services))
        root_children_id = [child["serviceid"] for child in root_children[0]["children"]]
        root_children = list(filter(lambda root_child: root_child["serviceid"] in root_children_id, zbx_services))

        # Find Services under the root & Service Groups under the root
        root_services = list(filter(lambda root_service: len(root_service["children"]) == 0, root_children))

        root_groups = list(filter(lambda root_group: len(root_group["children"]) > 0, root_children))

        zbx_info = []  # Hold list of Zabbix Service Information objects

        for rc in root_services:  # Root Components
            zbx_info.append(ZabbixServiceInfo(rc["serviceid"], rc["name"], ZbxStatus(int(rc["status"])).name))

        for rg in root_groups:  # Root Groups
            zbx_info.append(
                ZabbixServiceInfo(rg["serviceid"], rg["name"], ZbxStatus(int(rg["status"])).name, is_group_parent=True))

            group_children = list(
                filter(lambda group_child: group_child['serviceid'] == str(rg["serviceid"]), zbx_services))
            group_children_id = [child["serviceid"] for child in group_children[0]["children"]]
            group_children = list(
                filter(lambda group_child: group_child["serviceid"] in group_children_id, zbx_services))

            # Find the components which are under this group
            for gc in group_children:  # Group Child
                zbx_info.append(ZabbixServiceInfo(gc["serviceid"], gc["name"], ZbxStatus(int((gc["status"]))).name,
                                                  linked_parent_id=rg["serviceid"]))
        return zbx_info


class StatusPageSync:
    def __init__(self, api_host, page_id, api_key, allow_delete):
        """
        Initializes a StatusPageSync instance.
        :param api_host: The API host of the Statuspage instance.
        :param page_id: The ID of the Statuspage.
        :param api_key: The API key for authentication.
        :param allow_delete: Flag indicating whether component deletion is allowed.
        """
        self.sp_api_host = api_host + "/v1/pages/" + page_id
        self.allow_delete = allow_delete
        self.authorization_header = {'Authorization': 'OAuth ' + api_key}

    def sync_zbx_to_sp(self, zbx_info):
        """
        Get information from Statuspage about existing components. Match this information with zabbix
        service information. Create/Update/Delete the Statuspage components to match zabbix services
        :param zbx_info: List of ZabbixServiceInfo with information about zabbix services.
        """
        res_sp_components = requests.get(self.sp_api_host + "/components", headers=self.authorization_header,
                                         timeout=10, verify=False).json()
        component_changes_made = False

        sp_info = []  # Hold list of Statuspage Component Information objects
        for spc in res_sp_components:  # For each Statuspage Component
            sp_info.append(StatusPageComponentInfo(spc["id"], spc["name"], spc["status"], spc["group"]))

        # Match Zabbix Services with Statuspage Components and Sync Differences
        for zbx_service in [c for c in zbx_info if not c.is_group_parent]:

            # Find the statuspage component with the same name as a zabbix service
            # FIXME : This implementation requires unique component names even between different groups
            sp_component = next((c for c in sp_info if c.component_name == zbx_service.service_name), None)

            if sp_component is not None:
                # Make sure the status on the statuspage component is the same as the status on zabbix.
                sp_status = sp_component.component_status
                zbx_status = ZBX_SP_MAPPING[zbx_service.service_status]
                if sp_status != zbx_status:
                    logging.debug("Service: {} status mismatch (SP: {} ZBX: {}). Updating.".
                                  format(sp_component.component_name, sp_status, zbx_status))
                    self._update_component_status(sp_component.component_id, ZBX_SP_MAPPING[zbx_service.service_status],
                                                  zbx_service.service_name)
                    sp_component.matched = True  # Exists on both zabbix & statuspage, don't delete it.
            else:
                self._create_component(zbx_service.service_name)
                component_changes_made = True

        # Delete components which were on statuspage but not on zabbix.
        if self.allow_delete:
            for sp_component in sp_info:
                if not sp_component.is_group and not sp_component.matched:  # Ignore Groups
                    logging.debug("Found a component ({}) which exists on statuspage but not zabbix."
                                  "Configuration permits deletion".format(sp_component.component_id))
                    self._delete_component(sp_component.component_id)
                    component_changes_made = True

        # To modify component groups correctly, we need to most up-to-date information about the components on
        # statuspage Rather than recursively calling / sending another request, we can just wait until the next sync
        # to update the groups
        if component_changes_made:
            logging.warning(
                "Changes have been made to components during this sync. Updating component groups skipped and will be "
                "updated on the next sync")
            return  # Leave function

        sp_component_groups = requests.get(self.sp_api_host + "/component-groups", headers=self.authorization_header,
                                           timeout=10, verify=False).json()

        # Component Group Sync
        for zbx_group in [g for g in zbx_info if g.is_group_parent]:
            # Find the statuspage component group with the same name as a zabbix group
            sp_group = next((spg for spg in sp_component_groups if zbx_group.service_name == spg["name"]), None)

            # Get the Statuspage component ID's of all the children of this group
            # FIXME : This implementation requires unique component names even between different groups
            group_children = list(filter(lambda gc: gc.linked_parent_id == zbx_group.service_id, zbx_info))
            children_name = [item.service_name for item in group_children]
            matched_components = list(filter(lambda item: item.component_name in children_name, sp_info))
            extracted_ids = [item.component_id for item in matched_components]

            if sp_group is None:
                logging.debug("Creating a new component group on statuspage: {} with components: {}".format(
                    zbx_group.service_name, extracted_ids))
                self._create_component_group(zbx_group.service_name, extracted_ids)
                continue  # Newly created group, we don't need to continue to update the children again.

            # Check the ID's in the statuspage component group matches the children in the zabbix group.
            if len(set(extracted_ids) - set(sp_group["components"])) != 0:
                logging.debug("The children in the component group {} are not the same. Refreshing group children "
                              "to {}".format(zbx_group.id, extracted_ids))
                self._update_component_group(sp_group["id"], extracted_ids)

    def _create_component(self, name):
        """
        Create a new component on Statuspage with the specified name.
        :param name: The name of the component to create.
        """
        url = self.sp_api_host + "/components/"
        if not DRY_RUN:
            res = requests.post(url, json={'component': {'name': name, 'showcase': True}},
                                headers=self.authorization_header, timeout=10)
            res.raise_for_status()
        logging.info(
            "A new component has been created. Named: {}. The status will be updated during the next sync.".format(
                name))

    def _delete_component(self, component_id):
        """
        Delete a component from Statuspage.
        :param component_id: The ID of the component to delete.
        """
        url = self.sp_api_host + "/components/" + component_id
        if not DRY_RUN:
            res = requests.delete(url, headers=self.authorization_header, timeout=10)
            res.raise_for_status()
        logging.info("Deleted Component from Statuspage: {}".format(component_id))

    def _create_component_group(self, name, group_children):
        """
        Create a new component group on Statuspage with the specified name and children.
        :param name: The name of the component group to create.
        :param group_children: The IDs of the components that belong to the group.
        """
        url = self.sp_api_host + "/component-groups"
        if not DRY_RUN:
            res = requests.post(url, json={'component_group': {'name': name, 'components': group_children}},
                                headers=self.authorization_header, timeout=10)
            res.raise_for_status()
        logging.info("A new component group has been created: {} which now contains {}.".format(name, group_children))

    def _update_component_group(self, component_group_id, group_children):
        """
        Update the components of a component group on Statuspage.
        :param component_group_id: The ID of the component group to update.
        :param group_children: The IDs of the components that belong to the group.
        """
        url = self.sp_api_host + "/component-groups/" + component_group_id
        if not DRY_RUN:
            res = requests.put(url, json={'component_group': {'components': group_children}},
                               headers=self.authorization_header, timeout=10, verify=False)
            res.raise_for_status()
        logging.info("Updated the component group: {} which now contains {}".format(component_group_id, group_children))

    def _update_component_status(self, component_id, status, service_name):
        """
        Update the status of a component on Statuspage.
        :param component_id: The ID of the component to update.
        :param status: The new status of the component.
        :param service_name: The name of the service associated with the component.
        """
        url = self.sp_api_host + "/components/" + component_id

        logging.info("Setting component {} status to: {}".format(component_id, status))
        if not DRY_RUN:
            res = requests.patch(url, json={'component': {'status': status}}, headers=self.authorization_header,
                                 timeout=10, verify=False)
            res.raise_for_status()
            if status != 'operational':
                create_incident(component_id, status, service_name)
            else:
                get_incident_id_by_service_name(service_name)

        logging.info("Updated the status of component: {} to {}.".format(component_id, status))


def get_incident_id_by_service_name(service_name):
    """
    Get the incident ID(s) associated with a service name from Statuspage.
    :param service_name: The name of the service.
    """
    api_key = config["sp_api_key"]
    page_id = config["sp_api_pageid"]

    url = f"https://api.statuspage.io/v1/pages/{page_id}/incidents"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"OAuth {api_key}"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        incidents = response.json()

        component_incidents = [incident for incident in incidents if any(
            component["name"] == service_name for component in incident["components"]
        )]

        if len(component_incidents) > 0:
            incident_id = component_incidents[0]["id"]
            resolve_and_update_incident_name(incident_id)


    else:
        logging.info("Failed to retrieve incidents. Error:", response.text)


def resolve_and_update_incident_name(incident_id):
    """
    Resolve an incident by changing its status to "resolved" and update the incident name
    by adding created_at and resolved_at after resolving the incident.
    :param incident_id: The ID of the incident to resolve and update.
    """
    api_key = config["sp_api_key"]
    page_id = config["sp_api_pageid"]
    url = f"https://api.statuspage.io/v1/pages/{page_id}/incidents/{incident_id}"

    headers = {
        "Authorization": f"OAuth {api_key}",
        "Content-Type": "application/json"
    }

    # Resolve the incident
    resolve_payload = {
        "incident": {
            "status": "resolved",
        }
    }

    try:
        response = requests.put(url, headers=headers, json=resolve_payload)
        response.raise_for_status()
        logging.info(f"Incident {incident_id} resolved successfully.")
    except requests.exceptions.RequestException as e:
        logging.info(f"Error resolving incident: {e}")

    # Update the incident name
    incident_response = requests.get(url, headers=headers)
    data = incident_response.json()

    incident_name = data["name"]
    incident_updates = data["incident_updates"]
    started_at = incident_updates[1]["display_at"]
    ended_at = incident_updates[0]["display_at"]

    start = datetime.fromisoformat(started_at)
    end = datetime.fromisoformat(ended_at)

    started_at = str(start.strftime("%H:%M"))
    ended_at = str(end.strftime("%H:%M"))

    # Extract the hour and minute components and update the incident name
    updated_name = f"{incident_name} {started_at}-{ended_at}"

    update_payload = {
        "incident": {
            "name": updated_name,
        }
    }

    try:
        response = requests.put(url, headers=headers, json=update_payload)
        response.raise_for_status()
        logging.info(f"Incident {incident_id} name updated successfully.")
    except requests.exceptions.RequestException as e:
        logging.info(f"Error updating incident name: {e}")


def create_incident(component_id, status, service_name):
    """
    Create an incident on Statuspage for a component with the specified status and service name.
    :param component_id: The ID of the component associated with the incident.
    :param status: The status of the incident.
    :param service_name: The name of the service associated with the component.
    """
    api_key = config["sp_api_key"]
    page_id = config['sp_api_pageid']

    endpoint = f'https://api.statuspage.io/v1/pages/{page_id}/incidents'
    headers = {
        'Authorization': f'OAuth {api_key}',
        'Content-Type': 'application/json',
    }
    logging.info("Component creating the incident is: " + service_name)
    displayed_status = ""
    if status == "major_outage":
        displayed_status = "major outage"
    if status == "partial_outage":
        displayed_status = "partial outage"
    data = {
        'incident': {
            'name': str(service_name) + " " + str(displayed_status),
            'status': 'identified',  # Possible values: 'identified', 'investigating', 'monitoring', 'resolved'
            'impact_override': 'none',  # Possible values: 'none', 'critical', 'major', 'minor'
            'message': f'{service_name} service is currently experiencing issues.',
            "components": {
                str(service_name): str(status)
            },
            "component_ids": [
                str(component_id)
            ],
        }
    }

    response = requests.post(endpoint, headers=headers, json=data)

    if response.status_code == 201:
        logging.info('Incident created successfully.')
    else:
        logging.info(f'Failed to create incident. Response: {response.text}')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Synchronise Zabbix Services with Statuspage Components')
    parser.add_argument('-c', '--config', help="Path to script configuration file", type=str,
                        default="zabbix_sync_to_statuspage_conf.yaml")
    parser.add_argument('-d', '--dryrun', help="Dry-run mode. The value won't actually be sent to Statuspage.",
                        action='store_true')
    parser.add_argument('-l', '--logfile', help="Specify the log-file to store logging information.",
                        default='zabbix_sync_to_statuspage.log')
    parser.add_argument('-s', '--screen', help="Print log details to screen (console)", action='store_true')
    parser.add_argument('-v', '--verbose', help="Verbose. Log debug information", action='store_true')

    args = parser.parse_args()
    DRY_RUN = args.dryrun

    log_handlers = []

    # Logging output
    if args.logfile != "":
        log_handlers.append(logging.FileHandler(args.logfile))
    if args.screen:
        log_handlers.append(logging.StreamHandler())

    # Logging verbosity
    logging_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(handlers=log_handlers, format=LOGGING_FORMAT, level=logging_level,
                        datefmt=LOGGING_DATETIME_FORMAT)

    logging.info("Sync Zabbix Services To Statuspage Components Starting")

    try:
        with open(args.config, 'r') as stream:
            config = yaml.safe_load(stream)
        zabbix_con = ZabbixService(config["zbx_api_host"], config["zbx_api_username"], config["zbx_api_password"])
        statuspage_con = StatusPageSync(config["sp_api_host"], config["sp_api_pageid"], config["sp_api_key"],
                                        config["sp_allow_dangling_component_delete"])
        delay = config["updateDelay"]
        bail_fail_attempts = int(config["bail_fail_attempts"])

        failed_attempts_count = 0

        while True:  # Continue till exit or bail
            try:

                services_to_sync = zabbix_con.get_services(config["zabbix_root_service_id"])
                statuspage_con.sync_zbx_to_sp(services_to_sync)
                if failed_attempts_count > 0:
                    failed_attempts_count = 0

                logging.info(
                    "A Zabbix <-> Statuspage sync has completed. Waiting {}ms before the next sync.".format(str(delay)))
            except Exception as err:
                logging.error("Zabbix <-> Statuspage Sync failed. An exception occurred: {}".format(err))
                failed_attempts_count = failed_attempts_count + 1
                logging.info(
                    "Consecutive failed sync attempts: {}. Will retry in: {}ms".format(failed_attempts_count, delay))

                if (bail_fail_attempts != 0) and (failed_attempts_count >= bail_fail_attempts):
                    logging.fatal("Amount of consecutive sync attempts () greater than bail amount {}. Bailing-out.".
                                  format(failed_attempts_count, bail_fail_attempts))
                    exit(1)

            time.sleep(delay / 1000.0)
    except Exception as err:
        logging.error("An Unhandled Exception Occurred. Error: {}".format(traceback.print_exc()))
    finally:
        logging.info("*** Sync Zabbix Services to Statuspage Components Stopping ***")