import sys
import configparser
import os
import argparse
import oci
import json

try:
    import datasafe_python_client.datasafe_spec.models as data_safe_models
except:
    import oci.data_safe.models as data_safe_models

try:
    from datasafe_python_client.datasafe_spec import DataSafeClient, DataSafeClientCompositeOperations
except:
    from oci.data_safe import DataSafeClient, DataSafeClientCompositeOperations



class FindingSummary:
    def __init__(self, details=None, has_target_db_risk_level_changed=None,
                 is_risk_modified=None, is_top_finding=None, justification=None, key=None,
                 lifecycle_details=None, lifecycle_state=None, oracle_defined_severity=None,
                 references=None, remarks=None, severity=None, summary=None,
                 time_updated=None, time_valid_until=None, title=None):
        self.details = details
        self.has_target_db_risk_level_changed = has_target_db_risk_level_changed
        self.is_risk_modified = is_risk_modified
        self.is_top_finding = is_top_finding
        self.justification = justification
        self.key = key
        self.lifecycle_details = lifecycle_details
        self.lifecycle_state = lifecycle_state
        self.oracle_defined_severity = oracle_defined_severity
        self.references = references
        self.remarks = remarks
        self.severity = severity
        self.summary = summary
        self.time_updated = time_updated
        self.time_valid_until = time_valid_until
        self.title = title



class Target:
    def __init__(self, target_id):
        self.target_id = target_id
        self.finding_summaries = []  # List to hold FindingSummary objects for this target

    def add_finding_summary(self, finding_summary):
        self.finding_summaries.append(finding_summary)


class Tenancy:
    def __init__(self, tenancy_id):
        self.tenancy_id = tenancy_id
        self.targets = []  # Dictionary to hold Target objects, keyed by target_id

    def add_target(self, target_summary):
        self.targets.append(target_summary)


class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Tenancy):
            return {
                "tenancy_id": obj.tenancy_id,
                "targets": [self.default(target) for target in obj.targets]
            }
        elif isinstance(obj, Target):
            return {
                "target_id": obj.target_id,
                "finding_summaries": [self.default(finding_summary) for finding_summary in obj.finding_summaries]
            }
        elif isinstance(obj, FindingSummary):
            return {
                "details": obj.details,
#                "has_target_db_risk_level_changed":obj.has_target_db_risk_level_changed,
#                "is_risk_modified":obj.is_risk_modified,
#                "is_top_finding":obj.is_top_finding,
#                "justification":obj.justification,
                "key":obj.key,
#                "lifecycle_details":obj.lifecycle_details,
#                "lifecycle_state":obj.lifecycle_state,
#                "oracle_defined_severity":obj.oracle_defined_severity,
                "references":obj.references,
                "remarks":obj.remarks,
                "severity":obj.severity,
                "summary":obj.summary,
#                "time_updated":obj.time_updated,
#                "time_valid_until":obj.time_valid_until,
                "title":obj.title
            }
        elif isinstance(obj, list) and all(isinstance(item, FindingSummary) for item in obj):
            return [self.default(summary) for summary in obj]
        return json.JSONEncoder.default(self, obj)


def get_oci_profile_names(config_file_path):
    config_file_path = os.path.expanduser(config_file_path)
    config_parser = configparser.ConfigParser()
    config_parser.read(config_file_path)
    profile_names = config_parser.sections()
    return profile_names


def write_content_to_file(tenancy_obj,profile_name):
    filename = f"{profile_name}_sa_findings.json"
    json_string = json.dumps(tenancy_obj, cls=MyEncoder, indent=4)
    with open(filename, "w") as file:
        file.write(str(json_string))
    #print(f"Content for profile '{profile_name}' written to '{filename}'.")
    print(f"Security assessment report (JSON) for {profile_name} downloaded successfully as {filename}.")

def read_data_from_tenacies(config_file_path,profile):
    oci_config = oci.config.from_file(config_file_path,profile_name=profile)
    data_safe_client = DataSafeClient(oci_config)

    #creating a tenancy profile
    tenancy_name = oci_config.get('tenancy')

    tenancy_obj = Tenancy(tenancy_id=tenancy_name)

    # get all latest SAs that succeeded
    # root compartment ocid is the same as tenancy ocid
    # to run for a specific compartment use the compartment ocid instead of tenancy name
    # compartment_id_in_subtree and access_level should be True and ACCESSIBLE to transverse
    # all compartments
    list_security_assessments_response = data_safe_client.list_security_assessments(
        compartment_id=tenancy_name,
        type="LATEST",
        lifecycle_state="SUCCEEDED",
        compartment_id_in_subtree=True,
        access_level="ACCESSIBLE")


    # Loop through security assessments
    for instance in list_security_assessments_response.data:
        target_id=instance.target_ids[0]
        target_obj=Target(target_id)
        # for each assessment, get the findings
        list_findings_response = data_safe_client.list_findings(
            security_assessment_id=instance.id,
            references="CIS",
            limit=690,
            compartment_id_in_subtree=True)
        #print(str(list_findings_response.data))
        summary_collection=[]
        for response_object in list_findings_response.data:
            summary_obj = FindingSummary(
                 details=response_object.details, 
                 has_target_db_risk_level_changed=response_object.has_target_db_risk_level_changed,
                 is_risk_modified=response_object.is_risk_modified, 
                 is_top_finding=response_object.is_top_finding, 
                 justification=response_object.justification, 
                 key=response_object.key,
                 lifecycle_details=response_object.lifecycle_details, 
                 lifecycle_state=response_object.lifecycle_state, 
                 oracle_defined_severity=response_object.oracle_defined_severity,
                 references=str(response_object.references), 
                 remarks=response_object.remarks, 
                 severity=response_object.severity, 
                 summary=response_object.summary,
                 time_updated=response_object.time_updated, 
                 time_valid_until=response_object.time_valid_until, 
                 title=response_object.title)
            #to remove duplicates
            #if summary_obj not in summary_collection:
            summary_collection.append(summary_obj)
        target_obj.add_finding_summary(summary_collection)
        tenancy_obj.add_target(target_obj)

    write_content_to_file(tenancy_obj,profile)
if __name__ == "__main__":
    #
    #  
    # python3 sa_findings.py --f /path/to/custom/config/file --profile profile1 profile2 profile3
    # --f optional, --profile optional 
    #
    parser = argparse.ArgumentParser(description="Read OCI Profile Names from Configuration File")

    parser.add_argument(
    "--f",
    dest="config_file_path",
    default="~/.oci/config",
    help="Path to the OCI configuration file (default: ~/.oci/config). This file contains the credentials and settings for different OCI profiles."
)

    parser.add_argument(
    "--profile",
    dest="profile_names",
    nargs="*",
    default=[],
    help="OCI profile names to retrieve. Provide a space-separated list. If not specified, all profiles from the configuration file will be considered."
)
    args = parser.parse_args()
    if args.profile_names:
        print("OCI Profile Name:", args.profile_names)
        oci_profiles=args.profile_names
    else:
        # Retrieve and print all profile names
        oci_profiles = get_oci_profile_names(args.config_file_path)
        if oci_profiles:
            print("OCI Profile Names:", oci_profiles)
        else:
            print("No OCI Profile Names found.") 

    # read data from tenancies        
    for profile in oci_profiles:
        read_data_from_tenacies(args.config_file_path,profile)
    
